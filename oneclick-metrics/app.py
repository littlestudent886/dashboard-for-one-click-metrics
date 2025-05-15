import json
import logging
import asyncio
import sys
from psycopg import OperationalError
from utils.db_connect import DatabaseConnection
from utils.export_mertics import MetricsExporter
import os
import time
import argparse

all_projects = set()
# stash.calix.local use the Chicago time zone, use this for current_timestamp function
stash_time_zone = "America/Chicago"


async def register_prepared_sqls(db: DatabaseConnection, first_call=True):
    reg_sqls = {
        "check_summary_query(text[])": """
            SELECT
                repo.slug as stash_repo,
				string_agg(DISTINCT "REPORT_KEY",',') as present_report,
				project.project_key as project
	        FROM 
                "AO_2AD648_MERGE_CHECK" as merge_check
                RIGHT JOIN repository repo on merge_check."RESOURCE_ID" = repo.id AND merge_check."SCOPE_TYPE" = 'REPOSITORY'
                INNER JOIN project on repo.project_id = project.id
	        WHERE 
                project.project_key = ANY($1)
	        GROUP BY
                project.project_key,
				repo.slug	
        """,
        "closed_pr_report_query(timestamp)":"""
            SELECT
                repo.slug AS stash_repo,
                pr.scoped_id AS prno,
                string_agg (DISTINCT insrep."REPORT_KEY", ',') FILTER (WHERE insrep."REPORT_KEY" in ( 'sast','sabug','savul','sasmell','smoke','ci','codecoverage','snyk' )) AS present_reports,
                project.project_key AS "project",
				'[' || string_agg(DISTINCT nullif(insrep."DATA",''),',') || ']' AS report_data
            FROM
                sta_pull_request AS pr
                INNER JOIN repository repo on pr.to_repository_id = repo.id
                INNER JOIN project on repo.project_id = project.id
                LEFT  JOIN "AO_2AD648_INSIGHT_REPORT" insrep on pr.from_hash = insrep."COMMIT_ID"
                and pr.to_repository_id = insrep."REPOSITORY_ID"
            WHERE
                project.project_key not like '~%' AND (pr.closed_timestamp >= (date_trunc('minute', $1) - INTERVAL '1 minute')
            AND pr.closed_timestamp < date_trunc('minute', $1))
            GROUP BY
                stash_repo,
                prno,
                project.project_key
            ORDER BY
                stash_repo,
                prno,
                project.project_key;
        """,
        "open_pr_report_query": """
            SELECT
                repo.slug AS stash_repo,
                pr.scoped_id AS prno,
                string_agg (DISTINCT insrep."REPORT_KEY", ',') FILTER (WHERE insrep."REPORT_KEY" in ( 'sast','sabug','savul','sasmell','smoke','ci','codecoverage','snyk' )) AS present_reports,
                project.project_key AS "project",
                '[' || string_agg(DISTINCT nullif(insrep."DATA",''),',') || ']' AS report_data
            FROM
                sta_pull_request AS pr
                INNER JOIN repository repo on pr.to_repository_id = repo.id
                INNER JOIN project on repo.project_id = project.id
                LEFT  JOIN "AO_2AD648_INSIGHT_REPORT" insrep on pr.from_hash = insrep."COMMIT_ID"
                and pr.to_repository_id = insrep."REPOSITORY_ID"
            WHERE
                pr.pr_state = 0 AND project.project_key not like '~%'
            GROUP BY
                stash_repo,
                prno,
                project.project_key
            ORDER BY
                stash_repo,
                prno,
                project.project_key
        """,
        "result_report_query(text)": f"""
            WITH prbase AS(
                SELECT
				    pr.id AS pr_id,
                    CASE WHEN insrep."REPORT_KEY" = $1 THEN insrep."REPORT_KEY" ELSE null END AS report,
					string_agg(CASE WHEN insrep."REPORT_KEY" = $1 THEN insrep."REPORT_KEY" ELSE null END,',') OVER prw AS allrepts,
                    insrep."RESULT_ID" AS status,
                    project.project_key AS project_key
                FROM
                    sta_pull_request pr
                    INNER JOIN repository repo ON pr.to_repository_id = repo.id
                    INNER JOIN project ON repo.project_id = project.id
                    LEFT JOIN "AO_2AD648_INSIGHT_REPORT" insrep ON pr.from_hash = insrep."COMMIT_ID"
                    AND pr.to_repository_id = insrep."REPOSITORY_ID"
                WHERE
                    pr.pr_state = 0 AND project.project_key NOT LIKE '~%'
                    AND ( insrep."REPORT_KEY" = $1 OR repo.id = ANY ( SELECT "RESOURCE_ID" FROM "AO_2AD648_MERGE_CHECK" WHERE "RESOURCE_ID" = repo.id AND "REPORT_KEY" = $1 ) )
                GROUP BY
                    project.project_key,
                    pr.id,
                    report,
                    status
				WINDOW prw AS (PARTITION BY pr.id)
			)
            SELECT
                    report,
                    status,
                    project_key AS project,
                    COUNT(*) AS cnt
                FROM
				    prbase
                WHERE
                    report = $1
                GROUP BY
                    status,
					report,
                    project_key
			UNION
				SELECT
                    $1 AS report,
                    2 AS status,
                    project_key AS project,
                    COUNT(*) AS cnt
                FROM
				    prbase
				WHERE
				    allrepts IS NULL
                GROUP BY
                    project_key;
            """,
        "pr_counts_query(timestamp)": """
            SELECT
                pr_state,
                project.project_key AS project,
                COUNT(*)
            FROM
                sta_pull_request AS pr
                INNER JOIN repository AS repo ON pr.to_repository_id = repo.id
                INNER JOIN project AS project ON repo."project_id" = project.id
            WHERE project.project_key not like '~%'
                AND ( pr.closed_timestamp is null OR (pr.closed_timestamp >= ($1 - interval '1 minute') and pr.closed_timestamp < $1 ) )
            GROUP BY
                pr_state,
                project.project_key;
        """,
        "pr_missing_report_query(timestamp)": """
        SELECT SUM(cnt),pr_state,project_key
        FROM (
        -- part 1: count all pr(s) with partial reports
        SELECT COUNT(*) AS cnt,pr_state,project_key
        FROM (
            SELECT
                pr.id,
                pr.pr_state,
                repo.id AS repo_id,
                project.project_key
            FROM
                "AO_2AD648_INSIGHT_REPORT" AS insrep
                INNER JOIN sta_pull_request AS pr ON insrep."COMMIT_ID" = pr.from_hash
                INNER JOIN repository AS repo ON pr.to_repository_id = repo.id
                INNER JOIN project AS project ON repo.project_id = project.id
                INNER JOIN (
                    SELECT
                        merge_check."RESOURCE_ID" AS repo_id,
                        array_agg("REPORT_KEY") AS req_arr
                    FROM
                        "AO_2AD648_MERGE_CHECK" AS merge_check
                    WHERE
                        "SCOPE_TYPE" = 'REPOSITORY'
                        AND "REPORT_KEY" IN ('sast','sabug','savul','sasmell','smoke','ci','codecoverage','snyk')
                    GROUP BY
                        merge_check."RESOURCE_ID"
                ) AS repreq ON repo.id = repreq.repo_id
            WHERE
                project.project_key NOT LIKE '~%'
                AND ( pr.closed_timestamp is NULL OR (pr.closed_timestamp >= ($1 - interval '1 minute') and pr.closed_timestamp < $1 ) )
            GROUP BY
                pr.id,
                pr.pr_state,
                repo.id,
                project.project_key,
                repreq.req_arr
            HAVING NOT (repreq.req_arr <@ array_agg( DISTINCT
				CASE
					WHEN insrep."REPORT_KEY" in ('sast','sabug','savul','sasmell','smoke','ci','codecoverage','snyk') THEN insrep."REPORT_KEY"
					ELSE 'other'::VARCHAR
				END ))
        ) AS partquery
        GROUP BY
          project_key,
          pr_state
        UNION
        -- part 2: count pr(s) without any report
        SELECT count(pr.id) AS cnt, pr.pr_state, project.project_key
        FROM
          "AO_2AD648_INSIGHT_REPORT" AS insrep
          RIGHT JOIN sta_pull_request AS pr ON insrep."COMMIT_ID" = pr.from_hash
          INNER JOIN repository AS repo ON pr.to_repository_id = repo.id
          INNER JOIN project AS project ON repo.project_id = project.id
        WHERE
          insrep."REPORT_KEY" is null
          AND repo.id = ANY ( select "RESOURCE_ID"
                from "AO_2AD648_MERGE_CHECK"
                where "RESOURCE_ID" = repo.id
                AND "REPORT_KEY" in ('sast','sabug','savul','sasmell','smoke','ci','codecoverage','snyk') )
          AND ( pr.closed_timestamp is null OR (pr.closed_timestamp >= ($1 - interval '1 minute') and pr.closed_timestamp < $1 ) )
        GROUP BY project.project_key,pr.pr_state
        ) AS uniontable
        GROUP BY project_key,pr_state
        """,
    }

    for prot, sql in reg_sqls.items():
        name, pa, pb = prot.partition("(")
        param = pa + pb
        if not first_call:
            try:
                await db.execute_aync(f"DEALLOCATE {name};")
            except Exception as e:
                logging.error(f"Error dropping previous register sql: {name}")
        try:
            await db.execute_async(f"PREPARE {name}{param} AS {sql};")
        except Exception as e:
            logging.error(f"Error register sql: {name}")

def extract_code_coverage(raw_data: str) -> str:

    def is_number(value):
        return isinstance(value, (int, float))
    """
    extract first "Code Coverage" value
    parameter type：'[[{dict1}, {dict2}], [{dict3}, ...]]'
    """
    try:
        parsed_data = json.loads(raw_data)
        results = []
        
        for sub_array in parsed_data:
            if not isinstance(sub_array, list):
                continue
            
            for item in sub_array:

                if (
                    isinstance(item, dict)
                    and item.get("title") == "Code Coverage"
                ):
                    value = item.get("value", "")
                    if(is_number(value)):
                        results.append(str(value))
                        break  
        
        return results[0] if results else ""
    
    except (json.JSONDecodeError, TypeError, KeyError):
        return ""


async def get_all_projects(db: DatabaseConnection, knownProjects: set) -> set:
    global all_projects
    if not all_projects:
        try:
            sql = f"""SELECT  DISTINCT project.project_key
                FROM
                    sta_pull_request pr
                    inner join repository repo on pr.from_repository_id = repo.id
                    inner join project on repo.project_id = project.id
                where
                    project.project_key not like '~%';"""
            results = await db.fetch_all_async(sql)
            all_projects = set([result[0] for result in results])
        except Exception as e:
            logging.error(f"Error to fetch all project names")
    if knownProjects:
        all_projects = all_projects | knownProjects
    return all_projects


async def export_check_summary(db, metrics):
    try:
        projects = await get_all_projects(db, {})
        project_list = ",".join(projects)
        check_summary_query_results = await db.fetch_all_async(f"EXECUTE check_summary_query ('{{ {project_list} }}')")
        metrics["oneclick_check_summary"].clear()
        for result in check_summary_query_results:
            stash_repo = result[0]
            check_summary = result[1] or ""
            if check_summary == "":
                valid_appearance = 0
            else:
                valid_appearance = check_summary.count(",") + 1
            project = result[2]
            metrics["oneclick_check_summary"].labels(
                stash_repo=stash_repo,
                valid_appearance=valid_appearance,
                enabled_checks=check_summary,
                project=project,
            )
        logging.info("oneclick_check_summary metrics exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting oneclick_check_summary metrics: {e}")


async def export_open_pr_report(db, metrics):
    try:
        open_pr_report_query_results = await db.fetch_all_async("EXECUTE open_pr_report_query")
        metrics["oneclick_open_pr_report"].clear()
        for result in open_pr_report_query_results:
            stash_repo = result[0]
            pr_no = result[1]
            present_reports = result[2] or ""
            if present_reports == "":
                valid_appearance = 0
            else:
                valid_appearance = present_reports.count(",") + 1
            project = result[3]
            code_coverage = extract_code_coverage(result[4])
            metrics["oneclick_open_pr_report"].labels(
                stash_repo=stash_repo,
                pr_no=pr_no,
                valid_appearance=valid_appearance,
                present_reports=present_reports,
                project=project,
                code_coverage=code_coverage
            )
        logging.info("oneclick_open_pr_report metrics exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting oneclick_open_pr_report metrics: {e}")

async def export_closed_pr_report(db, metrics):
    try:
        closed_pr_report_query_results = await db.fetch_all_async(f"EXECUTE closed_pr_report_query(date_trunc('minute',current_timestamp AT TIME ZONE '{stash_time_zone}'))")
        metrics["oneclick_closed_pr_report"].clear()
        for result in closed_pr_report_query_results:
            stash_repo = result[0]
            pr_no = result[1]
            present_reports = result[2] or ""
            if present_reports == "":
                valid_appearance = 0
            else:
                valid_appearance = present_reports.count(",") + 1
            project = result[3]
            code_coverage = extract_code_coverage(result[4])
            metrics["oneclick_closed_pr_report"].labels(
                stash_repo=stash_repo,
                pr_no=pr_no,
                valid_appearance=valid_appearance,
                present_reports=present_reports,
                project=project,
                code_coverage=code_coverage
            )
        logging.info("oneclick_closed_pr_report metrics exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting oneclick_closed_pr_report metrics: {e}")


async def export_result_report(db, metrics):
    all_report_keys = [
        "ci",
        "codecoverage",
        "sast",
        "smoke",
        "snyk",
        "sabug",
        "sasmell",
        "savul",
    ]
    all_status = ["success", "failure", "notAvailable"]
    try:
        subtasks = dict()
        async with asyncio.TaskGroup() as tg:
            for report_key in all_report_keys:
                subtasks[report_key] = tg.create_task(
                    db.fetch_all_async(f"EXECUTE result_report_query('{report_key}')")
                )
        for task in subtasks.values():
            results = task.result()
            projects = set([result[2] for result in results])
            projects = await get_all_projects(db, projects)

        metrics["oneclick_result_report"].clear()
        for report_key, task in subtasks.items():
            results = task.result()
            cntarr = {}
            for k in projects:
                cntarr[k] = [0] * 3
            for result in results:
                status = 2 if result[1] is None else result[1]
                project = result[2]
                cnt = result[3]
                cntarr[project][status] = cnt
            for project in all_projects:
                cntTotal = cntarr[project][0] + cntarr[project][1]
                metrics["oneclick_result_report"].labels(report=report_key, status="failure", project=project).set(
                    cntarr[project][0]
                )
                metrics["oneclick_result_report"].labels(report=report_key, status="success", project=project).set(
                    cntarr[project][1]
                )
                metrics["oneclick_result_report"].labels(report=report_key, status="total", project=project).set(
                    cntTotal
                )
                metrics["oneclick_result_report"].labels(report=report_key, status="notAvailable", project=project).set(
                    cntarr[project][2]
                )
            logging.info(f"{report_key} oneclick_result_report exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting oneclick_result_report metrics: {e}")


async def export_pr_counts(db, metrics):
    try:
        pr_counts_query_results = await db.fetch_all_async(
            f"EXECUTE pr_counts_query(date_trunc('minute',current_timestamp AT TIME ZONE '{stash_time_zone}'))"
        )
        metrics["oneclick_pr_num"].clear()
        projects = set([result[1] for result in pr_counts_query_results])
        projects = await get_all_projects(db, projects)
        cntarr = {}
        for k in projects:
            cntarr[k] = [0] * 3
        for result in pr_counts_query_results:
            cntarr[result[1]][result[0]] = result[2]
        for project in projects:
            metrics["oneclick_pr_num"].labels(pr_state="open", project=project).set(cntarr[project][0])
            metrics["oneclick_pr_num"].labels(pr_state="merged", project=project).set(cntarr[project][1])
            metrics["oneclick_pr_num"].labels(pr_state="declined", project=project).set(cntarr[project][2])
        logging.info("oneclick_pr_num metrics exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting oneclick_pr_num metrics: {e}")


async def export_pr_missing_report(db, metrics):
    try:
        pr_missing_report_query_results = await db.fetch_all_async(
            f"EXECUTE pr_missing_report_query(date_trunc('minute',current_timestamp AT TIME ZONE '{stash_time_zone}'))"
        )
        metrics["oneclick_pr_missing_report"].clear()
        projects = set([result[2] for result in pr_missing_report_query_results])
        projects = await get_all_projects(db, projects)
        cntarr = {}
        for k in projects:
            cntarr[k] = [0] * 3
        for result in pr_missing_report_query_results:
            cntarr[result[2]][result[1]] = result[0]
        for project in projects:
            metrics["oneclick_pr_missing_report"].labels(pr_state="open", project=project).set(cntarr[project][0])
            metrics["oneclick_pr_missing_report"].labels(pr_state="merged", project=project).set(cntarr[project][1])
            metrics["oneclick_pr_missing_report"].labels(pr_state="declined", project=project).set(cntarr[project][2])
        logging.info("oneclick_pr_missing_report metrics exported")
    except OperationalError as econn:
        raise econn
    except Exception as e:
        logging.error(f"Error exporting pr_missing_report metrics: {e}")


def setup_metrics(client):
    metrics = {
        "oneclick_pr_missing_report": client.register_gauge(
            metric_name="oneclick_pr_missing_report",
            metric_description="The number of pull requests in one project with missing reports",
            label_names=["pr_state", "project"],
        ),
        "oneclick_pr_num": client.register_gauge(
            metric_name="oneclick_pr_num",
            metric_description="The number of pull requests in one project by state",
            label_names=["pr_state", "project"],
        ),
        "oneclick_open_pr_report": client.register_gauge(
            metric_name="oneclick_open_pr_report",
            metric_description="Report detail for open state pull requests by pull request id",
            label_names=[
                "stash_repo",
                "pr_no",
                "valid_appearance",
                "present_reports",
                "project",
                "code_coverage"
            ],
        ),
        "oneclick_closed_pr_report": client.register_gauge(
            metric_name="oneclick_closed_pr_report",
            metric_description="Report detail for recent one minute closed pull requests by pull request id",
            label_names=[
                "stash_repo",
                "pr_no",
                "valid_appearance",
                "present_reports",
                "project",
                "code_coverage"
            ],
        ),
        "oneclick_result_report": client.register_gauge(
            metric_name="oneclick_result_report",
            metric_description="The number of reports for open state pull requests in one project by report result category",
            label_names=["report", "status", "project"],
        ),
        "oneclick_check_summary": client.register_gauge(
            metric_name="oneclick_check_summary",
            metric_description="Report detail for enabled code insight checks by stash_repo",
            label_names=[
                "stash_repo",
                "valid_appearance",
                "enabled_checks",
                "project",
            ],
        ),
    }
    return metrics


async def main(metrics: dict, *, dbname: str, user: str, passfile: str, host: str, port: str):
    db = DatabaseConnection()
    try:
        status = await db.connect_async(
            dbname=dbname,
            user=user,
            passfile=passfile,
            host=host,
            port=port,
            application_name="oneclick metrics exporter",
            connect_timeout=int(os.getenv("POSTGRES_TIMEOUT") or 30),
        )
        if status is False:
            logging.error("Failed to connect to database, please check the connection")
            return
        await register_prepared_sqls(db)
        await get_all_projects(db, {})
        while True:
            next_chance = time.time() + fetch_interval
            logging.info("Start report collection...")
            async with asyncio.TaskGroup() as mtg:
                mtg.create_task(export_open_pr_report(db, metrics))
                mtg.create_task(export_closed_pr_report(db,metrics))
                mtg.create_task(export_result_report(db, metrics))
                mtg.create_task(export_pr_counts(db, metrics))
                mtg.create_task(export_pr_missing_report(db, metrics))
                mtg.create_task(export_check_summary(db, metrics))
            tmused = time.time() + fetch_interval - next_chance
            logging.info(f"Finish report collection in {tmused:.2f} seconds ...")
            wait_secends = next_chance - time.time()
            if wait_secends > 0:
                logging.debug(f"wait {wait_secends:.2f} seconds")
                await asyncio.sleep(wait_secends)
    finally:
        db.close_connection()


if __name__ == "__main__":
    verinfo = sys.version_info
    if verinfo.major < 3 or verinfo.major == 3 and verinfo.minor < 11:
        print("this script need 3.11 or newer python version", file=sys.stderr)
        exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("repoName", nargs="*", help="Slug Name of the repo to be move")
    parser.add_argument("--user", help="db connection user")
    parser.add_argument("--passfile", required=False, help="db password file")
    parser.add_argument("--host", help="db host name")
    parser.add_argument("--port", help="db port number")
    parser.add_argument("--dbname", help="db name")
    parser.add_argument("--loglevel", help="log level")
    args = parser.parse_args()

    if args.loglevel:
        level = logging.getLevelNamesMapping()[args.loglevel.upper()]
        logging.basicConfig(format="%(asctime)s  %(levelname)s - %(message)s", level=level)
    else:
        logging.basicConfig(format="%(asctime)s  %(levelname)s - %(message)s")
    client = MetricsExporter()
    client.start_server(8000)
    metrics = setup_metrics(client)
    fetch_interval = int(os.getenv("FETCH_INTERVAL") or 30)
    while True:
        try:
            asyncio.run(
                main(
                    metrics=metrics,
                    dbname=args.dbname,
                    user=args.user,
                    passfile=args.passfile,
                    host=args.host,
                    port=args.port,
                )
            )
        except Exception as e:
            logging.error(f"Error found: {e}")
        time.sleep(60)
