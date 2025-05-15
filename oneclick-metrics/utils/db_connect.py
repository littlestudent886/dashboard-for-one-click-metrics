import logging
from psycopg import AsyncConnection, Connection, OperationalError

import psycopg.rows


class DatabaseConnection:
    def __init__(self):
        self.connection: Connection = None
        self.async_connection: AsyncConnection = None

    def connect(self, autocommit: bool = True, **kwargs) -> bool:
        """establish a connection to the database"""
        try:
            logging.info("Trying to connect to the database")
            self.connection = psycopg.connect(autocommit=autocommit, **kwargs)
            logging.info("Successfully connected to the database")
            return True
        except OperationalError as e:
            logging.error(f"Fail to connect to the database: {e}")
            return False

    async def connect_async(self, autocommit: bool = True, **kwargs) -> bool:
        """establish a connection to the database"""
        try:
            logging.info("Trying to connect to the database")
            self.async_connection = await psycopg.AsyncConnection.connect(autocommit=autocommit, **kwargs)
            logging.info("Successfully connected to the database")
            return True
        except OperationalError as e:
            logging.error(f"Fail to connect to the database: {e}")
            return False

    def close_connection(self):
        """close the database connection"""
        if self.connection:
            self.connection.close()
            logging.info("connection closed")

    def fetch_all(self, query: str, params: list = None) -> list[psycopg.rows.Row]:
        """get data from the database"""
        with self.connection.cursor() as cur:
            cur.execute(query, params)
            result = cur.fetchall()
            return result

    def execute(self, query: str, params: list = None) -> psycopg.pq.abc.PGresult:
        """execute one DDL/CML script"""
        with self.connection.cursor() as cur:
            cur.execute(query, params)
            result = cur.pgresult
            return result

    async def fetch_all_async(self, query: str, params: list = None) -> list[psycopg.rows.Row]:
        """get data from the database"""
        async with self.async_connection.cursor() as cur:
            await cur.execute(query, params)
            result = await cur.fetchall()
            return result

    async def execute_async(self, query: str, params: list = None) -> psycopg.pq.abc.PGresult:
        """execute one DDL/CML script"""
        async with self.async_connection.cursor() as cur:
            await cur.execute(query, params)
            result = cur.pgresult
            return result


# example
# db = DatabaseConnection()
# db.connect(host=xxx,port=xxx,passfile=xxx)

# query = "SELECT * FROM your_table_name;"
# results = db.fetch_all(query)

# for row in results:
#     print(row)

# db.close_connection()
