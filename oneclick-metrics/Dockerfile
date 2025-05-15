FROM python:3.12-slim

WORKDIR /app

#CI_BUILD_PLACE_HOLDER_0# !!! Do not modify this line !!!

RUN pip install --no-cache-dir prometheus_client psycopg[binary]

#CI_BUILD_PLACE_HOLDER_1# !!! Do not modify this line !!!

ADD . /app/
CMD ["python3", "app.py"]
