FROM python:3.10

ENV CVELK_LOGGING=INFO
ENV CVELK_DOWNLOAD_DIR=/app/nvd/
ENV NVD_FEED=https://nvd.nist.gov/feeds/json/cve/1.1/
ENV EPSS_URL=https://epss.cyentia.com/epss_scores-current.csv.gz
ENV ELASTICSEARCH_HOST=http://localhost:9200
ENV KIBANA_HOST=http://localhost:5601

RUN mkdir -p /app/nvd/
WORKDIR /app/

ADD app /app
ADD pyproject.toml /app
ADD poetry.lock /app

RUN pip install --upgrade pip && \
    pip install poetry &&\
    poetry export -o requirements.txt &&\
    pip install --user -r requirements.txt

RUN python3 main.py -d -e

ENTRYPOINT [ "python", "main.py"]