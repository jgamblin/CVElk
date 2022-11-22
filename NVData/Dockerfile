FROM python:latest

ADD pyproject.toml /
ADD poetry.lock /
ADD NVData.py / 
ADD config.yml.example config.yml

RUN pip install --upgrade pip && \
    pip install poetry &&\
    poetry export -o requirements.txt &&\
    pip install --user -r requirements.txt

RUN python3 NVData.py -d -e

CMD [ "python", "./NVData.py", "-p"]