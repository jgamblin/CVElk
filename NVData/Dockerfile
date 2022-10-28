FROM python:latest

ADD requirements.txt /
ADD NVData.py / 
ADD urls.txt /

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

RUN apt install unzip wget

RUN wget -i urls.txt && unzip -o "*.zip" && \
wget https://epss.cyentia.com/epss_scores-current.csv.gz -O epss_scores-current.csv.gz && gzip -d epss_scores-current.csv.gz 

CMD [ "python", "./NVData.py"]

