import requests

from loguru import logger


class KibanaAPI:

    def __init__(self, url):
        self.url = url
        self.headers = {"kbn-xsrf": "kibana"}

    def set_theme(self):

        url = self.url + "/api/kibana/settings/theme:darkMode"
        logger.info(f"Sending request {url}")
        response = requests.post(url=url, headers=self.headers, data='{ "value": true}')
        logger.info(f"Dark theme set on Kibana")

        return response

    def create_dashboard(self):

        url = self.url + "/api/saved_objects/_import?createNewCopies=true"
        logger.info(f"Sending request {url}")
        files = {'file': open('resources/dashboard.ndjson', 'rb')}
        response = requests.post(url=url, headers=self.headers, files=files)
        logger.info(f"CVE Index and dashboard created in Kibana")

        return response
