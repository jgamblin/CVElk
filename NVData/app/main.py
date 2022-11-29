import argparse
import eland as ed
import glob

import json
import logging
import os
import sys
import warnings

from re import sub

import pandas as pd

from datetime import datetime
from elasticsearch import Elasticsearch
from envyaml import EnvYAML
from loguru import logger

import util
from api import KibanaAPI

env = EnvYAML(str('config.yml'), strict=False)
logger.remove()
logging_level = util.set_variable(os.environ.get('CVELK_LOGGING'), env['logging']['level'])
logger.add(sys.stderr, level=logging_level)
logger.info(f"Logging level set to {logging_level}")

logging.getLogger('matplotlib.font_manager').disabled = True
warnings.filterwarnings("ignore")


def get_nvd_urls(nvd_feed: str) -> list:
    nvd_urls = []
    for i in range(2002, datetime.today().year + 1):
        nvd_urls.append(f"{nvd_feed}nvdcve-1.1-{i}.json.{env['nvd']['archive_type']}")

    return nvd_urls


def process_nvd_files(directory) -> pd.DataFrame:
    row_accumulator = []
    for filename in glob.glob(directory + 'nvdcve-1.1-20*.json'):
        with open(filename, 'r', encoding='utf-8') as f:
            logger.info(f"Processing {filename}")
            nvd_data = json.load(f)
            for entry in nvd_data['CVE_Items']:
                cve = entry['cve']['CVE_data_meta']['ID']
                try:
                    published_date = entry['publishedDate']
                except KeyError:
                    published_date = 'Missing_Data'
                try:
                    modified_date = entry['publishedDate']
                except KeyError:
                    modified_date = '2000-01-01T00:00Z'
                try:
                    vector_string = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
                except KeyError:
                    vector_string = 'Missing_Data'
                try:
                    attack_vector = entry['impact']['baseMetricV3']['cvssV3']['attackVector']
                except KeyError:
                    attack_vector = 'Missing_Data'
                try:
                    attack_complexity = entry['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                except KeyError:
                    attack_complexity = 'Missing_Data'
                try:
                    privileges_required = entry['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                except KeyError:
                    privileges_required = 'Missing_Data'
                try:
                    user_interaction = entry['impact']['baseMetricV3']['cvssV3']['userInteraction']
                except KeyError:
                    user_interaction = 'Missing_Data'
                try:
                    scope = entry['impact']['baseMetricV3']['cvssV3']['scope']
                except KeyError:
                    scope = 'Missing_Data'
                try:
                    confidentiality_impact = entry['impact']['baseMetricV3']['cvssV3']['confidentialityImpact']
                except KeyError:
                    confidentiality_impact = 'Missing_Data'
                try:
                    integrity_impact = entry['impact']['baseMetricV3']['cvssV3']['integrityImpact']
                except KeyError:
                    integrity_impact = 'Missing_Data'
                try:
                    availability_impact = entry['impact']['baseMetricV3']['cvssV3']['availabilityImpact']
                except KeyError:
                    availability_impact = 'Missing_Data'
                try:
                    base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
                except KeyError:
                    base_score = '0.0'
                try:
                    base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                except KeyError:
                    base_severity = 'Missing_Data'
                try:
                    exploitability_score = entry['impact']['baseMetricV3']['exploitabilityScore']
                except KeyError:
                    exploitability_score = 'Missing_Data'
                try:
                    impact_score = entry['impact']['baseMetricV3']['impactScore']
                except KeyError:
                    impact_score = 'Missing_Data'
                try:
                    cwe = entry['cve']['problemtype']['problemtype_data'][0]['description'][0]['value']
                except IndexError:
                    cwe = 'Missing_Data'
                try:
                    description = entry['cve']['description']['description_data'][0]['value']
                except IndexError:
                    description = ''
                new_row = {
                    'CVE': cve,
                    'Published': published_date,
                    'Modified': modified_date,
                    'VectorString': vector_string,
                    'AttackVector': attack_vector,
                    'AttackComplexity': attack_complexity,
                    'PrivilegesRequired': privileges_required,
                    'UserInteraction': user_interaction,
                    'Scope': scope,
                    'ConfidentialityImpact': confidentiality_impact,
                    'IntegrityImpact': integrity_impact,
                    'AvailabilityImpact': availability_impact,
                    'BaseScore': base_score,
                    'BaseSeverity': base_severity,
                    'ExploitabilityScore': exploitability_score,
                    'ImpactScore': impact_score,
                    'CWE': cwe,
                    'Description': description
                }
                row_accumulator.append(new_row)
        nvd = pd.DataFrame(row_accumulator)
        logger.info(f"Panda DataFrame created from {filename}")

    nvd['Published'] = pd.to_datetime(nvd['Published'])
    nvd['Modified'] = pd.to_datetime(nvd['Modified'])

    return nvd


def exploit_prediction_scoring_system(nvd: pd.DataFrame, epss_scores_csv_file: str):
    logger.info(f"Creating Exploit Prediction Scoring System (EPSS)")

    epss = pd.read_csv(epss_scores_csv_file, skiprows=1)
    epss = epss.rename(columns={"cve": "CVE", "epss": "EPSS", "percentile": "EPSSPercentile"})
    epss['EPSS'] = epss['EPSS'] * 100
    epss['EPSSPercentile'] = epss['EPSSPercentile'] * 100
    epss_nvd = pd.merge(nvd, epss, how='inner', left_on='CVE', right_on='CVE')
    epss_nvd['BaseScore'] = epss_nvd['BaseScore'].apply(pd.to_numeric)
    epss_nvd['_id'] = epss_nvd['CVE']

    return epss_nvd


# Rename the Columns to be Camel Case
def camel_case_string(string):
    string = sub(r"(_|-)+", " ", string).title().replace(" ", "")
    string = string[0].lower() + string[1:]
    return string


def get_elasticsearch(cloud: bool):

    if cloud:
        logger.info("ES Cloud ID being set")
        es_cloud_id = util.set_variable(os.environ.get('ELASTICSEARCH_CLOUD_ID'), env['elasticsearch']['cloud_id'])
        logger.info("ES Cloud API ID being set")
        es_cloud_api_id = util.set_variable(os.environ.get('ELASTICSEARCH_API_ID'), env['elasticsearch']['api_id'])
        logger.info("ES Cloud API Key being set")
        es_cloud_api_key = util.set_variable(os.environ.get('ELASTICSEARCH_API_KEY'), env['elasticsearch']['api_key'])

        if es_cloud_id and es_cloud_api_id and es_cloud_api_key:
            logger.info(f"Setting up connection to Elastic Cloud {es_cloud_id}")
            elasticsearch = Elasticsearch(
                cloud_id=es_cloud_id,
                api_key=(es_cloud_api_id, es_cloud_api_key)
            )
        else:
            logger.error(f"Not all variables for cloud connection not set")
            exit(1)

    else:
        logger.info("ES Host URL being set")
        es_host = util.set_variable(os.environ.get('ELASTICSEARCH_HOST'), env['elasticsearch']['host'])
        logger.info(f"Connection URL for Elasticsearch: {es_host}")
        elasticsearch = Elasticsearch([es_host],)

    logger.info("Checking connection to Elasticsearch")
    if not elasticsearch.ping():
        logger.error(f"Connection failed")
        exit(1)
    else:
        logger.info("Connection successful")

    return elasticsearch


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        prog='NVData',
        description="Pull data from NVD and put it into Elastic"
    )
    parser.add_argument('-c', '--cloud', action='store_true', help='Use Elastic Cloud')
    parser.add_argument(
        '-d', '--download', action='store_true',
        help='Download NVD database and EPSS to the working directory declared in config.yml'
    )
    parser.add_argument(
        '-e', '--extract', action='store_true',
        help='Extract NVD files in the working directory declared in config.yml'
    )
    parser.add_argument(
        '-p', '--push', action='store_true',
        help='Process NVD files in the working directory declared in config.yml and push them to Elasticsearch'
    )
    parser.add_argument(
        '-k', '--kibana', action='store_true',
        help='Configure Kibana with the CVE index, dashboard and setting dark theme'
    )

    args = parser.parse_args()

    download_dir = util.set_variable(os.environ.get('CVELK_DOWNLOAD_DIR'), env['download_dir'])

    if args.download:
        # Set variables, if they are set as env variables use them if not resort to the values in the config.yml
        the_nvd_feed = util.set_variable(os.environ.get('NVD_FEED'), env['nvd']['feed'])
        logger.info(f"Using NVD feed: {the_nvd_feed}")
        the_epss_url = util.set_variable(os.environ.get('EPSS_URL'), env['epss']['url'])
        logger.info(f"Using EPSS URL: {the_epss_url}")

        for url in get_nvd_urls(the_nvd_feed):
            util.download_file_from_internet(download_url=url, out_dir=download_dir, proxies=env['proxies'])
        util.download_file_from_internet(download_url=the_epss_url, out_dir=download_dir, proxies=env['proxies'])

    if args.extract:
        util.extract_files(download_dir)

    if args.push:
        es = get_elasticsearch(args.cloud)

        # Create a Pandas Dataframe of Data to be Loaded into Elasticsearch
        data_frame = process_nvd_files(download_dir)
        df = exploit_prediction_scoring_system(data_frame, download_dir + "epss_scores-current.csv")

        # Replace NaN (null) Values with Zero
        df.fillna(0, inplace=True)

        df.columns = [camel_case_string(x) for x in df.columns]

        logger.info("Uploading data to Elasticsearch")
        # Save the Data into Elasticsearch
        df = ed.pandas_to_eland(
            pd_df=df,
            es_client=es,
            es_dest_index="cves",
            es_if_exists="replace",
            es_refresh=True,
        )
        logger.info("Successfully uploaded data to Elasticsearch")

    if args.kibana:
        kibana_host = util.set_variable(os.environ.get('KIBANA_HOST'), env['kibana']['host'])
        logger.info(f"Connection for Kibana: {kibana_host}")

        kb = KibanaAPI(url=kibana_host)

        kb.set_theme()
        dashboard = kb.create_dashboard()
        dash_url = kibana_host + "/app/dashboards#/view/" + dashboard.json().get('successResults')[1].get('destinationId')
        logger.info(f"Done visit {dash_url} to view the dashboard")
