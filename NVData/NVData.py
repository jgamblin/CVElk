#!/usr/bin/env python3

import argparse
import eland as ed
import glob
import gzip
import json
import logging
import os
import warnings
import sys

from re import sub
from zipfile import ZipFile

import pandas as pd
import requests

from datetime import datetime
from elasticsearch import Elasticsearch
from envyaml import EnvYAML
from loguru import logger


env = EnvYAML('config.yml', strict=False)
logger.remove()
logger.add(sys.stderr, level=env['logging']['level'])

logging.getLogger('matplotlib.font_manager').disabled = True
warnings.filterwarnings("ignore")


def get_nvd_urls() -> list:
    nvd_urls = []
    for i in range(2002, datetime.today().year + 1):
        nvd_urls.append(f"{env['nvd']['feed']}nvdcve-1.1-{i}.json.{env['nvd']['archive_type']}")

    return nvd_urls


def download_file_from_internet(download_url, out_dir, proxy_request=False):
    logger.info(f"Downloading file from {download_url}")
    if proxy_request:
        response = requests.get(download_url, proxies=env['proxies'], verify=False)
    else:
        response = requests.get(download_url)
    logger.info(f"Saving {download_url.split('/')[-1]} to {out_dir}")
    if out_dir == '.':
        file_path = download_url.split('/')[-1]
    else:
        file_path = out_dir + download_url.split('/')[-1]
    open(file_path, 'wb').write(response.content)


def extract_files(directory):
    logger.info(f"Extracting NVD zip files to {directory}")

    files = [f for f in os.listdir(directory)]

    for file in files:
        if directory == '.':
            file_path = file
        else:
            file_path = directory + file
        if file.endswith("zip"):
            logger.info(f"Extracting {file_path}")
            with ZipFile(file_path, 'r') as zip_obj:
                zip_obj.extractall(directory)
        if file.endswith(".gz"):
            logger.info(f"Extracting {file_path}")
            with gzip.open(file_path, 'rb') as gz_file:
                with open(file_path.replace('.gz', ''), 'wb') as output_file:
                    output_file.write(gz_file.read())


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

    args = parser.parse_args()

    # Setup Connection to Elasticsearch
    if args.cloud:
        logger.info("Connecting to Elastic Cloud")
        es = Elasticsearch(
            cloud_id=env['elasticsearch']['cloud_id'],
            api_key=(env['elasticsearch']['api_id'], env['elasticsearch']['api_key'])
        )
    else:
        logger.info(f"Connecting to Elastic instance {env['elasticsearch']['host']}")
        es = Elasticsearch([env['elasticsearch']['host']],)

    if args.download:
        for url in get_nvd_urls():
            download_file_from_internet(download_url=url, out_dir=env['working_dir'])
        download_file_from_internet(download_url=env['epss']['url'], out_dir=env['working_dir'])

    if args.extract:
        extract_files(env['working_dir'])

    if args.push:
        # Create a Pandas Dataframe of Data to be Loaded into Elasticsearch
        data_frame = process_nvd_files(env['working_dir'])
        df = exploit_prediction_scoring_system(data_frame, env['working_dir'] + "epss_scores-current.csv")

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
