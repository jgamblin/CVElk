#!/usr/bin/env python3

from elasticsearch import Elasticsearch
from re import sub
import eland as ed
import glob
import json
import logging
import pandas as pd
import warnings

INDEX="cve"
TYPE= "record"

logging.getLogger('matplotlib.font_manager').disabled = True
warnings.filterwarnings("ignore")

row_accumulator = []
for filename in glob.glob('nvdcve-1.1-20*.json'):
    with open(filename, 'r', encoding='utf-8') as f:
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
                vector_string  = 'Missing_Data'
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


nvd['Published'] = pd.to_datetime(nvd['Published'])
nvd['Modified'] = pd.to_datetime(nvd['Modified'])
epss = pd.read_csv('epss_scores-current.csv', skiprows=1)
epss = epss.rename(columns={"cve": "CVE", "epss" : "EPSS", "percentile" : "EPSSPercentile"})
epss['EPSS'] = epss['EPSS']*100
epss['EPSSPercentile'] = epss['EPSSPercentile']*100
epss_nvd = pd.merge(nvd, epss, how='inner', left_on='CVE', right_on='CVE')
epss_nvd['BaseScore'] = epss_nvd['BaseScore'].apply(pd.to_numeric)
epss_nvd['_id'] = epss_nvd['CVE']


## Setup Variables

elasticHost      = 'http://localhost:9200'
## Setup Connection to Elasticsearch
es = Elasticsearch(
    [elasticHost],   
)

## Create a Pandas Dataframe of Data to be Loaded into Elasticsearch
df = epss_nvd

## Replace NaN (null) Values with Zero 
df.fillna(0, inplace=True)

# Rename the Columns to be Camel Case
def camel_case_string(string):
    string =  sub(r"(_|-)+", " ", string).title().replace(" ", "")
    string = string[0].lower() + string[1:]
    return string
df.columns = [camel_case_string(x) for x in df.columns]

## Save the Data into Elasticsearch
df = ed.pandas_to_eland(
    pd_df=df,
    es_client=es,
    es_dest_index="cves",
    es_if_exists="replace",
    es_refresh=True,
)
