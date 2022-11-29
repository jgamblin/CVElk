import os

import gzip
import requests

from loguru import logger
from zipfile import ZipFile


def download_file_from_internet(download_url, out_dir, proxies, proxy_request=False):
    logger.info(f"Downloading file from {download_url}")
    if proxy_request:
        response = requests.get(download_url, proxies=proxies, verify=False)
    else:
        response = requests.get(download_url)
    logger.info(f"Saving {download_url.split('/')[-1]} to {out_dir}")
    if out_dir == '.':
        file_path = download_url.split('/')[-1]
    else:
        file_path = out_dir + download_url.split('/')[-1]
    open(file_path, 'wb').write(response.content)


def extract_files(directory):
    logger.info(f"Extracting NVD archive files to {directory}")

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
            logger.info(f"File {file_path} extracted, cleaning up...")
            os.remove(file_path)


def set_variable(environment_variable, config_file_variable):
    if environment_variable:
        logger.info(f"Environment variable will be used")
        return environment_variable
    elif config_file_variable:
        logger.info(f"Config file variable will be used")
        return config_file_variable
    else:
        logger.info(f"No value set")
        return None
