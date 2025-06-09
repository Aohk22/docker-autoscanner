#!/usr/bin/env python3

import requests
import sys
import os
import hashlib
import time
import logging
from urllib.parse import quote
from dotenv import load_dotenv

URL_FILE = 'https://www.virustotal.com/api/v3/files'
URL_SANDBOX_HTML = 'https://www.virustotal.com/api/v3/file_behaviours/sandbox_id/html'
BUF_SIZE = 65536  
OUTPUT_FOLDER = 'vt-output'
REPORT_DIR = 'html-reports'
REPORT_DIR_PATH = os.path.join(OUTPUT_FOLDER, REPORT_DIR)

os.makedirs(REPORT_DIR_PATH, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

logger = logging.getLogger(__name__)
# logging.basicConfig(filename=(os.path.join(OUTPUT_FOLDER, 'submitvtlogs.log')), encoding='utf-8', level=logging.INFO)
logging.basicConfig(level=logging.INFO)

# helper functions
def handle_response_error(res):
    logger.info(f'Error status code {res.status_code}')
    logger.info(f'Error data {res.text}')
    raise Exception('Web response error')
    

def get_file_hashes(fn: str):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(fn, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    return md5, sha1, sha256

def get_available_sandboxes(data):
    '''
    Gets sandboxes with available HTML to download from full behaviour analysis.
    '''
    sandbox_ids = []
    for entry in data.get("data", []):
        attributes = entry.get("attributes", {})
        sandbox_id = entry.get("id", "")
        sb_name = attributes.get('sandbox_name')
        has_html = attributes.get("has_html_report", False)
        if has_html:
            sandbox_ids.append((sb_name, sandbox_id))
    return sandbox_ids


# web request functions
def vt_submit_file(url: str, api_key, fn: str, fh):
    '''
    Submits file to VirusTotal.
    '''
    files = { "file": (fn, fh, "application/octet-stream") }
    headers = { "accept": "application/json", 'x-apikey': api_key }

    logger.info(f'Sending request to {url}')
    res = requests.post(url, files=files, headers=headers)
    if (res.status_code == 200):
        res_json = res.json()

        logger.info('File submission response')
        logger.info(f"Request type:\t{res_json['data']['type']}")
        logger.info(f"File id:\t{res_json['data']['id']}")
        logger.info(f"Analyses link:\t{res_json['data']['links']['self']}")
    else:
        handle_response_error(res)


def vt_get_summary(url: str, api_key, filehash: str):
    '''
    Writes summary to file.
    Currently unused.
    '''
    url += f'/{filehash}/behaviour_summary'
    headers = { "accept": "application/json", 'x-apikey': api_key }
    fn = 'summary.json'
    file_path = os.path.join(OUTPUT_FOLDER, fn)

    logger.debug(f'File path {file_path}')
    logger.info(f'Sending request to {url}')
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        try:
            with open(file_path, 'w') as file:
                file.write(res.text)
            logger.info('Summary written to {file_path}')
        except Exception as e:
            raise Exception(e)
    else:
        handle_response_error(res)


def vt_get_behaviour(url: str, api_key, filehash: str):
    '''
    Gets full behaviour analysis from VirusTotal.
    Returns response if succesfull for getting HTML sandbox report.
    '''
    url += f'/{filehash}/behaviours'
    headers = { 'accept': 'application/json', 'x-apikey': api_key}

    logger.debug(f'Sending request to {url}')
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        return res.json()
    else:
        handle_response_error(res)


def vt_get_sandbox_html(url: str, api_key, box_name: str, sandbox_id: str):
    '''
    Retrieve HTML report.
    '''
    url = url.replace('sandbox_id', quote(sandbox_id)) # url encode
    box_name = f'{box_name}.html'
    headers = { "accept": "text/plain", 'x-apikey': api_key }
    file_path = os.path.join(REPORT_DIR_PATH, box_name)

    logger.debug(f'File path {file_path}')
    logger.debug(f'Sending request to {url}')
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        try:
            with open(file_path, 'w') as file:
                file.write(res.text)
            logger.info(f'Report written to {file_path}')
        except Exception as e:
            raise Exception(e)
    else:
        handle_response_error(res)


def main():
    fn = sys.argv[1]
    fh = open(fn, 'rb')

    if not load_dotenv() and not os.environ.get('VIRUS_TOTAL_API'):
        logger.debug('API key not found')
        print('VirusTotal API key not found, exiting.')
        exit(1)
    api_key = os.environ.get('VIRUS_TOTAL_API')
    _, _, sha256 = get_file_hashes(fn)

    try:
        logger.info('Submitting file...')
        vt_submit_file(URL_FILE, api_key, fn, fh)
        print('---')

        logger.info('Getting behaviour summary...')
        vt_get_summary(URL_FILE, api_key, sha256.hexdigest())
        print('---')
            
        logger.info('Getting available HTML sandbox reports...')
        full_behaviour = vt_get_behaviour(URL_FILE, api_key, sha256.hexdigest())
        sandboxes = get_available_sandboxes(full_behaviour) # tuple[<name>, <id>]
        print('---')

        logger.info('Getting detailed HTML sandbox reports...')
        if len(sandboxes) > 0:
            logger.info('Available sanboxes {sanboxes}')
            for sanbox in sandboxes: 
                vt_get_sandbox_html(URL_SANDBOX_HTML, api_key, sanbox[0], sanbox[1])
                time.sleep(3) # wait sometime before sending another request
        else:
            logger.info('No HTML reports are available.')
    except Exception as e:
        logger.info(f'Error occured {e}')
        exit(1)


if __name__ == '__main__':
    main()
