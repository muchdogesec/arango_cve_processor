import logging
import math
import os
import time
import requests


RATE_LIMIT_WINDOW = 30
RATE_LIMIT_MAX_SLEEP = 10*60 #10 minutes


def fetch_nvd_api(url, query: dict):
    total_results = math.inf
    start_index = 0
    query.update(startIndex=0)

    session = requests.Session()
    api_key = os.environ.get("NVD_API_KEY")
    requests_per_window = 5
    if api_key:
        session.headers = {"apiKey": api_key}
        requests_per_window = 50

    backoff_time = RATE_LIMIT_WINDOW / 2
    while start_index < total_results:
        logging.info(
            f"Calling NVD API `{url}` with startIndex: {start_index}",
        )
        query.update(startIndex=start_index)

        try:
            logging.info(f"Query => {query}")
            response = session.get(url, params=query)
            logging.info(f"URL => {response.url}")
            logging.info(f"HEADERS => {response.request.headers}")
            logging.info(f"Status Code => {response.status_code} [{response.reason}]")
            if response.status_code != 200:
                logging.warning("Got response status code %d.", response.status_code)
                raise requests.ConnectionError

        except requests.ConnectionError as ex:
            logging.warning(
                "Got ConnectionError. Backing off for %d seconds.", backoff_time
            )
            time.sleep(backoff_time)
            backoff_time = min(backoff_time * 1.5, RATE_LIMIT_MAX_SLEEP)
            continue

        backoff_time = RATE_LIMIT_WINDOW / 2
        content: dict = response.json()
        total_results = content["totalResults"]
        logging.info(f"Total Results {total_results}")
        t = time.time()
        yield content
        dt = time.time() - t
        start_index += content["resultsPerPage"]
        if start_index < total_results:
            time.sleep(max(RATE_LIMIT_WINDOW / requests_per_window - dt, 0))
