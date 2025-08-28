from datetime import UTC, datetime
import itertools
import json
import logging
import math
import os
import time
from typing import Any
from urllib.parse import urlparse
import uuid
import requests
from tqdm import tqdm
from stix2.serialization import serialize

from arango_cve_processor import config
from arango_cve_processor.managers.base_manager import RelationType
from arango_cve_processor.tools import cpe
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.tools.utils import stix2python
from .cve_kev import CISAKevManager
from .base_manager import STIXRelationManager

RATE_LIMIT_WINDOW = 30

class CpeMatchUpdateManager(STIXRelationManager, relationship_note="cpematch"):
    relation_type = RelationType.RELATE_SEQUENTIAL

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.api_key = os.environ.get("NVD_API_KEY")
        self.requests_per_window = 5
        if self.api_key:
            self.session.headers = {"apiKey": self.api_key}
            self.requests_per_window = 50
        if not self.modified_min:
            raise ValueError("modified_min is required for this mode")
        self.ignore_embedded_relationships = True

    def get_updated_cpematches(self):
        total_results = math.inf
        start_index = 0
        query = dict(startIndex=0)
        if self.modified_min:
            query.update(
                lastModStartDate=self.modified_min,
                lastModEndDate=datetime.now(UTC).isoformat(),
            )

        iterator = tqdm(total=1, desc="retrieve cpematch from nvd")
        backoff_time = RATE_LIMIT_WINDOW / 2
        url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
        while start_index < total_results:
            logging.info(
                f"Calling NVD API `{url}` with startIndex: {start_index}",
            )
            query.update(startIndex=start_index)

            try:
                logging.info(f"Query => {query}")
                response = self.session.get(url, params=query)
                logging.info(f"URL => {response.url}")
                logging.info(f"HEADERS => {response.request.headers}")
                logging.info(
                    f"Status Code => {response.status_code} [{response.reason}]"
                )
                if response.status_code != 200:
                    logging.warning(
                        "Got response status code %d.", response.status_code
                    )
                    raise requests.ConnectionError

            except requests.ConnectionError as ex:
                logging.warning(
                    "Got ConnectionError. Backing off for %d seconds.", backoff_time
                )
                time.sleep(backoff_time)
                backoff_time = min(backoff_time * 1.5, RATE_LIMIT_WINDOW*20)
                continue

            backoff_time = RATE_LIMIT_WINDOW / 2
            content = response.json()
            total_results = content["totalResults"]
            logging.info(f"Total Results {total_results}")
            groups: dict[str, dict] = {
                group["matchString"]["matchCriteriaId"]: group["matchString"]
                for group in content["matchStrings"]
            }
            iterator.total = total_results
            iterator.update(len(groups))
            yield groups

            start_index += content["resultsPerPage"]
            if start_index < total_results:
                time.sleep(RATE_LIMIT_WINDOW / self.requests_per_window)

    def process(self, **kwargs):
        for groupings in self.get_updated_cpematches():
            if not groupings:
                continue
            objects = self.get_objects(groupings)
            self.groupings = groupings
            self.grouping_objects = []
            self.do_process(objects)

    def get_objects(self, criteria_ids):
        query = """
        FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "acvep_cpematch", forceIndexHint: true}
        FILTER doc.type == 'indicator' AND doc._is_latest == TRUE
        FILTER doc.x_cpes.vulnerable[*].matchCriteriaId IN @criteria_ids OR doc.x_cpes.not_vulnerable[*].matchCriteriaId IN @criteria_ids
        RETURN doc
        """
        return self.arango.execute_raw_query(
            query,
            bind_vars={
                # "@collection": self.collection,
                "criteria_ids": list(criteria_ids),
            },
        )

    def relate_single(self, object):
        indicator = object
        retval = []
        for x_cpe_item in itertools.chain(*object['x_cpes'].values()):
            if match_data := self.groupings.get(x_cpe_item['matchCriteriaId']):
                objects = cpe.parse_objects_for_criteria(match_data)
                grouping_object = objects[0]
                self.grouping_objects.append(grouping_object)
                relationships = cpe.relate_indicator(grouping_object, indicator)
                for r in relationships:
                    r['_from'] = indicator['_id']
                retval.extend(objects)
                retval.extend(relationships)
        return stix2python(retval)