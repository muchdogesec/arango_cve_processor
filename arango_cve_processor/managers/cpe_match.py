from datetime import UTC, date, datetime
from datetime import UTC, date, datetime
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
from arango_cve_processor.tools import cpe
from arango_cve_processor.tools.nvd import fetch_nvd_api
from arango_cve_processor.tools.retriever import STIXObjectRetriever, chunked
from arango_cve_processor.tools.utils import stix2python
from .cve_kev import CISAKevManager
from .base_manager import STIXRelationManager


class CpeMatchUpdateManager(STIXRelationManager, relationship_note="cpematch"):
    DESCRIPTION = """
    Run CPEMATCH Updates for CVEs in database
    """

    def __init__(self, *args, updated_after, **kwargs):
        super().__init__(*args, **kwargs)
        self.updated_after = updated_after
        if not self.updated_after:
            raise ValueError("updated_after is required for this mode")
        if isinstance(self.updated_after, (datetime, date)):
            self.updated_after = self.updated_after.isoformat()
        self.ignore_embedded_relationships = True
        self.updated_before = datetime.now(UTC).isoformat()

    def get_updated_cpematches(self):
        query = {}
        if self.updated_after:
            query.update(
                lastModStartDate=self.updated_after,
                lastModEndDate=self.updated_before,
            )
        iterator = tqdm(total=1, desc="retrieve cpematch from nvd")
        for content in fetch_nvd_api("https://services.nvd.nist.gov/rest/json/cpematch/2.0", query):
            groups: dict[str, dict] = {
                group["matchString"]["matchCriteriaId"]: group["matchString"]
                for group in content["matchStrings"]
            }
            iterator.total = content["totalResults"]
            iterator.update(len(groups))
            yield groups

    def get_object_chunks(self):
        for groupings in self.get_updated_cpematches():
            if not groupings:
                continue
            objects = self.get_single_chunk(list(groupings))
            self.groupings = groupings
            for objects_chunk in chunked(objects, 200):
                yield objects_chunk

    def get_single_chunk(self, criteria_ids):
        query = """
        FOR doc IN nvd_cve_vertex_collection OPTIONS {indexHint: "acvep_cpematch", forceIndexHint: true}
        FILTER doc.type == 'indicator' AND doc._is_latest == TRUE
        FILTER doc.x_cpes.vulnerable[*].matchCriteriaId IN @criteria_ids OR doc.x_cpes.not_vulnerable[*].matchCriteriaId IN @criteria_ids
        RETURN KEEP(doc, 'id', 'x_cpes', 'name', '_id', 'external_references', 'created', 'modified')
        """
        return self.arango.execute_raw_query(
            query,
            bind_vars={
                "criteria_ids": list(criteria_ids),
            },
        )

    def relate_single(self, indicator):
        retval = []
        for x_cpe_item in itertools.chain(*indicator['x_cpes'].values()):
            if match_data := self.groupings.get(x_cpe_item['matchCriteriaId']):
                objects = cpe.parse_objects_for_criteria(match_data)
                grouping_object = objects[0]
                relationships = cpe.relate_indicator(grouping_object, indicator)
                deprecations = cpe.parse_deprecations(objects[1:])
                for r in relationships:
                    r['_from'] = indicator['_id']
                retval.extend(objects)
                retval.extend(relationships)
                retval.extend(deprecations)
        return stix2python(retval)