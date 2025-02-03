from datetime import datetime, timezone
import json
import logging
import time
import uuid

from stix2arango.services.arangodb_service import ArangoDBService
from arango_cve_processor import config
from arango_cve_processor.tools.epss import EPSSManager
from arango_cve_processor.tools.utils import stix2dict
from .base_manager import STIXRelationManager
from stix2 import Vulnerability, Report


class CveEpssManager(STIXRelationManager, relationship_note="cve-epss"):
    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"
    default_objects = [
        "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/report-epss-scoring.json"
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.update_objects = []

    def get_objects(self, **kwargs):
        limit = 20_000
        query = """
  FOR doc IN @@collection
  FILTER doc._is_latest == TRUE AND doc.type == 'report' AND doc.labels[0] == 'epss' && doc._record_created >= @record_created
  LET cve_name = doc.external_references[0].external_id
  FILTER (NOT @cve_ids OR cve_name IN @cve_ids)
  LIMIT @limit
  RETURN [cve_name, KEEP(doc, '_key', 'x_epss', '_record_created')]
        """
        objects = []
        record_created = ""

        t0 = time.time()
        while True:
            t = time.time()
            ret = self.arango.execute_raw_query(
                query,
                bind_vars={
                    "@collection": self.collection,
                    # "created_min": self.created_min,
                    # "modified_min": self.modified_min,
                    'cve_ids': self.cve_ids or None,
                    'record_created': record_created,
                    'limit': limit,
                },
            )
            objects.extend(ret)
            if len(ret) < limit:
                break
            record_created = ret[-1][1]['_record_created']
            logging.info(f'retrieving... len = {len(objects)}, t = {time.time() - t}, total_time = {time.time() - t0}')
        return objects

    def pre_process(self, objects):
        todays_epss_all = EPSSManager.get_epss_data()
        cve_ids = set(todays_epss_all)
        if self.cve_ids:
            cve_ids = cve_ids.intersection(self.cve_ids)

        epss_objects = {}
        for cve_name, report_obj in objects:
            epss_objects[cve_name] = dict(name=cve_name, id=self.get_cve_id(cve_name), epss=report_obj)

        for epss in todays_epss_all.values():
            cve_name = epss["cve"]
            if cve_name in epss_objects or cve_name not in cve_ids:
                continue
            epss_objects[cve_name] = dict(name=cve_name, id=self.get_cve_id(cve_name), epss=None)
        return [epss for epss in epss_objects.values()]
    
    def do_process(self, objects):
        objects = self.pre_process(objects)
        return super().do_process(objects)
    
    @staticmethod
    def get_cve_id(name):
        cve2stix_namespace = uuid.UUID("562918ee-d5da-5579-b6a1-fae50cc6bad3")
        return "vulnerability--" + str(uuid.uuid5(cve2stix_namespace, name))
    
    def relate_single(self, object):
        todays_report = parse_cve_epss_report(object)
        if not todays_report:
            return []
        if object["epss"]:
            all_epss = sorted(
                object["epss"]["x_epss"] + todays_report["x_epss"],
                key=lambda x: x["date"],
            )
            if len(set(map(lambda x: x["date"], all_epss))) != len(
                object["epss"]["x_epss"]
            ):
                self.update_objects.append(
                    {
                        **object["epss"],
                        "x_epss": all_epss,
                        "_record_modified": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        ),
                        "modified": datetime.strptime(all_epss[0]["date"], "%Y-%m-%d")
                        .date()
                        .strftime("%Y-%m-%dT00:00:00.000Z"),
                        "_arango_cve_processor_note": self.relationship_note,
                    }
                )
            return []
        else:
            return [stix2dict(todays_report)]

    def upload_vertex_data(self, objects):
        logging.info("updating %d existing reports", len(self.update_objects))
        self.arango.execute_raw_query(
            """
        FOR obj IN @objects
        UPDATE obj IN @@collection
        """,
            bind_vars={
                "@collection": self.vertex_collection,
                "objects": self.update_objects,
            },
            batch_size=self.BATCH_SIZE,
        )

        return super().upload_vertex_data(objects)


def parse_cve_epss_report(vulnerability: Vulnerability):
    try:
        cve_id = vulnerability.get("name")
        epss_data = EPSSManager.get_data_for_cve(cve_id)
        content = f"EPSS Scores: {cve_id}"

        if epss_data:
            epss_data = [epss_data]
        else:
            epss_data = []

        modified = None
        if epss_data:
            modified = datetime.strptime(epss_data[-1]["date"], "%Y-%m-%d").date()

        return Report(
            id="report--"+str(uuid.uuid5(config.namespace, content)),
            created=modified,
            modified=modified,
            published=modified,
            name=content,
            x_epss=epss_data,
            object_refs=[
                vulnerability["id"],
            ],
            extensions={
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            object_marking_refs=config.OBJECT_MARKING_REFS,
            created_by_ref=config.IDENTITY_REF,
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                }
            ],
            labels=["epss"],
        )
    except:
        logging.error("get epss for %s failed", vulnerability.get("name"))
        return []
