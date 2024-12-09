from datetime import datetime, timezone
import json
import logging

from stix2arango.services.arangodb_service import ArangoDBService
from arango_cve_processor.tools.epss import EPSSManager
from arango_cve_processor.tools.cpe_match import fetch_cpe_matches
from arango_cve_processor.tools.utils import stix2dict
from .base_manager import STIXRelationManager
from stix2 import Vulnerability, Report


class CveEpssManager(STIXRelationManager, relationship_note='cve-epss'):
    edge_collection = 'nvd_cve_edge_collection'
    vertex_collection = 'nvd_cve_vertex_collection'
    default_objects = [
        "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/report-epss-scoring.json"
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.update_objects = []

    def get_objects(self, **kwargs):
        query = """
LET cve_epss_map = MERGE(
  FOR doc IN @@collection
  FILTER doc._is_latest AND doc.type == 'report' AND doc.x_epss != NULL
  LET cve_name = doc.external_references[0].external_id
  RETURN {[cve_name]: KEEP(doc, '_key', 'x_epss')}
)
FOR doc IN @@collection
FILTER doc._is_latest AND doc.type == 'vulnerability' AND doc.created >= @created_min AND doc.modified >= @modified_min 
RETURN MERGE(KEEP(doc, '_id', 'id', 'name', 'object_marking_refs', 'created_by_ref', 'external_references'), {epss: cve_epss_map[doc.name]})
        """
        return self.arango.execute_raw_query(query, bind_vars={'@collection': self.collection, 'created_min': self.created_min, 'modified_min': self.modified_min})
    
    def relate_single(self, object):
        todays_report = parse_cve_epss_report(object)
        if not todays_report:
            return []
        if object['epss']:
            all_epss = sorted(object['epss']['x_epss'] + todays_report['x_epss'], key=lambda x: x['date'])
            if len(set(map(lambda x: x['date'], all_epss))) != len(object['epss']['x_epss']):
                self.update_objects.append({
                    **object['epss'],
                    'x_epss': all_epss,
                    '_record_modified': datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    'modified': datetime.strptime(all_epss[0]["date"], "%Y-%m-%d").date().strftime("%Y-%m-%dT00:00:00.000Z"),
                    "_arango_cve_processor_note": self.relationship_note,
                })
            return []
        else:
            return [stix2dict(todays_report)]
    
    def upload_vertex_data(self, objects):
        logging.info("updating %d existing reports", len(self.update_objects))
        self.arango.execute_raw_query("""
        FOR obj IN @objects
        UPDATE obj IN @@collection
        """, bind_vars={"@collection": self.vertex_collection, "objects": self.update_objects})

        return super().upload_vertex_data(objects)

def parse_cve_epss_report(vulnerability: Vulnerability):
    try:
        cve_id = vulnerability.get('name')
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
            # id=vulnerability['id'].replace("vulnerability", "report"),
            created=modified,
            modified=modified,
            published=modified,
            name=content,
            x_epss=epss_data,
            object_refs=[
                vulnerability['id'],
            ],
            extensions= {
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d"
            ],
            created_by_ref="identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            external_references=vulnerability['external_references'][:1],
            labels=['epss'],

        )
    except:
        logging.error('get epss for %s failed', vulnerability.get('name'))
        return []