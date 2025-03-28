import logging
from typing import Any
import uuid
import requests

from arango_cve_processor import config
from arango_cve_processor.tools.utils import stix2dict
from stix2 import Report
from .base_manager import STIXRelationManager, RelationType


class CveKevManager(STIXRelationManager, relationship_note="cve-kev"):
    relation_type = RelationType.RELATE_PARALLEL
    KEV_URLS = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/main/known_exploited_vulnerabilities.json",
    ]

    def get_objects(self, **kwargs):
        self.kev_map = self.retrieve_kevs()
        query = """
        FOR doc IN @@collection
        FILTER doc.type == 'vulnerability' AND doc._is_latest == TRUE AND doc.created >= @created_min AND doc.modified >= @modified_min 
                AND (NOT @cve_ids OR doc.name IN @cve_ids) // filter --cve_id
        RETURN KEEP(doc, '_id', 'id', 'name', 'created', 'modified')
        """
        cve_ids = set(self.cve_ids).intersection(self.kev_map) if self.cve_ids else self.kev_map
        return self.arango.execute_raw_query(
            query,
            bind_vars={
                "@collection": self.collection,
                "created_min": self.created_min,
                "modified_min": self.modified_min,
                'cve_ids': list(cve_ids),
            },
            batch_size=self.BATCH_SIZE,
        )

    def relate_multiple(self, objects):
        kev_map = self.kev_map
        retval = []
        for cve in objects:
            cve_id = cve["name"]
            cisa_obj: dict[str, Any] = kev_map.get(cve_id)
            if not cisa_obj:
                continue

            more_external_refs = [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                }
            ]

            for note in cisa_obj["notes"].split(" ; ")[:-1]:
                more_external_refs.append(dict(source_name="cisa_note", url=note))

            content = f"CISA KEV: {cve_id}"
            retval.append(
                stix2dict(
                    Report(
                        id="report--"+str(uuid.uuid5(config.namespace, content)),
                        type="report",
                        spec_version="2.1",
                        created=cve["created"],
                        modified=cve["modified"],
                        published=cve["created"],
                        name=content,
                        description=f"{cisa_obj['vulnerabilityName']}\n\n{cisa_obj['shortDescription']}\n\nRequired action: {cisa_obj['requiredAction']}\n\nAction due by: {cisa_obj['dueDate']}",
                        object_refs=[cve["id"]],
                        labels=["kev"],
                        external_references=more_external_refs,
                        object_marking_refs=config.OBJECT_MARKING_REFS,
                        created_by_ref=config.IDENTITY_REF,
                    )
                )
            )
        return retval

    def retrieve_kevs(self):
        for kev_url in self.KEV_URLS:
            try:
                resp = requests.get(
                    kev_url
                ).json()
                kev_map: dict[dict[str, Any]] = {}
                for vulnerability in resp["vulnerabilities"]:
                    kev_map[vulnerability["cveID"]] = vulnerability

                logging.info("CISA endpoint returns %d known vulnerabilities", len(kev_map))
                return kev_map
            except Exception as e:
                logging.error("failed to retrieve known exploited vulnerabilities from `%s`", kev_url)
        raise Exception("failed to retrieve known exploited vulnerabilities")
