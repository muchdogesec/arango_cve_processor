import logging
from typing import Any
import uuid
import requests

from arango_cve_processor import config
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.tools.utils import make_stix_id, stix2python
from stix2 import Report
from arango_cve_processor.managers.base_manager import STIXRelationManager


class CISAKevManager(STIXRelationManager, relationship_note="cve-kev"):
    DESCRIPTION = """
    Creates KEV report objects for CVEs, Source: CISA
    """
    KEV_URLS = [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/main/known_exploited_vulnerabilities.json",
    ]
    content_fmt = "CISA KEV: {cve_id}"

    def get_cve_for_kevs(self, kev_map):
        query = """
        FOR doc IN @@collection OPTIONS {indexHint: "acvep_search_v2", forceIndexHint: true}
        FILTER doc.type == 'vulnerability' AND doc._is_latest == TRUE
                AND (NOT @cve_ids OR doc.name IN @cve_ids) // filter --cve_id
        RETURN KEEP(doc, '_id', 'id', 'name', 'created', 'modified', '_key')
        """
        cve_ids = list(
            set(self.cve_ids).intersection(kev_map)
            if self.cve_ids
            else kev_map
        )
        retval = []
        for obj in self.arango.execute_raw_query(
            query,
            bind_vars={
                "@collection": self.collection,
                "cve_ids": cve_ids,
            },
            batch_size=self.BATCH_SIZE,
        ):
            obj.update(kev=kev_map[obj['name']])
            retval.append(obj)
        return retval

    def get_all_cwes(self, objects):
        cwe_ids = []
        for obj in objects:
            cwe_ids.extend(obj['kev']["cwes"])
        cwe_objects = STIXObjectRetriever().get_objects_by_external_ids(
            cwe_ids, "cwe", query_filter="cwe_id"
        )
        return cwe_objects

    def get_object_chunks(self):
        for kev_map in self.get_all_kevs():
            if not kev_map:
                continue
            objects = self.get_cve_for_kevs(kev_map)
            self.cwe_objects = self.get_all_cwes(objects)
            yield objects

    def parse_exploits(self, cve, kev):
        return []

    def get_additional_refs(self, kev_obj):
        for note in kev_obj["notes"].split(" ; ")[:-1]:
            yield dict(source_name="cisa_note", url=note)

    def get_dates(self, cve):
        date_added = cve['kev']["dateAdded"] + 'T00:00:00Z'
        return date_added, date_added

    def relate_single(self, vuln_obj):
        cve_id = vuln_obj["name"]
        kev_obj = vuln_obj['kev']
        references = [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            },
            {
                "source_name": "vulnerability_name",
                "description": kev_obj["vulnerabilityName"],
            },
            {
                "source_name": "arango_cve_processor",
                "external_id": self.relationship_note,
            },
            {
                "source_name": "known_ransomware",
                "description": kev_obj["knownRansomwareCampaignUse"],
            },
            {
                "source_name": "action_required",
                "description": kev_obj.get("required_action")
                or kev_obj.get("requiredAction"),
            },
        ]
        if dueDate := kev_obj.get("dueDate"):
            references.append({"source_name": "action_due", "description": dueDate})

        references.extend(self.get_additional_refs(kev_obj))
        cwe_objects = [
            self.cwe_objects[cwe_id]
            for cwe_id in kev_obj["cwes"]
            if cwe_id in self.cwe_objects
        ]
        cwe_stix_ids = []
        for cwe in cwe_objects:
            cwe_stix_ids.append(cwe["id"])
            references.append(cwe["external_references"][0])

        exploit_objects = self.parse_exploits(vuln_obj, kev_obj)
        content = self.content_fmt.format(cve_id=cve_id)
        created, modified = self.get_dates(vuln_obj)
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": make_stix_id("report", content),
            "created_by_ref": config.IDENTITY_REF,
            "created": created,
            "modified": modified,
            "published": created,
            "name": content,
            "description": kev_obj["shortDescription"],
            "object_refs": [
                vuln_obj["id"],
                *cwe_stix_ids,
                *[exploit["id"] for exploit in exploit_objects],
            ],
            "labels": ["kev"],
            "report_types": ["vulnerability"],
            "external_references": references,
            "object_marking_refs": config.OBJECT_MARKING_REFS,
        }
        self.update_objects.append(dict(_key=vuln_obj['_key'], x_opencti_cisa_kev=True))
        return [report, *exploit_objects, *cwe_objects]

    def get_all_kevs(self):
        for kev_url in self.KEV_URLS:
            try:
                resp = requests.get(kev_url)
                resp.raise_for_status()
                resp_data = resp.json()
                kev_map: dict[dict[str, Any]] = {}
                for vulnerability in resp_data["vulnerabilities"]:
                    kev_map[vulnerability["cveID"]] = vulnerability

                logging.info(
                    "CISA endpoint returns %d known vulnerabilities", len(kev_map)
                )
                return [kev_map]
            except Exception as e:
                logging.error(
                    "failed to retrieve known exploited vulnerabilities from `%s`",
                    kev_url,
                )
        raise Exception("failed to retrieve known exploited vulnerabilities")
