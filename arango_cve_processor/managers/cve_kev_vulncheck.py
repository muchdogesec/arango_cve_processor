import logging
import os
from typing import Any
from urllib.parse import urlparse
import uuid
import requests
from tqdm import tqdm

from arango_cve_processor import config
from arango_cve_processor.managers.base_manager import RelationType
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.managers.cve_kev import CISAKevManager
from arango_cve_processor.tools.utils import make_stix_id


class VulnCheckKevManager(CISAKevManager, relationship_note="cve-vulncheck-kev"):
    relation_type = RelationType.RELATE_SEQUENTIAL

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = requests.Session()
        self.session.headers = {"Authorization": os.environ.get("VULNCHECK_API_KEY")}
        self.verify_auth()

    def verify_auth(self):
        resp = self.session.get("https://api.vulncheck.com/v3/index")
        if resp.status_code != 200:
            raise ValueError(f"Bad API KEY for vulncheck: {resp.content}")

    def get_all_kevs(self):
        params = dict(limit=1500)
        if self.modified_min:
            params.update(lastModStartDate=self.modified_min[:10])
        if self.created_min:
            params.update(pubStartDate=self.created_min[:10])
        page = 1
        iterator = tqdm(total=1, desc="retrieve kev from vulncheck")
        while True:
            params.update(page=page)
            resp_data = self.session.get(
                "https://api.vulncheck.com/v3/index/vulncheck-kev", params=params
            ).json()
            meta = resp_data["_meta"]
            kev_map: dict[dict[str, Any]] = {}
            for entry in resp_data["data"]:
                cve_id = entry["cve"][0]
                kev_map[cve_id] = entry

            iterator.total = meta["total_documents"]
            iterator.update(len(kev_map))

            logging.info(
                "vulncheck endpoint returns %d known vulnerabilities", len(kev_map)
            )
            yield kev_map
            page += 1
            if meta["last_item"] >= meta["total_documents"]:
                break

    def retrieve_kevs(self):
        return self.kev_map

    def process(self, **kwargs):
        for kev_map in self.get_all_kevs():
            if not kev_map:
                continue
            self.kev_map = kev_map
            objects = self.get_objects()
            self.cwe_objects = self.get_all_cwes(objects)
            logging.info("got %d objects - %s", len(objects), self.relationship_note)

            self.do_process(objects)

    def get_all_cwes(self, objects):
        cwe_ids = []
        for obj in objects:
            cwe_ids.extend(self.kev_map[obj["name"]]["cwes"])
        cwe_objects = {}
        for k, v in (
            STIXObjectRetriever("ctibutler")
            .get_objects_by_external_ids(cwe_ids, "cwe", query_filter="cwe_id")
            .items()
        ):
            cwe_objects[k] = v[0]
        return cwe_objects

    def relate_single(self, object):
        cve_id = object["name"]
        kev_obj = self.kev_map[cve_id]
        kev_obj.setdefault("dueDate", "N/A")
        references = [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
            },
            {
                "source_name": "vulnerabilityName",
                "description": kev_obj["vulnerabilityName"],
            },
            {"source_name": "arango_cve_processor", "external_id": "cve-vulncheck-kev"},
            {
                "source_name": "known_ransomware",
                "description": kev_obj["knownRansomwareCampaignUse"],
            },
            {
                "source_name": "action_required",
                "description": kev_obj["required_action"],
            },
            {"source_name": "action_due", "description": kev_obj["dueDate"]},
        ]
        for reported in kev_obj["vulncheck_reported_exploitation"]:
            ref = dict(
                url=reported["url"],
                description=f"Added on: {reported['date_added']}",
                source_name=urlparse(reported["url"]).hostname,
            )
            references.append(ref)
        cwe_objects = [
            self.cwe_objects[cwe_id]
            for cwe_id in kev_obj["cwes"]
            if cwe_id in self.cwe_objects
        ]
        cwe_stix_ids = []
        for cwe in cwe_objects:
            cwe_stix_ids.append(cwe["id"])
            references.append(cwe["external_references"][0])

        exploit_objects = self.parse_exploits(object, kev_obj["vulncheck_xdb"])
        content = f"Vulncheck KEV: {cve_id}"
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": make_stix_id("report", content),
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "created": kev_obj["date_added"],
            "modified": kev_obj["_timestamp"],
            "published": kev_obj["date_added"],
            "name": content,
            "description": kev_obj["shortDescription"],
            "object_refs": [
                object["id"],
                *cwe_stix_ids,
                *[exploit["id"] for exploit in exploit_objects],
            ],
            "labels": ["kev"],
            "report_types": ["vulnerability"],
            "external_references": references,
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
        }
        return [report, *exploit_objects, *cwe_objects]

    def parse_exploits(self, object, xdbs: list[dict]):
        cve_id = object["name"]
        exploits = []
        for xdb in xdbs:
            exp = {
                "type": "exploit",
                "spec_version": "2.1",
                "id": "exploit--" + str(uuid.uuid5(config.namespace, xdb["xdb_id"])),
                "created_by_ref": "identity--e1db4e59-c7f9-5ec0-bd55-10004728a167",
                "created": xdb["date_added"],
                "modified": xdb["date_added"],
                "name": object["name"],
                "vulnerability_ref": object["id"],
                "exploit_type": xdb["exploit_type"],
                "proof_of_concept": xdb["clone_ssh_url"],
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": cve_id,
                        "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                    },
                    {
                        "source_name": "vulncheck_xdb",
                        "external_id": xdb["xdb_id"],
                        "url": xdb["xdb_url"],
                    },
                ],
                "object_marking_refs": [
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    "marking-definition--60c0f466-511a-5419-9f7e-4814e696da40",
                ],
                "extensions": {
                    "extension-definition--5a047f57-0149-59b6-a079-e2d7c7ac799a": {
                        "extension_type": "new-sdo"
                    }
                },
            }
            exploits.append(exp)
        return exploits
