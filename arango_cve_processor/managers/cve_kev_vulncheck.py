import logging
import os
from typing import Any
from urllib.parse import urlparse
import uuid
import requests
from tqdm import tqdm

from arango_cve_processor import config
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.managers.cve_kev import CISAKevManager
from arango_cve_processor.tools.utils import make_stix_id


class VulnCheckKevManager(CISAKevManager, relationship_note="cve-vulncheck-kev"):
    DESCRIPTION = """
    Creates KEV report objects for CVEs, Source: Vulncheck
    """
    content_fmt = "Vulncheck KEV: {cve_id}"

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

    def get_additional_refs(self, kev_obj):
        for reported in kev_obj["vulncheck_reported_exploitation"]:
            ref = dict(
                url=reported["url"],
                description=f"Added on: {reported['date_added']}",
                source_name=urlparse(reported["url"]).hostname,
            )
            yield ref

    def get_dates(self, cve, kev_obj):
        return kev_obj["date_added"], kev_obj["_timestamp"]

    def parse_exploits(self, object, kev_obj):
        xdbs = kev_obj["vulncheck_xdb"]
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
