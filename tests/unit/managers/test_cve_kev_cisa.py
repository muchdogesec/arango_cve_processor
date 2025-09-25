import pytest

from arango_cve_processor.managers.cve_kev import CISAKevManager
from collections import ChainMap


@pytest.fixture
def cisa_kev_manager(acp_processor):
    manager = CISAKevManager(acp_processor)
    yield manager


def test_relate_single(cisa_kev_manager, patched_retriever):
    cve_object = {
        "_id": "nvd_cve_vertex_collection/12753767",
        "created": "2025-06-02T18:15:25.010Z",
        "id": "vulnerability--43bad614-9f2f-5f84-9dfa-a68f5fa54ad4",
        "modified": "2025-09-12T13:40:47.133Z",
        "name": "CVE-2025-5086",
        "kev": {
            "cveID": "CVE-2025-5086",
            "vendorProject": "Dassault Systèmes",
            "product": "DELMIA Apriso",
            "vulnerabilityName": "Dassault Systèmes DELMIA Apriso Deserialization of Untrusted Data Vulnerability",
            "dateAdded": "2025-09-11",
            "shortDescription": "Dassault Systèmes DELMIA Apriso contains a deserialization of untrusted data vulnerability that could lead to a remote code execution.",
            "requiredAction": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
            "dueDate": "2025-10-02",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "https://www.3ds.com/trust-center/security/security-advisories/cve-2025-5086 ; https://nvd.nist.gov/vuln/detail/CVE-2025-5086",
            "cwes": ["CWE-502", "CWE-862", "CWE-276"],
        },
    }
    cisa_kev_manager.cwe_objects = cisa_kev_manager.get_all_cwes([cve_object])
    retval = cisa_kev_manager.relate_single(cve_object)
    assert retval == [
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--79b04f39-d572-5d4d-946e-b68e992c9a53",
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "created": "2025-06-02T18:15:25.010Z",
            "modified": "2025-09-12T13:40:47.133Z",
            "published": "2025-06-02T18:15:25.010Z",
            "name": "CISA KEV: CVE-2025-5086",
            "description": "Dassault Systèmes DELMIA Apriso contains a deserialization of untrusted data vulnerability that could lead to a remote code execution.",
            "object_refs": [
                "vulnerability--43bad614-9f2f-5f84-9dfa-a68f5fa54ad4",
                "weakness--e0f27140-5b49-51ea-aef0-0fed0dd082cf",
                "weakness--bfa2f40d-b5f0-505e-9ac5-92adfe0b6bd8",
            ],
            "labels": ["kev"],
            "report_types": ["vulnerability"],
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2025-5086",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5086",
                },
                {
                    "source_name": "vulnerability_name",
                    "description": "Dassault Systèmes DELMIA Apriso Deserialization of Untrusted Data Vulnerability",
                },
                {"source_name": "arango_cve_processor", "external_id": "cve-kev"},
                {"source_name": "known_ransomware", "description": "Unknown"},
                {
                    "source_name": "action_required",
                    "description": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
                },
                {"source_name": "action_due", "description": "2025-10-02"},
                {
                    "source_name": "cisa_note",
                    "url": "https://www.3ds.com/trust-center/security/security-advisories/cve-2025-5086",
                },
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/862.html",
                    "external_id": "CWE-862",
                },
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/276.html",
                    "external_id": "CWE-276",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
        },
        {
            "common_consequences": [
                "Confidentiality",
                "Integrity",
                "Access Control",
                "Availability",
            ],
            "created": "2011-05-24T00:00:00.000Z",
            "created_by_ref": "identity--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
            "description": "The product does not perform an authorization check when an actor attempts to access a resource or perform an action.",
            "detection_methods": [
                "Automated Static Analysis",
                "Automated Dynamic Analysis",
                "Manual Analysis",
                "Manual Static Analysis - Binary or Bytecode",
                "Dynamic Analysis with Automated Results Interpretation",
                "Dynamic Analysis with Manual Results Interpretation",
                "Manual Static Analysis - Source Code",
                "Automated Static Analysis - Source Code",
                "Architecture or Design Review",
            ],
            "extensions": {
                "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
                    "extension_type": "new-sdo"
                }
            },
            "external_references": [
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/862.html",
                    "external_id": "CWE-862",
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/665.html",
                    "external_id": "CAPEC-665",
                },
            ],
            "id": "weakness--e0f27140-5b49-51ea-aef0-0fed0dd082cf",
            "likelihood_of_exploit": ["High"],
            "modes_of_introduction": [
                "Architecture and Design",
                "Implementation",
                "Operation",
            ],
            "modified": "2024-11-19T00:00:00.000Z",
            "name": "Missing Authorization",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
            ],
            "spec_version": "2.1",
            "type": "weakness",
        },
        {
            "common_consequences": ["Confidentiality", "Integrity"],
            "created": "2006-07-19T00:00:00.000Z",
            "created_by_ref": "identity--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
            "description": "During installation, installed file permissions are set to allow anyone to modify those files.",
            "detection_methods": [
                "Automated Static Analysis - Binary or Bytecode",
                "Manual Static Analysis - Binary or Bytecode",
                "Dynamic Analysis with Automated Results Interpretation",
                "Dynamic Analysis with Manual Results Interpretation",
                "Manual Static Analysis - Source Code",
                "Automated Static Analysis - Source Code",
                "Automated Static Analysis",
                "Architecture or Design Review",
            ],
            "extensions": {
                "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
                    "extension_type": "new-sdo"
                }
            },
            "external_references": [
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/276.html",
                    "external_id": "CWE-276",
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/1.html",
                    "external_id": "CAPEC-1",
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/127.html",
                    "external_id": "CAPEC-127",
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/81.html",
                    "external_id": "CAPEC-81",
                },
            ],
            "id": "weakness--bfa2f40d-b5f0-505e-9ac5-92adfe0b6bd8",
            "likelihood_of_exploit": ["Medium"],
            "modes_of_introduction": [
                "Architecture and Design",
                "Implementation",
                "Installation",
                "Operation",
            ],
            "modified": "2023-06-29T00:00:00.000Z",
            "name": "Incorrect Default Permissions",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
            ],
            "spec_version": "2.1",
            "type": "weakness",
        },
    ]


def test_run_all(cisa_kev_manager):
    cisa_kev_manager.process()
    query = "FOR d IN nvd_cve_vertex_collection RETURN [d.id, d.x_opencti_cisa_kev]"
    cves_has_kev_map = dict(cisa_kev_manager.arango.execute_raw_query(query))
    vulns_with_kev = {k for k, has_kev in cves_has_kev_map.items() if has_kev}
    vulns_with_no_kev = set(cves_has_kev_map).difference(vulns_with_kev)
    query2 = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d.type == "report"
    RETURN d.object_refs[0]
    """
    report_vuln_ids = set(cisa_kev_manager.arango.execute_raw_query(query2))
    assert report_vuln_ids == vulns_with_kev
    assert vulns_with_no_kev, 'there must be at least 1 vuln with no kev'
    assert vulns_with_kev, 'there must be at least 1 vuln with kev'
