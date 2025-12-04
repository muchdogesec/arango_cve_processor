import pytest

from arango_cve_processor.managers.cve_kev_vulncheck import VulnCheckKevManager
from collections import ChainMap


@pytest.fixture
def vulncheck_kev_manager(acp_processor):
    manager = VulnCheckKevManager(acp_processor)
    yield manager


def test_get_all_kevs(vulncheck_kev_manager):
    kevs = ChainMap(*vulncheck_kev_manager.get_all_kevs())
    assert "CVE-2025-5086" in kevs


def test_relate_single(vulncheck_kev_manager, patched_retriever):
    cve_object = {
        "_id": "nvd_cve_vertex_collection/vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85+2025-09-04T15:28:55.109187Z",
        "_key": "vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85+2025-09-04T15:28:55.109187Z",
        "created": "2025-01-09T07:15:27.203Z",
        "id": "vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85",
        "modified": "2025-02-19T15:33:49.643Z",
        "name": "CVE-2024-53704",
        "kev": {
            "vendorProject": "SonicWall",
            "product": "SonicOS",
            "shortDescription": "SonicWall SonicOS contains an improper authentication vulnerability in the SSLVPN authentication mechanism that allows a remote attacker to bypass authentication.",
            "vulnerabilityName": "SonicWall SonicOS SSLVPN Improper Authentication Vulnerability",
            "required_action": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
            "knownRansomwareCampaignUse": "Unknown",
            "cve": ["CVE-2024-53704"],
            "cwes": ["CWE-287", "CWE-94"],
            "vulncheck_xdb": [
                {
                    "xdb_id": "364cc4eceb03",
                    "xdb_url": "https://vulncheck.com/xdb/364cc4eceb03",
                    "date_added": "2025-02-11T20:43:23Z",
                    "exploit_type": "initial-access",
                    "clone_ssh_url": "git@github.com:istagmbh/CVE-2024-53704.git",
                }
            ],
            "vulncheck_reported_exploitation": [
                {
                    "url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2025-11-29&host_type=src&vulnerability=cve-2024-53704",
                    "date_added": "2025-11-29T00:00:00Z",
                },
                {
                    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    "date_added": "2025-02-18T00:00:00Z",
                },
                {
                    "url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2025-02-24&host_type=src&vulnerability=cve-2024-53704",
                    "date_added": "2025-02-24T00:00:00Z",
                },
            ],
            "dueDate": "2025-03-11T00:00:00Z",
            "cisa_date_added": "2025-02-18T00:00:00Z",
            "date_added": "2025-02-13T00:00:00Z",
            "_timestamp": "2025-09-16T10:25:34.044567372Z",
        },
    }
    vulncheck_kev_manager.cwe_objects = vulncheck_kev_manager.get_all_cwes([cve_object])
    retval = vulncheck_kev_manager.relate_single(cve_object)
    assert [obj for obj in retval if obj["type"] != "weakness"] == [
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--06439778-3439-5f81-b549-8df65fbf5abd",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-02-13T00:00:00Z",
            "modified": "2025-09-16T10:25:34.044567372Z",
            "published": "2025-02-13T00:00:00Z",
            "name": "Vulncheck KEV: CVE-2024-53704",
            "description": "SonicWall SonicOS contains an improper authentication vulnerability in the SSLVPN authentication mechanism that allows a remote attacker to bypass authentication.",
            "object_refs": [
                "vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85",
                "weakness--bd696f33-1ee8-59eb-9d30-3bdee9553805",
                "exploit--e8476b83-2154-5db3-8380-a4fced6061e2",
            ],
            "labels": ["kev"],
            "report_types": ["vulnerability"],
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2024-53704",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-53704",
                },
                {
                    "source_name": "vulnerability_name",
                    "description": "SonicWall SonicOS SSLVPN Improper Authentication Vulnerability",
                },
                {
                    "source_name": "arango_cve_processor",
                    "external_id": "cve-vulncheck-kev",
                },
                {"source_name": "known_ransomware", "description": "Unknown"},
                {
                    "source_name": "action_required",
                    "description": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
                },
                {"source_name": "action_due", "description": "2025-03-11T00:00:00Z"},
                {
                    "url": "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?host_type=src&vulnerability=cve-2024-53704",
                    "description": "Added on: 2025-11-29T00:00:00Z",
                    "source_name": "dashboard.shadowserver.org",
                },
                {
                    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    "description": "Added on: 2025-02-18T00:00:00Z",
                    "source_name": "www.cisa.gov",
                },
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/94.html",
                    "external_id": "CWE-94",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
        },
        {
            "type": "exploit",
            "spec_version": "2.1",
            "id": "exploit--e8476b83-2154-5db3-8380-a4fced6061e2",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-02-11T20:43:23Z",
            "modified": "2025-02-11T20:43:23Z",
            "name": "CVE-2024-53704",
            "vulnerability_ref": "vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85",
            "exploit_type": "initial-access",
            "proof_of_concept": "git@github.com:istagmbh/CVE-2024-53704.git",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2024-53704",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-53704",
                },
                {
                    "source_name": "vulncheck_xdb",
                    "external_id": "364cc4eceb03",
                    "url": "https://vulncheck.com/xdb/364cc4eceb03",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "extensions": {
                "extension-definition--5a047f57-0149-59b6-a079-e2d7c7ac799a": {
                    "extension_type": "new-sdo"
                }
            },
        },
    ]


def test_run_all(vulncheck_kev_manager):
    vulncheck_kev_manager.process()
    query = "FOR d IN nvd_cve_vertex_collection RETURN [d.id, d.x_opencti_cisa_kev]"
    cves_has_kev_map = dict(vulncheck_kev_manager.arango.execute_raw_query(query))
    vulns_with_kev = {k for k, has_kev in cves_has_kev_map.items() if has_kev}
    vulns_with_no_kev = set(cves_has_kev_map).difference(vulns_with_kev)
    query2 = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d.type == "report"
    RETURN d.object_refs[0]
    """
    report_vuln_ids = set(vulncheck_kev_manager.arango.execute_raw_query(query2))
    assert report_vuln_ids == vulns_with_kev
    assert vulns_with_no_kev, "there must be at least 1 vuln with no kev"
    assert vulns_with_kev, "there must be at least 1 vuln with kev"
