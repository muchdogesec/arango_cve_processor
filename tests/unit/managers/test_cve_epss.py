from datetime import date
from arango_cve_processor.managers.cve_epss import (
    CveEpssManager,
    _CveEpssWorker,
)
from tests.unit.utils import remove_volatile_keys


def process(acp_processor, start_date, end_date):
    manager = CveEpssManager(acp_processor, start_date=start_date, end_date=end_date)
    manager.process()


def test_epss_backfill(acp_processor):
    process(acp_processor, start_date=date(2025, 1, 5), end_date=date(2025, 1, 6))
    process(acp_processor, start_date=date(2025, 1, 3), end_date=date(2025, 1, 3))
    process(acp_processor, start_date=date(2025, 2, 15), end_date=date(2025, 2, 17))
    query = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d.type == "report"
    SORT d.created ASC
    RETURN d
    """
    retval = remove_volatile_keys(
        acp_processor.execute_raw_query(query), extra_keys=["_key", "_id"]
    )
    print(retval)
    assert retval == [
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--bc62edca-1d49-5cd1-9387-a49168fba4ae",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-01-02T15:15:18.650Z",
            "modified": "2025-02-17T00:00:00.000Z",
            "name": "EPSS Scores: CVE-2022-45830",
            "published": "2025-01-02T15:15:18.65Z",
            "object_refs": ["vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606"],
            "labels": ["epss"],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                    "external_id": "CVE-2022-45830",
                },
                {"source_name": "arango_cve_processor", "external_id": "cve-epss"},
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "extensions": {
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "x_epss": [
                {"date": "2025-02-17", "epss": 0.00043, "percentile": 0.11665},
                {"date": "2025-02-16", "epss": 0.00043, "percentile": 0.1166},
                {"date": "2025-02-15", "epss": 0.00043, "percentile": 0.1166},
                {"date": "2025-01-06", "epss": 0.00043, "percentile": 0.11007},
                {"date": "2025-01-05", "epss": 0.00043, "percentile": 0.11005},
                {"date": "2025-01-03", "epss": 0.00043, "percentile": 0.11013},
            ],
            "_arango_cve_processor_note": "cve-epss",
            "_record_md5_hash": "dd9295679421ae55cd4ab7a20532a509",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--af588801-5892-5917-b389-e6cc21b1bea6",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-01-06T17:15:14.217Z",
            "modified": "2025-02-17T00:00:00.000Z",
            "name": "EPSS Scores: CVE-2023-6601",
            "published": "2025-01-06T17:15:14.217Z",
            "object_refs": ["vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543"],
            "labels": ["epss"],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6601",
                    "external_id": "CVE-2023-6601",
                },
                {"source_name": "arango_cve_processor", "external_id": "cve-epss"},
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "extensions": {
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "x_epss": [
                {"date": "2025-02-17", "epss": 0.00043, "percentile": 0.11665},
                {"date": "2025-02-16", "epss": 0.00043, "percentile": 0.1166},
                {"date": "2025-02-15", "epss": 0.00043, "percentile": 0.1166},
            ],
            "_arango_cve_processor_note": "cve-epss",
            "_record_md5_hash": "f25e43d30c9d44a2e73a698d12dc015d",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--65ee976d-e65d-566a-b027-3afe0895ed74",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-01-08T03:15:10.190Z",
            "modified": "2025-02-17T00:00:00.000Z",
            "name": "EPSS Scores: CVE-2024-56447",
            "published": "2025-01-08T03:15:10.19Z",
            "object_refs": ["vulnerability--f503c132-140d-589f-ac60-6ae527fd2036"],
            "labels": ["epss"],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-56447",
                    "external_id": "CVE-2024-56447",
                },
                {"source_name": "arango_cve_processor", "external_id": "cve-epss"},
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "extensions": {
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "x_epss": [
                {"date": "2025-02-17", "epss": 0.00087, "percentile": 0.39353},
                {"date": "2025-02-16", "epss": 0.00087, "percentile": 0.3935},
                {"date": "2025-02-15", "epss": 0.00087, "percentile": 0.3935},
            ],
            "_arango_cve_processor_note": "cve-epss",
            "_record_md5_hash": "19c7516d89633f14acb35319480dcd3c",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
        {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--6cfb9545-0f59-577d-a04e-5ab3e4523574",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2025-01-09T07:15:27.203Z",
            "modified": "2025-02-17T00:00:00.000Z",
            "name": "EPSS Scores: CVE-2024-53704",
            "published": "2025-01-09T07:15:27.203Z",
            "object_refs": ["vulnerability--e1c66db1-3846-5f2c-91ea-4abadaa95a85"],
            "labels": ["epss"],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-53704",
                    "external_id": "CVE-2024-53704",
                },
                {"source_name": "arango_cve_processor", "external_id": "cve-epss"},
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "extensions": {
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "x_epss": [
                {"date": "2025-02-17", "epss": 0.00054, "percentile": 0.25386},
                {"date": "2025-02-16", "epss": 0.00054, "percentile": 0.25386},
                {"date": "2025-02-15", "epss": 0.00054, "percentile": 0.25395},
            ],
            "_arango_cve_processor_note": "cve-epss",
            "_record_md5_hash": "daf44f8b6498071b6c6cd7d213fbecd8",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
    ]

    query = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d.type == "vulnerability" AND d.id IN @vuln_refs
    RETURN [d.name, [d.x_opencti_epss_date, d.x_opencti_epss_score, d.x_opencti_epss_percentile]]
    """
    epss = dict(
        acp_processor.execute_raw_query(
            query, bind_vars=dict(vuln_refs=[obj["object_refs"][0] for obj in retval])
        )
    )
    assert epss == {
        "CVE-2024-56447": ["2025-02-17", 0.00087, 0.39353],
        "CVE-2023-6601": ["2025-02-17", 0.00043, 0.11665],
        "CVE-2022-45830": ["2025-02-17", 0.00043, 0.11665],
        "CVE-2024-53704": ["2025-02-17", 0.00054, 0.25386],
    }
