from unittest.mock import patch
from arango_cve_processor.managers.cve_cwe import CveCwe
from arango_cve_processor.tools.retriever import STIXObjectRetriever


def test_get_object_chunks(acp_processor):
    manager = CveCwe(acp_processor, created_min="1970-01-01", modified_min="1970-01-01")
    manager.CHUNK_SIZE = 2
    matches = list(manager.get_object_chunks())
    assert matches == [
        [
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.901482Z",
                "created": "2025-01-02T15:15:18.650Z",
                "external_references": [
                    {
                        "source_name": "cve",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                        "external_id": "CVE-2022-45830",
                    },
                    {
                        "source_name": "cwe",
                        "url": "https://cwe.mitre.org/data/definitions/CWE-862.html",
                        "external_id": "CWE-862",
                    },
                    {
                        "source_name": "audit@patchstack.com",
                        "description": "Third Party Advisory",
                        "url": "https://patchstack.com/database/wordpress/plugin/wp-analytify/vulnerability/wordpress-analytify-google-analytics-dashboard-plugin-4-2-3-privilege-escalation?_s_id=cve",
                    },
                    {"source_name": "vulnStatus", "description": "Analyzed"},
                    {
                        "source_name": "sourceIdentifier",
                        "description": "audit@patchstack.com",
                    },
                ],
                "id": "vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606",
                "modified": "2025-06-05T21:01:15.860Z",
                "name": "CVE-2022-45830",
            },
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
                "created": "2025-01-06T17:15:14.217Z",
                "external_references": [
                    {
                        "source_name": "cve",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6601",
                        "external_id": "CVE-2023-6601",
                    },
                    {
                        "source_name": "cwe",
                        "url": "https://cwe.mitre.org/data/definitions/CWE-99.html",
                        "external_id": "CWE-99",
                    },
                    {
                        "source_name": "cwe",
                        "url": "https://cwe.mitre.org/data/definitions/CWE-94.html",
                        "external_id": "CWE-94",
                    },
                    {
                        "source_name": "patrick@puiterwijk.org",
                        "description": "Exploit,Issue Tracking",
                        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=2253172",
                    },
                    {"source_name": "vulnStatus", "description": "Analyzed"},
                    {
                        "source_name": "sourceIdentifier",
                        "description": "patrick@puiterwijk.org",
                    },
                ],
                "id": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
                "modified": "2025-08-05T18:04:59.290Z",
                "name": "CVE-2023-6601",
            },
        ],
        [
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--f503c132-140d-589f-ac60-6ae527fd2036+2025-09-12T11:25:56.462899Z",
                "created": "2025-01-08T03:15:10.190Z",
                "external_references": [
                    {
                        "source_name": "cve",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-56447",
                        "external_id": "CVE-2024-56447",
                    },
                    {
                        "source_name": "cwe",
                        "url": "https://cwe.mitre.org/data/definitions/CWE-269.html",
                        "external_id": "CWE-269",
                    },
                    {
                        "source_name": "cwe",
                        "url": "https://cwe.mitre.org/data/definitions/CWE-276.html",
                        "external_id": "CWE-276",
                    },
                    {
                        "source_name": "psirt@huawei.com",
                        "description": "Vendor Advisory",
                        "url": "https://consumer.huawei.com/en/support/bulletin/2025/1/",
                    },
                    {"source_name": "vulnStatus", "description": "Analyzed"},
                    {
                        "source_name": "sourceIdentifier",
                        "description": "psirt@huawei.com",
                    },
                ],
                "id": "vulnerability--f503c132-140d-589f-ac60-6ae527fd2036",
                "modified": "2025-01-13T21:42:30.453Z",
                "name": "CVE-2024-56447",
            }
        ],
    ]


def test_do_process(acp_processor, patched_retriever):
    manager = CveCwe(acp_processor, created_min="1970-01-01", modified_min="1970-01-01")
    manager.CHUNK_SIZE = 2  # only use first two
    objects = list(manager.get_object_chunks())[0]

    with patch(
        "arango_cve_processor.managers.cve_cwe.STIXRelationManager.do_process"
    ) as mock_super_do_process:
        manager.do_process(objects)

        mock_super_do_process.assert_called_once()
        assert mock_super_do_process.call_args[0][0] == objects
        assert {
            obj["id"] for obj in mock_super_do_process.call_args[1]["extra_uploads"]
        } == {
            "weakness--c80522e0-a937-5dcb-846a-d5aefc1dc552",
            "weakness--bd696f33-1ee8-59eb-9d30-3bdee9553805",
            "weakness--e0f27140-5b49-51ea-aef0-0fed0dd082cf",
        }


def test_relate_single(acp_processor, patched_retriever):
    manager = CveCwe(acp_processor, created_min="1970-01-01", modified_min="1970-01-01")
    manager.all_external_objects = STIXObjectRetriever().get_objects_by_external_ids(
        ["CWE-269", "CWE-276", "CWE-99"], "cwe"
    )
    retval = manager.relate_single(
        {
            "_id": "nvd_cve_vertex_collection/vulnerability--f503c132-140d-589f-ac60-6ae527fd2036+2025-09-12T11:25:56.462899Z",
            "created": "2025-01-08T03:15:10.190Z",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-56447",
                    "external_id": "CVE-2024-56447",
                },
                {
                    "source_name": "cwe",
                    "url": "https://cwe.mitre.org/data/definitions/CWE-269.html",
                    "external_id": "CWE-269",
                },
                {
                    "source_name": "cwe",
                    "url": "https://cwe.mitre.org/data/definitions/CWE-276.html",
                    "external_id": "CWE-276",
                },
                {
                    "source_name": "psirt@huawei.com",
                    "description": "Vendor Advisory",
                    "url": "https://consumer.huawei.com/en/support/bulletin/2025/1/",
                },
                {"source_name": "vulnStatus", "description": "Analyzed"},
                {
                    "source_name": "sourceIdentifier",
                    "description": "psirt@huawei.com",
                },
            ],
            "id": "vulnerability--f503c132-140d-589f-ac60-6ae527fd2036",
            "modified": "2025-01-13T21:42:30.453Z",
            "name": "CVE-2024-56447",
        }
    )
    assert retval == [
        {
            "spec_version": "2.1",
            "id": "relationship--0cff6b43-dbc2-5901-af73-eda08d55ca56",
            "type": "relationship",
            "created": "2025-01-08T03:15:10.190Z",
            "modified": "2025-01-13T21:42:30.453Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--f503c132-140d-589f-ac60-6ae527fd2036",
            "target_ref": "weakness--eb90af25-bcf1-5a0e-a162-a149ed58712a",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2024-56447 is exploited using CWE-269",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2024-56447",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-56447",
                },
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/269.html",
                    "external_id": "CWE-269",
                },
            ],
            "_arango_cve_processor_note": "cve-cwe",
            "_from": "nvd_cve_vertex_collection/vulnerability--f503c132-140d-589f-ac60-6ae527fd2036+2025-09-12T11:25:56.462899Z",
            "_is_ref": False,
        },
        {
            "spec_version": "2.1",
            "id": "relationship--148d44b1-3820-511b-bb88-cd23de2f4906",
            "type": "relationship",
            "created": "2025-01-08T03:15:10.190Z",
            "modified": "2025-01-13T21:42:30.453Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--f503c132-140d-589f-ac60-6ae527fd2036",
            "target_ref": "weakness--bfa2f40d-b5f0-505e-9ac5-92adfe0b6bd8",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2024-56447 is exploited using CWE-276",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2024-56447",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-56447",
                },
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/276.html",
                    "external_id": "CWE-276",
                },
            ],
            "_arango_cve_processor_note": "cve-cwe",
            "_from": "nvd_cve_vertex_collection/vulnerability--f503c132-140d-589f-ac60-6ae527fd2036+2025-09-12T11:25:56.462899Z",
            "_is_ref": False,
        },
    ]
