import time
from unittest.mock import call, patch

import pytest
from arango_cve_processor.managers.cve_attack import CveAttack
from arango_cve_processor.managers.cve_capec import CveCapec
from arango_cve_processor.managers.cve_cwe import CveCwe
from arango_cve_processor.tools.retriever import STIXObjectRetriever


@pytest.fixture
def capec_processor(acp_processor, module_retriever):
    cwe_manager = CveCwe(
        acp_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    cwe_manager.process()
    time.sleep(1)
    yield acp_processor


def test_get_object_chunks(capec_processor):
    manager = CveCapec(
        capec_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    manager.CHUNK_SIZE = 2
    matches = list(manager.get_object_chunks())
    assert matches == [
        [
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.901482Z",
                "created": "2025-01-02T15:15:18.650Z",
                "id": "vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606",
                "modified": "2025-06-05T21:01:15.860Z",
                "name": "CVE-2022-45830",
                "external_references": [
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/665.html",
                        "external_id": "CAPEC-665",  # from CWE-862
                    }
                ],
            },
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
                "created": "2025-01-06T17:15:14.217Z",
                "id": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
                "modified": "2025-08-05T18:04:59.290Z",
                "name": "CVE-2023-6601",
                "external_references": [
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/242.html",
                        "external_id": "CAPEC-242",  # from CWE-94
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/35.html",
                        "external_id": "CAPEC-35",  # from CWE-94
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/77.html",
                        "external_id": "CAPEC-77",  # from CWE-94
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/10.html",
                        "external_id": "CAPEC-10",  # from CWE-99
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/240.html",
                        "external_id": "CAPEC-240",  # from CWE-99
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/75.html",
                        "external_id": "CAPEC-75",  # from CWE-99
                    },
                ],
            },
        ],
        [
            {
                "_id": "nvd_cve_vertex_collection/vulnerability--f503c132-140d-589f-ac60-6ae527fd2036+2025-09-12T11:25:56.462899Z",
                "created": "2025-01-08T03:15:10.190Z",
                "id": "vulnerability--f503c132-140d-589f-ac60-6ae527fd2036",
                "modified": "2025-01-13T21:42:30.453Z",
                "name": "CVE-2024-56447",
                "external_references": [
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/122.html",
                        "external_id": "CAPEC-122",
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/233.html",
                        "external_id": "CAPEC-233",
                    },
                    {
                        "source_name": "capec",
                        "url": "https://capec.mitre.org/data/definitions/58.html",
                        "external_id": "CAPEC-58",
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
            }
        ],
        [],
    ]


def test_do_process(capec_processor):
    manager = CveCapec(
        capec_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
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
            "attack-pattern--4317ab6c-93e4-4c5a-a814-0cd2752c61b9",  # CAPEC-665 <- CVE-2022-45830
            "attack-pattern--7f0f7de2-bf09-4f60-86bb-6933192b7128",  # CAPEC-242
            "attack-pattern--9a7c6cbc-e3f9-4925-992e-f07e1359de87",  # CAPEC-35
            "attack-pattern--5e4a268e-f89f-445a-aa42-395922f56bf0",  # CAPEC-77
            "attack-pattern--4a29d66d-8617-4382-b456-578ecdb1609e",  # CAPEC-10
            "attack-pattern--12de9227-495b-49b2-859f-334a20197ba3",  # CAPEC-240
            "attack-pattern--08c74bd3-c5ad-4d6c-a8bb-bb93d7503ddb",  # CAPEC-75
        }


def test_relate_single(capec_processor):
    manager = CveCapec(
        capec_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    manager.all_external_objects = STIXObjectRetriever().get_objects_by_external_ids(
        ["CAPEC-75", "CAPEC-35", "CAPEC-77"], "capec"
    )  # skip 3 capecs to simulate missing
    retval = manager.relate_single(
        {
            "_id": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
            "created": "2025-01-06T17:15:14.217Z",
            "id": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
            "modified": "2025-08-05T18:04:59.290Z",
            "name": "CVE-2023-6601",
            "external_references": [
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/242.html",
                    "external_id": "CAPEC-242",  # from CWE-94
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/35.html",
                    "external_id": "CAPEC-35",  # from CWE-94
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/77.html",
                    "external_id": "CAPEC-77",  # from CWE-94
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/10.html",
                    "external_id": "CAPEC-10",  # from CWE-99
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/240.html",
                    "external_id": "CAPEC-240",  # from CWE-99
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/75.html",
                    "external_id": "CAPEC-75",  # from CWE-99
                },
            ],
        }
    )
    assert retval == [
        {
            "spec_version": "2.1",
            "id": "relationship--65af2d7d-b15a-5c1c-9bca-7559a22e9f3b",
            "type": "relationship",
            "created": "2025-01-06T17:15:14.217Z",
            "modified": "2025-08-05T18:04:59.290Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
            "target_ref": "attack-pattern--9a7c6cbc-e3f9-4925-992e-f07e1359de87",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2023-6601 is exploited using CAPEC-35",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2023-6601",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6601",
                },
                {
                    "external_id": "CAPEC-35",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/35.html",
                },
            ],
            "_arango_cve_processor_note": "cve-capec",
            "_from": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
            "_is_ref": False,
        },
        {
            "spec_version": "2.1",
            "id": "relationship--2268f4e6-4835-5648-b695-c4fed221f91a",
            "type": "relationship",
            "created": "2025-01-06T17:15:14.217Z",
            "modified": "2025-08-05T18:04:59.290Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
            "target_ref": "attack-pattern--5e4a268e-f89f-445a-aa42-395922f56bf0",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2023-6601 is exploited using CAPEC-77",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2023-6601",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6601",
                },
                {
                    "external_id": "CAPEC-77",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/77.html",
                },
            ],
            "_arango_cve_processor_note": "cve-capec",
            "_from": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
            "_is_ref": False,
        },
        {
            "spec_version": "2.1",
            "id": "relationship--0b649c51-56bc-5970-9397-2b5f34bcde82",
            "type": "relationship",
            "created": "2025-01-06T17:15:14.217Z",
            "modified": "2025-08-05T18:04:59.290Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543",
            "target_ref": "attack-pattern--08c74bd3-c5ad-4d6c-a8bb-bb93d7503ddb",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2023-6601 is exploited using CAPEC-75",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2023-6601",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-6601",
                },
                {
                    "external_id": "CAPEC-75",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/75.html",
                },
            ],
            "_arango_cve_processor_note": "cve-capec",
            "_from": "nvd_cve_vertex_collection/vulnerability--01f30f82-30fd-5e43-a096-0ae15a29c543+2025-09-12T11:25:43.985959Z",
            "_is_ref": False,
        },
    ]
