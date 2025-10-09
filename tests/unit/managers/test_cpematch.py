import pytest
import time
from unittest.mock import call, patch, MagicMock
from arango_cve_processor.managers.cpe_match import (
    CpeMatchUpdateManager,
)
import requests

from datetime import UTC, datetime, timedelta, timezone


@pytest.fixture
def cpematch_manager(acp_processor, mocked_updates):
    manager = CpeMatchUpdateManager(
        acp_processor, updated_after="2025-01-01T00:00:00.000Z"
    )
    manager.updated_before = "2025-01-03T21:05:57.937Z"

    manager.groupings = mocked_updates
    return manager


@pytest.mark.parametrize(
    ["criteria_ids", "expected_indicators"],
    [
        pytest.param(
            [
                "A974CA73-84E8-480B-BB4C-4A81D0C985B2",
                "DE670466-3267-48D2-A826-99B23F7FBD12",
            ],
            [
                "indicator--01f30f82-30fd-5e43-a096-0ae15a29c543",
                "indicator--f503c132-140d-589f-ac60-6ae527fd2036",
            ],
            id="both vulnerable",
        ),
        pytest.param(
            [
                "DE670466-3267-48D2-A826-99B23F7FBD12",
            ],
            [
                "indicator--01f30f82-30fd-5e43-a096-0ae15a29c543",
            ],
            id="vulnerable",
        ),
        pytest.param(
            [
                "2401DE15-9DBF-4645-A261-8C24D57C6342",
            ],
            [
                "indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            ],
            id="not vulnerable",
        ),
        pytest.param(
            [
                "2401DE15-9DBF-4645-A261-8C24D57C6342",
                "DE670466-3267-48D2-A826-99B23F7FBD12",
            ],
            [
                "indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606",
                "indicator--01f30f82-30fd-5e43-a096-0ae15a29c543",
            ],
            id="not_vulnerable+vulnerable",
        ),
    ],
)
def test_get_single_chunk(cpematch_manager, criteria_ids, expected_indicators):
    chunk1 = cpematch_manager.get_single_chunk(criteria_ids)
    print(chunk1)
    assert [x["id"] for x in chunk1] == expected_indicators


def test_relate_single(cpematch_manager):
    indicator = {
        "_id": "nvd_cve_vertex_collection/indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.563706Z",
        "created": "2025-01-02T15:15:18.650Z",
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                "external_id": "CVE-2022-45830",
            }
        ],
        "id": "indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606",
        "modified": "2025-06-05T21:01:15.860Z",
        "name": "CVE-2022-45830",
        "x_cpes": {
            "not_vulnerable": [
                {
                    "criteria": "cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*",
                    "matchCriteriaId": "8198CDB2-4BC5-411A-8736-615A531FC545",
                },
                {
                    "criteria": "cpe:2.3:o:huawei:harmonyos:4.2.0:*:*:*:*:*:*:*",
                    "matchCriteriaId": "2401DE15-9DBF-4645-A261-8C24D57C6342",
                },
            ],
            "vulnerable": [
                {
                    "criteria": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:*:*:*:*:*:wordpress:*:*",
                    "matchCriteriaId": "9664F6D2-4EE2-4326-9A93-5F8328FF65EC",
                }
            ],
        },
    }
    objects: list = cpematch_manager.relate_single(indicator)
    for obj in objects.copy():
        if obj["type"] == "relationship" and obj["source_ref"].startswith("software"):
            objects.remove(obj)

    relationships = [obj for obj in objects if obj["type"] == "relationship"]
    assert relationships == [
        {
            "spec_version": "2.1",
            "id": "relationship--f777aa6c-c618-5d7f-be39-5dc326ed642b",
            "type": "relationship",
            "created": "2025-01-02T15:15:18.650Z",
            "modified": "2025-06-05T21:01:15.860Z",
            "relationship_type": "x-cpes-not-vulnerable",
            "source_ref": "indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            "target_ref": "grouping--aea1190d-db1d-5e2a-a1ad-6119bf0e0f41",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "8198CDB2-4BC5-411A-8736-615A531FC545 (cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*) is not vulnerable to CVE-2022-45830",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                    "external_id": "CVE-2022-45830",
                },
                {
                    "source_name": "matchCriteriaId",
                    "external_id": "8198CDB2-4BC5-411A-8736-615A531FC545",
                },
                {
                    "source_name": "matchstring",
                    "external_id": "cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*",
                },
            ],
            "_from": "nvd_cve_vertex_collection/indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.563706Z",
        },
        {
            "spec_version": "2.1",
            "id": "relationship--1bd65338-ad37-54b0-a033-a64780944062",
            "type": "relationship",
            "created": "2025-01-02T15:15:18.650Z",
            "modified": "2025-06-05T21:01:15.860Z",
            "relationship_type": "x-cpes-vulnerable",
            "source_ref": "indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            "target_ref": "grouping--bda5cd3d-0b85-5428-9e11-04c75a1d236a",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "9664F6D2-4EE2-4326-9A93-5F8328FF65EC (cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:*:*:*:*:*:wordpress:*:*) is vulnerable to CVE-2022-45830",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                    "external_id": "CVE-2022-45830",
                },
                {
                    "source_name": "matchCriteriaId",
                    "external_id": "9664F6D2-4EE2-4326-9A93-5F8328FF65EC",
                },
                {
                    "source_name": "matchstring",
                    "external_id": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:*:*:*:*:*:wordpress:*:*",
                },
            ],
            "_from": "nvd_cve_vertex_collection/indicator--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.563706Z",
        },
    ]
    assert {obj["id"] for obj in objects} == {
        "software--af14673c-cb01-5062-aab8-99ece177b757",
        "grouping--aea1190d-db1d-5e2a-a1ad-6119bf0e0f41",
        "software--7535020a-ef27-52c8-96b8-f6dc3e46a5ec",
        "software--38cbef71-8e67-5bb8-a79f-8a5f333f01ec",
        "relationship--f777aa6c-c618-5d7f-be39-5dc326ed642b",
        "software--4f152dca-e486-5432-90bb-d73eaaa4b986",
        "relationship--1bd65338-ad37-54b0-a033-a64780944062",
        "grouping--bda5cd3d-0b85-5428-9e11-04c75a1d236a",
    }


@pytest.fixture
def mocked_updates():
    c1 = {
        "matchCriteriaId": "8198CDB2-4BC5-411A-8736-615A531FC545",
        "criteria": "cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*",
        "lastModified": "2023-09-25T16:05:08.087",
        "cpeLastModified": "2023-09-25T16:05:08.087",
        "created": "2023-09-25T12:51:26.620",
        "status": "Active",
        "matches": [
            {
                "cpeName": "cpe:2.3:o:huawei:harmonyos:4.0.0:*:*:*:*:*:*:*",
                "cpeNameId": "13772648-495D-4EC7-8149-B6D7315A9B14",
            }
        ],
    }
    c2 = {
        "matchCriteriaId": "9664F6D2-4EE2-4326-9A93-5F8328FF65EC",
        "criteria": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:*:*:*:*:*:wordpress:*:*",
        "versionEndExcluding": "4.3.0",
        "lastModified": "2025-06-30T17:43:54.423",
        "cpeLastModified": "2025-05-30T14:51:02.800",
        "created": "2025-05-30T14:51:02.800",
        "status": "Active",
        "matches": [
            {
                "cpeName": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:-:*:*:*:*:wordpress:*:*",
                "cpeNameId": "1614B4A1-45B6-4E89-89C5-9E022AE82474",
            },
            {
                "cpeName": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:1.0.0:*:*:*:*:wordpress:*:*",
                "cpeNameId": "406D49C7-9260-481E-B3ED-875E3B986B00",
            },
            {
                "cpeName": "cpe:2.3:a:analytify:analytify_-_google_analytics_dashboard:1.0.1:*:*:*:*:wordpress:*:*",
                "cpeNameId": "EE44CE90-984E-4175-BF3E-0F40E3E6C30D",
            },
        ],
    }
    c3 = {
        "matchCriteriaId": "DE670466-3267-48D2-A826-99B23F7FBD12",
        "criteria": "cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.0",
        "versionEndIncluding": "6.0",
        "lastModified": "2025-06-18T15:07:21.570",
        "cpeLastModified": "2025-06-18T15:07:21.570",
        "created": "2025-06-18T15:07:21.570",
        "status": "Active",
        "matches": [
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0:*:*:*:*:*:*:*",
                "cpeNameId": "5168F11E-6A10-4088-B0FD-7D4A27E6B9F4",
            },
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0.1:*:*:*:*:*:*:*",
                "cpeNameId": "D2DBB792-9311-4DAE-B24F-80EBF1E863FD",
            },
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0.2:*:*:*:*:*:*:*",
                "cpeNameId": "D166C485-D262-49E2-8A73-99F6124D9E87",
            },
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0.3:*:*:*:*:*:*:*",
                "cpeNameId": "7984A7F0-9447-4088-8868-D26F8885A28A",
            },
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0.4:*:*:*:*:*:*:*",
                "cpeNameId": "9C0A2417-F535-49C1-9128-EDA00660D9C9",
            },
            {
                "cpeName": "cpe:2.3:a:ffmpeg:ffmpeg:2.0.5:*:*:*:*:*:*:*",
                "cpeNameId": "750E5040-01A9-40BD-A845-E5731EDA14BB",
            },
        ],
    }
    return {c["matchCriteriaId"]: c for c in (c1, c2, c3)}


def test_get_object_chunks(cpematch_manager, mocked_updates):
    cpematch_manager.groupings = None
    fake_grouping = {"will-be-called": None}
    cpematch_manager.get_updated_cpematches = MagicMock(
        return_value=[{}, mocked_updates, {}, fake_grouping]
    )
    cpematch_manager.get_single_chunk = MagicMock(return_value=[1, 2, 3])
    groupings_list = []
    for chunk in cpematch_manager.get_object_chunks():
        cpematch_manager.groupings and groupings_list.append(cpematch_manager.groupings)
        cpematch_manager.groupings = None
    cpematch_manager.get_single_chunk.assert_has_calls(
        [
            call(
                [
                    "8198CDB2-4BC5-411A-8736-615A531FC545",
                    "9664F6D2-4EE2-4326-9A93-5F8328FF65EC",
                    "DE670466-3267-48D2-A826-99B23F7FBD12",
                ]
            ),
            call(["will-be-called"]),
        ]
    )
    assert groupings_list == [mocked_updates, fake_grouping]


def test_get_cpematches__online(cpematch_manager):
    groupings = {}
    for updates in cpematch_manager.get_updated_cpematches():
        if updates:
            groupings.update(updates)
    assert groupings
