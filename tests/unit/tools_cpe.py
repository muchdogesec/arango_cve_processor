from datetime import UTC, datetime
import json
import random
from unittest.mock import patch

import pytest
from stix2 import Software, Indicator, Relationship
from pytz import timezone
from arango_cve_processor.tools import cpe as cpe_match
from arango_cve_processor.tools.utils import stix2python


@pytest.mark.parametrize(
    "cpename, expected_split",
    [
        (
            "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*",
            [
                "cpe",
                "2.3",
                "a",
                "apache",
                "http_server",
                "2.4.1",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            ],
        ),
        (
            "cpe:2.3:a:microsoft:windows\\:server:2019:*:*:*:*:*:*:*",
            [
                "cpe",
                "2.3",
                "a",
                "microsoft",
                "windows\\:server",
                "2019",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            ],
        ),
    ],
)
def test_split_cpe_name(cpename, expected_split):
    split = cpe_match.split_cpe_name(cpename)
    assert split == expected_split


def test_cpe_name_as_dict_extracts_fields():
    cpe = "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    d = cpe_match.cpe_name_as_dict(cpe)
    assert d == {
        "cpe_version": "2.3",
        "part": "a",
        "vendor": "apache",
        "product": "http_server",
        "version": "2.4.1",
        "update": "*",
        "edition": "*",
        "language": "*",
        "sw_edition": "*",
        "target_sw": "*",
        "target_hw": "*",
        "other": "*",
    }


def test_parse_software_returns_valid_software():
    cpe = "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*:*"
    swid = "software--12345"
    software_obj = cpe_match.parse_software(cpe, swid)
    assert isinstance(software_obj, Software)
    assert software_obj.x_cpe_struct == cpe_match.cpe_name_as_dict(cpe)
    assert software_obj.name == cpe
    assert software_obj.cpe == cpe
    assert software_obj.version == "2.4.1"
    assert software_obj.vendor == software_obj.x_cpe_struct["vendor"]
    assert swid == software_obj.swid
    assert (
        cpe_match.software_cpe_properties_ExtensionDefinitionSMO.id
        in software_obj.extensions
    )


@pytest.fixture
def indicator_with_cpes():
    return Indicator(
        **{
            "created": "2010-04-01T22:30:00.360Z",
            "created_by_ref": "identity--562918ee-d5da-5579-b6a1-fae50cc6bad3",
            "description": "Placeholder; this is not a real CVE Indicator",
            "extensions": {
                "extension-definition--ad995824-2901-5f6e-890b-561130a239d4": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-1226",
                    "external_id": "CVE-2010-1226",
                }
            ],
            "id": "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "indicator_types": ["compromised"],
            "modified": "2025-04-11T00:51:21.963Z",
            "name": "CVE-2010-1226",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
            ],
            "pattern": "[software:cpe='cpe:2.3:h:apple:iphone:2g:*:*:*:*:*:*:*']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": "2010-04-01T22:30:00.36Z",
            "x_cpes": {
                "not_vulnerable": [
                    {
                        "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                        "matchCriteriaId": "A2572D17-1DE6-457B-99CC-64AFD54487EA",
                    },
                ],
                "vulnerable": [
                    {
                        "criteria": "cpe:2.3:o:apple:iphone_os:3.1:*:*:*:*:*:*:*",
                        "matchCriteriaId": "51D3BE2B-5A01-4AD4-A436-0056B50A535D",
                    },
                    {
                        "matchCriteriaId": "703AF700-7A70-47E2-BC3A-7FD03B3CA9C1",
                        "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                    },
                ],
            },
        }
    )


@pytest.fixture
def cpematch():
    return {
        "resultsPerPage": 4,
        "startIndex": 0,
        "totalResults": 4,
        "format": "NVD_CPEMatchString",
        "version": "2.0",
        "timestamp": "2025-08-26T09:21:01.340",
        "matchStrings": [
            {
                "matchString": {
                    "matchCriteriaId": "A2572D17-1DE6-457B-99CC-64AFD54487EA",
                    "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                    "lastModified": "2022-09-26T22:47:53.533",
                    "cpeLastModified": "2025-03-11T18:33:05.670",
                    "created": "2019-06-17T09:16:33.960",
                    "status": "Active",
                    "versionEndExcluding": "138.0.7204.183",
                    "matches": [
                        {
                            "cpeName": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "cpeNameId": "32D33F53-B7FC-4674-BD03-299D70A278F3",
                        },
                        {
                            "cpeName": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:arm64:*",
                            "cpeNameId": "9DD26176-7C8B-46E0-B52E-827BDB94E383",
                        },
                        {
                            "cpeName": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*",
                            "cpeNameId": "2470AF67-0E77-4E85-92E8-79DE0D826055",
                        },
                        {
                            "cpeName": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x86:*",
                            "cpeNameId": "892CAEC7-9569-4385-8335-239B83D58837",
                        },
                    ],
                }
            },
            {
                "matchString": {
                    "matchCriteriaId": "703AF700-7A70-47E2-BC3A-7FD03B3CA9C1",
                    "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                    "lastModified": "2024-05-17T15:36:38.157",
                    "cpeLastModified": "2024-12-30T18:00:49.943",
                    "created": "2019-06-17T09:16:33.960",
                    "status": "Inactive",
                    "matches": [
                        {
                            "cpeName": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                            "cpeNameId": "0BA1AF04-98FA-4EBA-893B-700905C43151",
                        },
                        {
                            "cpeName": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:arm32:*",
                            "cpeNameId": "0EE3D2E5-A1B7-4DD3-9B6A-9CD7014FF769",
                        },
                        {
                            "cpeName": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:x64:*",
                            "cpeNameId": "DCBFE1ED-9B0D-4F9C-ABCF-0AFDFA24DFAF",
                        },
                    ],
                }
            },
            {
                "matchString": {
                    "matchCriteriaId": "387021A0-AF36-463C-A605-32EA7DAC172E",
                    "criteria": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
                    "lastModified": "2022-09-27T14:33:10.613",
                    "cpeLastModified": "2021-09-08T17:26:22.730",
                    "created": "2020-06-30T18:09:44.937",
                    "status": "Active",
                    "matches": [
                        {
                            "cpeName": "cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*",
                            "cpeNameId": "65828730-1ABF-46EF-8AD3-8F809902378A",
                        }
                    ],
                }
            },
        ],
    }


@pytest.fixture
def matchString(cpematch):
    return cpematch["matchStrings"][0]["matchString"]


def test_parse_cpematch_date():
    assert cpe_match.parse_cpematch_date("2022-09-26T22:47:53.533") == datetime(
        2022, 9, 26, 22, 47, 53, microsecond=533 * 1000, tzinfo=UTC
    )
    assert cpe_match.parse_cpematch_date("2025-03-11T18:33:05.670") == datetime(
        2025, 3, 11, 18, 33, 5, microsecond=670 * 1000, tzinfo=UTC
    )
    assert cpe_match.parse_cpematch_date("2019-06-17T09:16:33.960") == datetime(
        2019, 6, 17, 9, 16, 33, microsecond=960 * 1000, tzinfo=UTC
    )


def test_parse_objects_for_criteria(matchString):
    grouping, *softwares = cpe_match.parse_objects_for_criteria(matchString)
    assert grouping["id"] == "grouping--3143de40-745c-5251-aa25-aedea6a0756e"
    assert grouping["name"] == matchString["criteria"]
    assert grouping["external_references"] == [
        {
            "external_id": "A2572D17-1DE6-457B-99CC-64AFD54487EA",
            "source_name": "matchCriteriaId",
        },
        {
            "external_id": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
            "source_name": "pattern",
        },
        {"external_id": "138.0.7204.183", "source_name": "versionEndExcluding"},
    ]
    assert grouping["object_refs"] == [
        "software--01b9ce26-9416-54e7-a916-5290eafe6176",
        "software--8f1a5af2-5495-5046-82bb-34932c321ac3",
        "software--2647140d-fc46-59ef-ae53-e1b8b21e1a3d",
        "software--6d0008e3-6e68-5b44-9c96-9d03148c5ea2",
    ]


@pytest.mark.parametrize(
    "i,expected_revoked",
    [
        (0, False),
        (1, True),
        (2, False),
    ],
)
def test_grouping_revoked(cpematch, i, expected_revoked):
    grouping, *softwares = cpe_match.parse_objects_for_criteria(
        cpematch["matchStrings"][i]["matchString"]
    )
    assert grouping["revoked"] == expected_revoked


def test_grouping__object_ref_contains_all_softwares(cpematch):
    for match in cpematch["matchStrings"]:
        grouping, *softwares = cpe_match.parse_objects_for_criteria(
            match["matchString"]
        )
        assert set(grouping["object_refs"]) == {s["id"] for s in softwares}


def test_parse_software():
    s = cpe_match.parse_software(
        "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
        "0BA1AF04-98FA-4EBA-893B-700905C43151",
    )
    assert stix2python(s) == {
        "type": "software",
        "spec_version": "2.1",
        "id": "software--246f33a1-3525-5ccb-a1fd-b057a0907c55",
        "name": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
        "cpe": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
        "swid": "0BA1AF04-98FA-4EBA-893B-700905C43151",
        "vendor": "linux",
        "version": "-",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        "extensions": {
            "extension-definition--82cad0bb-0906-5885-95cc-cafe5ee0a500": {
                "extension_type": "toplevel-property-extension"
            }
        },
        "x_cpe_struct": {
            "cpe_version": "2.3",
            "part": "o",
            "vendor": "linux",
            "product": "linux_kernel",
            "version": "-",
            "update": "*",
            "edition": "*",
            "language": "*",
            "sw_edition": "*",
            "target_sw": "*",
            "target_hw": "*",
            "other": "*",
        },
    }


def test_relate_indicator__not_vulnerable(indicator_with_cpes, cpematch):
    grouping, *softwares = cpe_match.parse_objects_for_criteria(
        cpematch["matchStrings"][0]["matchString"]
    )
    relationships = stix2python(
        cpe_match.relate_indicator(grouping, indicator_with_cpes)
    )
    assert relationships == [
        {
            "spec_version": "2.1",
            "id": "relationship--4148fc82-05e7-59ba-89e3-b10d3e94a377",
            "type": "relationship",
            "created": "2010-04-01T22:30:00.360Z",
            "modified": "2025-04-11T00:51:21.963Z",
            "relationship_type": "x-cpes-not-vulnerable",
            "source_ref": "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "target_ref": "grouping--3143de40-745c-5251-aa25-aedea6a0756e",
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "A2572D17-1DE6-457B-99CC-64AFD54487EA (cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*) is not vulnerable to CVE-2010-1226",
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-1226",
                    "external_id": "CVE-2010-1226",
                },
                {
                    "source_name": "matchCriteriaId",
                    "external_id": "A2572D17-1DE6-457B-99CC-64AFD54487EA",
                },
                {
                    "source_name": "pattern",
                    "external_id": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                },
            ],
        }
    ]


def test_parse_objects__null_matchdata():
    from stix2 import parse

    null_match = {
        "matchCriteriaId": "BBBF5AF2-7910-4D1D-9BAD-2E5D243CE02F",
        "criteria": "cpe:2.3:a:ultrapress:unseen_blog:*:*:*:*:*:wordpress:*:*",
        "versionEndIncluding": "1.0.0",
        "lastModified": "2024-11-08T21:29:12.073",
        "cpeLastModified": "2024-11-08T21:29:12.073",
        "created": "2024-11-08T21:29:12.073",
        "status": "Active",
    }
    grouping, *softwares = cpe_match.parse_objects_for_criteria(null_match)
    grouping = parse(grouping)
    assert len(softwares) == 0
    assert grouping.object_refs == [
        "software--11111111-1111-4111-8111-111111111111"
    ], "must have exactly one software with null id"
    assert grouping.description


def test_relate_indicator__vulnerable(indicator_with_cpes, cpematch):
    grouping, *softwares = cpe_match.parse_objects_for_criteria(
        cpematch["matchStrings"][1]["matchString"]
    )
    relationships = stix2python(
        cpe_match.relate_indicator(grouping, indicator_with_cpes)
    )
    assert relationships == [
        {
            "id": "relationship--b72c5225-b258-5b1b-8855-c69878151c04",
            "type": "relationship",
            "spec_version": "2.1",
            "source_ref": "indicator--02e44f54-182b-551d-b3c1-3ba098ed56a6",
            "target_ref": "grouping--48a6e763-650c-589e-9fba-2b87e78a2125",
            "created": "2010-04-01T22:30:00.360Z",
            "modified": "2025-04-11T00:51:21.963Z",
            "relationship_type": "x-cpes-vulnerable",
            "description": "703AF700-7A70-47E2-BC3A-7FD03B3CA9C1 (cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*) is vulnerable to CVE-2010-1226",
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2010-1226",
                    "external_id": "CVE-2010-1226",
                },
                {
                    "source_name": "matchCriteriaId",
                    "external_id": "703AF700-7A70-47E2-BC3A-7FD03B3CA9C1",
                },
                {
                    "source_name": "pattern",
                    "external_id": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                },
            ],
        },
    ]
