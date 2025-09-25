import time
from unittest.mock import call, patch
from arango_cve_processor.managers.cve_attack import CveAttack

from unittest.mock import call, patch

import pytest
from arango_cve_processor.managers.cve_attack import CveAttack
from arango_cve_processor.managers.cve_capec import CveCapec
from arango_cve_processor.managers.cve_cwe import CveCwe
from arango_cve_processor.tools.retriever import STIXObjectRetriever


@pytest.fixture(scope="module")
def attack_processor(acp_processor, module_retriever):
    cwe_manager = CveCwe(
        acp_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    capec_manager = CveCapec(
        acp_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    cwe_manager.process()
    time.sleep(1)
    capec_manager.process()
    time.sleep(1)
    yield acp_processor


def test_get_object_chunks(attack_processor):
    manager = CveAttack(
        attack_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    manager.CHUNK_SIZE = 2
    matches = list(manager.get_object_chunks())
    print(matches)
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
                        "description": "Exploitation for Defensive Evasion",
                        "external_id": "T1211",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1211",
                    },
                    {
                        "description": "Pre-OS Boot: Component Firmware",
                        "external_id": "T1542.002",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1542/002",
                    },
                    {
                        "description": "Modify Authentication Process",
                        "external_id": "T1556",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1556",
                    },
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
                        "description": "Obfuscated Files or Information: HTML Smuggling",
                        "external_id": "T1027.006",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1027/006",
                    },
                    {
                        "description": "Obfuscated Files or Information:\xa0Embedded Payloads",
                        "external_id": "T1027.009",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1027/009",
                    },
                    {
                        "description": "Hide Artifacts: Resource Forking",
                        "external_id": "T1564.009",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1564/009",
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
                        "description": "Abuse Elevation Control Mechanism",
                        "external_id": "T1548",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1548",
                    },
                    {
                        "description": "Hijack Execution Flow: ServicesFile Permissions Weakness",
                        "external_id": "T1574.010",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1574/010",
                    },
                    {
                        "description": "Abuse Elevation Control Mechanism",
                        "external_id": "T1548",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1548",
                    },
                    {
                        "description": "File and Directory Discovery",
                        "external_id": "T1083",
                        "source_name": "ATTACK",
                        "url": "https://attack.mitre.org/wiki/Technique/T1083",
                    },
                ],
            }
        ],
        [],
    ]


def test_do_process(attack_processor):
    manager = CveAttack(
        attack_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    manager.CHUNK_SIZE = 2  # only use first two
    objects = list(manager.get_object_chunks())[0]

    with patch(
        "arango_cve_processor.managers.cve_cwe.STIXRelationManager.do_process"
    ) as mock_super_do_process:
        manager.do_process(objects)

        mock_super_do_process.assert_called_once()
        assert mock_super_do_process.call_args[0][0] == objects
        print(
            {
                (k, obj["id"])
                for k, obj in STIXObjectRetriever.make_map(
                    mock_super_do_process.call_args[1]["extra_uploads"]
                ).items()
            }
        )
        assert {
            (k, obj["id"])
            for k, obj in STIXObjectRetriever.make_map(
                mock_super_do_process.call_args[1]["extra_uploads"]
            ).items()
        } == {
            ("T1564.009", "attack-pattern--b22e5153-ac28-4cc6-865c-2054e36285cb"),
            ("T1542.002", "attack-pattern--791481f8-e96a-41be-b089-a088763083d4"),
            ("T1027.006", "attack-pattern--d4dc46e3-5ba5-45b9-8204-010867cacfcb"),
            ("T1027.009", "attack-pattern--0533ab23-3f7d-463f-9bd8-634d27e4dee1"),
            ("T1556", "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84"),
            ("T1211", "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b"),
        }


def test_relate_single(attack_processor):
    manager = CveAttack(
        attack_processor, created_min="1970-01-01", modified_min="1970-01-01"
    )
    manager.all_external_objects = STIXObjectRetriever().get_objects_by_external_ids(
        ["T1564.009", "T1027.006", "T1211", "T1556"], CveAttack.ctibutler_path
    )  # skip 3 capecs to simulate missing
    retval = manager.relate_single(
        {
            "_id": "nvd_cve_vertex_collection/vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.901482Z",
            "created": "2025-01-02T15:15:18.650Z",
            "id": "vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            "modified": "2025-06-05T21:01:15.860Z",
            "name": "CVE-2022-45830",
            "external_references": [
                {
                    "description": "Exploitation for Defensive Evasion",
                    "external_id": "T1211",
                    "source_name": "ATTACK",
                    "url": "https://attack.mitre.org/wiki/Technique/T1211",
                },
                {
                    "description": "Pre-OS Boot: Component Firmware",
                    "external_id": "T1542.002",
                    "source_name": "ATTACK",
                    "url": "https://attack.mitre.org/wiki/Technique/T1542/002",
                },
                {
                    "description": "Modify Authentication Process",
                    "external_id": "T1556",
                    "source_name": "ATTACK",
                    "url": "https://attack.mitre.org/wiki/Technique/T1556",
                },
            ],
        }
    )
    print(retval)
    assert retval == [
        {
            "spec_version": "2.1",
            "id": "relationship--9a5d8e10-758e-5daa-a1d1-f026f688e001",
            "type": "relationship",
            "created": "2025-01-02T15:15:18.650Z",
            "modified": "2025-06-05T21:01:15.860Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            "target_ref": "attack-pattern--fe926152-f431-4baf-956c-4ad3cb0bf23b",
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2022-45830 is exploited using T1211",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2022-45830",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1211",
                    "external_id": "T1211",
                },
            ],
            "_arango_cve_processor_note": "cve-attack",
            "_from": "nvd_cve_vertex_collection/vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.901482Z",
            "_is_ref": False,
        },
        {
            "spec_version": "2.1",
            "id": "relationship--b2b8f553-ccd4-53d2-9542-9eda3c109977",
            "type": "relationship",
            "created": "2025-01-02T15:15:18.650Z",
            "modified": "2025-06-05T21:01:15.860Z",
            "relationship_type": "exploited-using",
            "source_ref": "vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606",
            "target_ref": "attack-pattern--f4c1826f-a322-41cd-9557-562100848c84",
            "created_by_ref": "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            ],
            "description": "CVE-2022-45830 is exploited using T1556",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2022-45830",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-45830",
                },
                {
                    "source_name": "mitre-attack",
                    "url": "https://attack.mitre.org/techniques/T1556",
                    "external_id": "T1556",
                },
            ],
            "_arango_cve_processor_note": "cve-attack",
            "_from": "nvd_cve_vertex_collection/vulnerability--b7e6accd-fb2a-540c-bf13-f305fe42d606+2025-09-12T11:25:34.901482Z",
            "_is_ref": False,
        },
    ]
