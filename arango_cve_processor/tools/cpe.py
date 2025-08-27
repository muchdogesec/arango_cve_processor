from datetime import datetime
import re
import uuid
import pytz
from stix2 import Grouping, Software, Relationship
from stix2extensions._extensions import software_cpe_properties_ExtensionDefinitionSMO

from arango_cve_processor import config
from arango_cve_processor.tools.utils import genrate_relationship_id


def parse_cpematch_date(d):
    return pytz.utc.localize(datetime.strptime(d, "%Y-%m-%dT%H:%M:%S.%f"))


def parse_objects_for_criteria(match_data):
    match_data = match_data["matchString"]
    criteria_id: str = match_data["matchCriteriaId"]
    cpes = []
    for cpe in match_data.get("matches", []):
        cpes.append((cpe["cpeName"], cpe["cpeNameId"]))
    softwares = parse_softwares(cpes)
    grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": "grouping--"
        + str(
            uuid.uuid5(
                config.namespace,
                criteria_id,
            )
        ),
        "created_by_ref": config.IDENTITY_REF,
        "created": parse_cpematch_date(match_data["created"]),
        "modified": parse_cpematch_date(match_data["lastModified"]),
        "name": match_data["matchCriteriaId"],
        "revoked": match_data["status"] == "Inactive",
        "context": "unspecified",
        "object_refs": [software["id"] for software in softwares],
        "external_references": [
            dict(source_name="pattern", external_id=match_data["criteria"]),
            dict(
                source_name="matchCriteriaId", external_id=match_data["matchCriteriaId"]
            ),
        ],
        "object_marking_refs": config.OBJECT_MARKING_REFS,
    }
    return [grouping, *softwares]


def parse_softwares(softwares):
    return [parse_software(cpename, swid) for cpename, swid in softwares]


def relate_indicator(grouping: Grouping, indicator):
    criteria_id, cve_name = grouping["name"], indicator["name"]
    vulnerable_criteria_ids = []
    for vv in indicator["x_cpes"].get("vulnerable", []):
        vulnerable_criteria_ids.append(vv["matchCriteriaId"])
    relationships = []
    ext_refs = [
        indicator["external_references"][0],
        *grouping["external_references"],
    ]

    relationships.append(
        dict(
            id=genrate_relationship_id(
                indicator["id"], grouping["id"], "pattern-match-string"
            ),
            spec_version="2.1",
            type="relationship",
            source_ref=indicator["id"],
            target_ref=grouping["id"],
            created=indicator["created"],
            modified=indicator["modified"],
            relationship_type="pattern-match-string",
            description=f"{criteria_id} pattern matches {cve_name}",
            created_by_ref=config.IDENTITY_REF,
            object_marking_refs=config.OBJECT_MARKING_REFS,
            external_references=ext_refs,
        )
    )
    if criteria_id in vulnerable_criteria_ids:
        relationships.append(
            dict(
                id=genrate_relationship_id(
                    indicator["id"], grouping["id"], "pattern-match-string"
                ),
                type="relationship",
                spec_version="2.1",
                source_ref=indicator["id"],
                target_ref=grouping["id"],
                created=indicator["created"],
                modified=indicator["modified"],
                relationship_type="vulnerable-match-string",
                description=f"{criteria_id} is vulnerable to {cve_name}",
                created_by_ref=config.IDENTITY_REF,
                object_marking_refs=config.OBJECT_MARKING_REFS,
                external_references=ext_refs,
            )
        )
    return relationships


def split_cpe_name(cpename: str) -> list[str]:
    """
    Split CPE 2.3 into its components, accounting for escaped colons.
    """
    non_escaped_colon = r"(?<!\\):"
    split_name = re.split(non_escaped_colon, cpename)
    return split_name


def cpe_name_as_dict(cpe_name: str) -> dict[str, str]:
    splits = split_cpe_name(cpe_name)[1:]
    return dict(
        zip(
            [
                "cpe_version",
                "part",
                "vendor",
                "product",
                "version",
                "update",
                "edition",
                "language",
                "sw_edition",
                "target_sw",
                "target_hw",
                "other",
            ],
            splits,
        )
    )


def parse_software(cpename, swid):
    cpe_struct = cpe_name_as_dict(cpename)
    return Software(
        id="software--"
        + str(
            uuid.uuid5(
                config.namespace,
                f"{cpename}+{swid}",
            )
        ),
        x_cpe_struct=cpe_struct,
        cpe=cpename,
        name=cpename,
        swid=swid,
        version=cpe_struct["version"],
        vendor=cpe_struct["vendor"],
        extensions={
            software_cpe_properties_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--562918ee-d5da-5579-b6a1-fae50cc6bad3",
        ],
        allow_custom=True,
    )
