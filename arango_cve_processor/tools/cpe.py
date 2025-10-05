from datetime import datetime
import re
import uuid
import pytz
from stix2 import Grouping, Software
from stix2extensions._extensions import software_cpe_properties_ExtensionDefinitionSMO

from arango_cve_processor import config
from arango_cve_processor.tools import utils
from arango_cve_processor.tools.cpe_db import SwidTitleDB


def parse_cpematch_date(d):
    return pytz.utc.localize(datetime.strptime(d, "%Y-%m-%dT%H:%M:%S.%f"))


def parse_objects_for_criteria(match_data: dict):
    criteria_id: str = match_data["matchCriteriaId"]
    cpes = []
    for cpe in match_data.get("matches", []):
        cpes.append((cpe["cpeName"], cpe["cpeNameId"]))
    softwares = parse_softwares(cpes)
    more_refs = [
        dict(source_name=k, external_id=v)
        for k, v in match_data.items()
        if k.startswith("version")
    ]
    grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": generate_grouping_id(criteria_id),
        "created_by_ref": config.IDENTITY_REF,
        "created": parse_cpematch_date(match_data["created"]),
        "modified": parse_cpematch_date(match_data["lastModified"]),
        "name": match_data["criteria"],
        "revoked": match_data["status"] == "Inactive",
        "context": "unspecified",
        "object_refs": [software["id"] for software in softwares],
        "external_references": [
            dict(
                source_name="matchCriteriaId", external_id=match_data["matchCriteriaId"]
            ),
            dict(source_name="matchstring", external_id=match_data["criteria"]),
            *more_refs,
        ],
        "object_marking_refs": config.OBJECT_MARKING_REFS,
    }
    if not softwares:
        grouping["object_refs"] = ["software--11111111-1111-4111-8111-111111111111"]
        grouping["description"] = (
            "This grouping contains no CPEs, a null software object has been added in object_refs"
        )
    return [grouping, *softwares]


def generate_grouping_id(criteria_id):
    return "grouping--" + str(
        uuid.uuid5(
            config.namespace,
            criteria_id,
        )
    )


def parse_deprecations(softwares, add_arango_props=True):
    name_db = SwidTitleDB.get_db()
    objects = []
    for source in softwares:
        cpe = name_db.lookup(source.swid)
        for deprecated in cpe["deprecates"]:
            target = parse_software(deprecated["cpeName"], deprecated["cpeNameId"])
            objects.append(
                utils.create_relationship(
                    source["id"],
                    target.id,
                    relationship_type="related-to",
                    description=f"{source.cpe} deprecates {target.cpe}",
                    add_arango_props=add_arango_props,
                    created=source["x_created"],
                    modified=source["x_modified"],
                    _from=source.get("_id"),
                )
            )
            objects.append(target)
    return objects


def parse_softwares(cpematches):
    softwares = []
    for cpename, swid in cpematches:
        s = parse_software(cpename, swid)
        softwares.append(s)
    return softwares


def relate_indicator(grouping: Grouping, indicator):
    group_name, cve_name = grouping["name"], indicator["name"]
    criteria_id = grouping["external_references"][0]["external_id"]
    vulnerable_criteria_ids = []
    for vv in indicator["x_cpes"].get("vulnerable", []):
        vulnerable_criteria_ids.append(vv["matchCriteriaId"])
    relationships = []
    ext_refs = [
        indicator["external_references"][0],
        *grouping["external_references"][:2],
    ]

    if criteria_id in vulnerable_criteria_ids:
        relationships.append(
            utils.create_relationship(
                indicator["id"],
                grouping["id"],
                "x-cpes-vulnerable",
                f"{criteria_id} ({group_name}) is vulnerable to {cve_name}",
                external_references=ext_refs,
                add_arango_props=False,
                created=indicator["created"],
                modified=indicator["modified"],
                _from=indicator.get('_id'),
            )
        )
    else:
        relationships.append(
            utils.create_relationship(
                indicator["id"],
                grouping["id"],
                "x-cpes-not-vulnerable",
                f"{criteria_id} ({group_name}) is not vulnerable to {cve_name}",
                external_references=ext_refs,
                add_arango_props=False,
                created=indicator["created"],
                modified=indicator["modified"],
                _from=indicator.get('_id'),
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


def make_software_id(cpename, swid):
    return "software--" + str(
        uuid.uuid5(
            config.namespace,
            f"{cpename}+{swid}",
        )
    )


def parse_software(cpename, swid):
    cpe_struct = cpe_name_as_dict(cpename)
    name_db = SwidTitleDB.get_db()
    cpe = name_db.lookup(swid)
    stix_id = make_software_id(cpename, swid)
    created = parse_cpematch_date(cpe["created"])
    modified = parse_cpematch_date(cpe["modified"])

    return Software(
        id=stix_id,
        x_cpe_struct=cpe_struct,
        cpe=cpename,
        name=cpe.get("title", cpename),
        swid=swid,
        version=cpe_struct["version"],
        vendor=cpe_struct["vendor"],
        extensions={
            software_cpe_properties_ExtensionDefinitionSMO.id: {
                "extension_type": "toplevel-property-extension"
            }
        },
        object_marking_refs=config.OBJECT_MARKING_REFS,
        x_revoked=cpe["deprecated"],
        x_created=created,
        x_modified=modified,
        allow_custom=True,
    )
