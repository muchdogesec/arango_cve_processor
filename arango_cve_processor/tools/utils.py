import json, hashlib
import logging
import re
import uuid

from arango.database import StandardDatabase
import requests
from stix2arango.services import ArangoDBService
import stix2
from stix2.serialization import serialize as serialize_stix
from tqdm import tqdm

from arango_cve_processor import config


def generate_md5(obj: dict):
    obj_copy = {k: v for k, v in obj.items() if not k.startswith("_")}
    for k in ["_from", "_to"]:
        if v := obj.get(k):
            obj_copy[k] = v
    json_str = json.dumps(obj_copy, sort_keys=True, default=str).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()


REQUIRED_COLLECTIONS = ["nvd_cve_vertex_collection", "nvd_cve_edge_collection"]


def validate_collections(db: "StandardDatabase"):
    missing_collections = set()
    for collection in REQUIRED_COLLECTIONS:
        try:
            db.collection(collection).info()
        except Exception as e:
            missing_collections.add(collection)
    if missing_collections:
        raise Exception(
            f"The following collections are missing. Please add them to continue. \n {missing_collections}"
        )


def import_default_objects(processor: ArangoDBService, default_objects: list = None):
    default_objects = list(default_objects or []) + config.DEFAULT_OBJECT_URL
    object_list = []
    for obj_url in default_objects:
        if isinstance(obj_url, str):
            obj = json.loads(load_file_from_url(obj_url))
        else:
            obj = obj_url
        obj["_arango_cve_processor_note"] = (
            "automatically imported object at script runtime"
        )
        obj["_record_md5_hash"] = generate_md5(obj)
        object_list.append(obj)

    collection_name = "nvd_cve_vertex_collection"
    inserted_ids, _ = processor.insert_several_objects(object_list, collection_name)
    processor.update_is_latest_several(inserted_ids, collection_name)


def genrate_relationship_id(source_ref, target_ref, relationship_type):
    return make_stix_id('relationship', f"{relationship_type}+{source_ref}+{target_ref}")


def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error loading JSON from {url}: {e}")
        raise Exception("Load default objects error")


def stix2python(obj: "stix2.base._STIXBase"):
    return json.loads(serialize_stix(obj))


EMBEDDED_RELATIONSHIP_RE = re.compile(r"([a-z_]+)_refs{0,1}")


def get_embedded_refs(object: list | dict, xpath: list = []):
    embedded_refs = []
    if isinstance(object, dict):
        for key, value in object.items():
            if key in ["source_ref", "target_ref"]:
                continue
            if match := EMBEDDED_RELATIONSHIP_RE.fullmatch(key):
                relationship_type = "-".join(xpath + match.group(1).split("_"))
                targets = value if isinstance(value, list) else [value]
                for target in targets:
                    embedded_refs.append((relationship_type, target))
            elif isinstance(value, list):
                embedded_refs.extend(get_embedded_refs(value, xpath + [key]))
    elif isinstance(object, list):
        for obj in object:
            if isinstance(obj, dict):
                embedded_refs.extend(get_embedded_refs(obj, xpath))
    return embedded_refs


def create_relationship(
    source,
    target_ref,
    relationship_type,
    description,
    relationship_id=None,
    is_ref=False,
    external_references=None,
    relationship_note=None,
    add_arango_props=True,
):
    relationship_id = relationship_id or make_stix_id('relationship', f"{relationship_type}+{source["id"]}+{target_ref}")
    retval = dict(
        spec_version="2.1",
        id=relationship_id,
        type="relationship",
        created=source.get("created"),
        modified=source.get("modified"),
        relationship_type=relationship_type,
        source_ref=source.get("id"),
        target_ref=target_ref,
        created_by_ref=config.IDENTITY_REF,
        object_marking_refs=config.OBJECT_MARKING_REFS,
        description=description,
    )
    if external_references:
        retval["external_references"] = external_references
    if add_arango_props:
        retval.update(
            _arango_cve_processor_note=relationship_note,
            _from=source.get("_id"),
            _is_ref=is_ref,
        )
    return retval


def chunked_tqdm(iterable, n, description=None):
    if not iterable:
        return []
    iterator = tqdm(range(0, len(iterable), n), total=len(iterable), desc=description)
    for i in iterator:
        chunk = iterable[i : i + n]
        yield chunk
        iterator.update(len(chunk))


def create_indexes(db: StandardDatabase):
    logging.info("start creating indexes")
    vertex_collection = db.collection("nvd_cve_vertex_collection")
    edge_collection = db.collection("nvd_cve_edge_collection")
    vertex_collection.add_index(
        dict(
            type="persistent",
            fields=["_arango_cve_processor_note", "type"],
            storedValues=["created", "modified"],
            inBackground=True,
            name=f"acvep_imports-type",
            sparse=True,
        )
    )
    vertex_collection.add_index(
        {
            "analyzer": "identity",
            "features": ["frequency", "norm"],
            "fields": [
                {"name": "x_cpes.vulnerable[*].matchCriteriaId"},
                {"name": "x_cpes.not_vulnerable[*].matchCriteriaId"},
                {"name": "_is_latest"},
                {"name": "type"},
            ],
            "name": "acvep_cpematch",
            "primarySort": {"fields": [], "compression": "lz4"},
            "sparse": True,
            "storedValues": [{"fields": [], "compression": "lz4"}],
            "type": "inverted",
        }
    )
    edge_collection.add_index(
        dict(
            type="persistent",
            fields=["_arango_cve_processor_note"],
            storedValues=["id", "_is_ref", "_is_latest"],
            inBackground=True,
            name=f"acvep_imports-type",
            sparse=True,
        )
    )
    logging.info("finished creating indexes")


def make_stix_id(type_part: str, content: str):
    id_part = uuid.uuid5(config.namespace, content)
    return type_part + "--" + str(id_part)
