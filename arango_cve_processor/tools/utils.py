import json, hashlib
import logging

from arango.database import StandardDatabase
import requests
from stix2arango.services import ArangoDBService

from arango_cve_processor import config

def generate_md5(obj: dict):
    obj_copy = {k: v for k, v in obj.items() if not k.startswith("_")}
    for k in ['_from', '_to', '_arango_cve_processor_note']:
        if v := obj.get(k):
            obj_copy[k] = v
    json_str = json.dumps(obj_copy, sort_keys=True, default=str).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()

REQUIRED_COLLECTIONS = ['nvd_cve_vertex_collection', 'nvd_cve_edge_collection']

def validate_collections(db: 'StandardDatabase'):
    missing_collections = set()
    for collection in REQUIRED_COLLECTIONS:
        try:
            db.collection(collection).info()
        except Exception as e:
            missing_collections.add(collection)
    if missing_collections:
        raise Exception(f"The following collections are missing. Please add them to continue. \n {missing_collections}")
    

def import_default_objects(processor: ArangoDBService, default_objects: list = None):
    default_objects = list(default_objects or []) + config.DEFAULT_OBJECT_URL
    object_list = []
    for obj_url in default_objects:
        if isinstance(obj_url, str):
            obj = json.loads(load_file_from_url(obj_url))
        else:
            obj = obj_url
        obj['_arango_cve_processor_note'] = "automatically imported object at script runtime"
        obj['_record_md5_hash'] = generate_md5(obj)
        object_list.append(obj)


    collection_name = 'nvd_cve_vertex_collection'
    inserted_ids, _ = processor.insert_several_objects(object_list, collection_name)
    processor.update_is_latest_several(inserted_ids, collection_name)

    

def load_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error loading JSON from {url}: {e}")
        raise Exception("Load default objects error")