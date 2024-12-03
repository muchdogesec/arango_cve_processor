import json, hashlib

from arango.database import StandardDatabase

def generate_md5(obj: dict):
    obj_copy = {k: v for k, v in obj.items() if not k.startswith("_")}
    for k in ['_from', '_to', '_arango_cve_processor_note']:
        if v := obj.get(k):
            obj_copy[k] = v
    json_str = json.dumps(obj_copy, sort_keys=True, default=str).encode("utf-8")
    return hashlib.md5(json_str).hexdigest()

def validate_collections(db: 'StandardDatabase'):
    missing_collections = set()
    for collection in ['nvd_cve_vertex_collection', 'nvd_cpe_vertex_collection', 'nvd_cve_edge_collection', 'nvd_cpe_edge_collection']:
        try:
            db.collection(collection).info()
        except Exception as e:
            missing_collections.add(collection)
    if missing_collections:
        raise Exception(f"The following collections are missing. Please add them to continue. \n {missing_collections}")