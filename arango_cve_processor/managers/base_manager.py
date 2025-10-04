from datetime import UTC, datetime
import itertools
import logging
from types import SimpleNamespace
import uuid

from tqdm import tqdm
from arango_cve_processor import config
from enum import IntEnum, StrEnum
from stix2arango.services.arangodb_service import ArangoDBService

from arango_cve_processor.tools import utils
from arango_cve_processor.tools.utils import (
    chunked_tqdm,
    generate_md5,
    genrate_relationship_id,
    get_embedded_refs,
)


SMO_TYPES = ["marking-definition", "extension-definition", "language-content"]
RELATION_MANAGERS: dict[str, "type[STIXRelationManager]"] = {}


class STIXRelationManager:
    MIN_DATE_STR = "1970-01-01"
    BATCH_SIZE = 1000
    CHUNK_SIZE = BATCH_SIZE
    DESCRIPTION = "please set"

    def __init_subclass__(cls, /, relationship_note, register=True) -> None:
        cls.relationship_note = relationship_note
        if not register:
            return
        RELATION_MANAGERS[relationship_note] = cls

    vertex_collection: str = "nvd_cve_vertex_collection"
    edge_collection: str = "nvd_cve_edge_collection"

    containing_collection: str = None
    relationship_note = "stix-relation-manager"
    default_objects = []

    priority = 10  # used to determine order of running, for example cve_cwe must run before cve_capec, lower => run earlier

    def __init__(
        self,
        processor: ArangoDBService,
        *args,
        modified_min=None,
        created_min=None,
        cve_ids=None,
        ignore_embedded_relationships=True,
        ignore_embedded_relationships_smo=True,
        ignore_embedded_relationships_sro=True,
        **kwargs,
    ) -> None:
        self.arango = processor
        self.client = self.arango._client
        self.cve_ids = cve_ids or []
        self.created_min = created_min or self.MIN_DATE_STR
        self.modified_min = modified_min or self.MIN_DATE_STR
        self.ignore_embedded_relationships = ignore_embedded_relationships
        self.kwargs = kwargs
        self.ignore_embedded_relationships_smo = ignore_embedded_relationships_smo
        self.ignore_embedded_relationships_sro = ignore_embedded_relationships_sro
        self.update_objects = []

    @property
    def collection(self):
        return self.containing_collection or self.vertex_collection

    def get_object_chunks(self, **kwargs):
        raise NotImplementedError("must be subclassed")

    @classmethod
    def create_relationship(
        cls,
        source_ref,
        target_ref,
        relationship_type,
        description,
        relationship_id=None,
        is_ref=False,
        external_references=None,
        **kwargs,
    ):
        return utils.create_relationship(
            source_ref,
            target_ref,
            relationship_type,
            description,
            relationship_id=relationship_id,
            is_ref=is_ref,
            external_references=external_references,
            relationship_note=cls.relationship_note,
            **kwargs,
        )

    def upload_vertex_data(self, objects):
        if self.update_objects:
            modified_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            for obj in self.update_objects:
                obj.update(_record_modified=modified_at)

            logging.info("updating %d existing reports", len(self.update_objects))
            for batch in chunked_tqdm(
                self.update_objects, n=10_000, description="update existing objects"
            ):
                self.arango.db.collection(self.vertex_collection).update_many(batch)

        self.update_objects.clear()
        logging.info("uploading %d vertices", len(objects))
        for obj in objects:
            obj["_arango_cve_processor_note"] = self.relationship_note
            obj["_record_md5_hash"] = generate_md5(obj)

        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(
            objects, self.vertex_collection
        )
        self.arango.update_is_latest_several_chunked(
            inserted_ids, self.vertex_collection, self.edge_collection
        )

    def upload_edge_data(self, objects: list[dict]):
        logging.info("uploading %d edges", len(objects))

        ref_ids = []
        for edge in objects:
            edge.get("_to") or ref_ids.append(edge["target_ref"])
            edge.get("_from") or ref_ids.append(edge["source_ref"])

        edge_id_map = self.get_edge_ids(ref_ids, self.collection)

        for edge in objects:
            edge.update(_from=edge.get("_from") or edge_id_map.get(edge["source_ref"]))
            edge.update(_to=edge.get("_to") or edge_id_map.get(edge["target_ref"]))
            edge["_record_md5_hash"] = generate_md5(edge)

        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(
            objects, self.edge_collection
        )
        self.arango.update_is_latest_several_chunked(
            inserted_ids, self.edge_collection, self.edge_collection
        )
        if not self.ignore_embedded_relationships:
            self.create_embedded_relationships(
                objects, self.vertex_collection, self.edge_collection
            )

    def create_embedded_relationships(self, objects, *collections):
        edge_ids = {}
        obj_targets_map = {}
        for edge in objects:
            obj_targets_map[edge["id"]] = get_embedded_refs(edge)
        ref_ids = [
            target_ref for _, target_ref in itertools.chain(*obj_targets_map.values())
        ] + list(obj_targets_map)

        for collection in collections:
            edge_ids.update(self.get_edge_ids(ref_ids, collection))

        embedded_relationships = []
        for obj in objects:
            if (
                self.ignore_embedded_relationships_smo and obj["type"] in SMO_TYPES
            ) or (
                self.ignore_embedded_relationships_sro and obj["type"] == "relationship"
            ):
                continue

            for ref, target_id in obj_targets_map.get(obj["id"], []):
                _from, _to = edge_ids.get(obj["id"]), edge_ids.get(target_id)
                if not (_to and _from):
                    continue
                rel = self.create_relationship(
                    obj["id"],
                    target_ref=target_id,
                    relationship_type=ref,
                    is_ref=True,
                    description=None,
                    created=obj["created"],
                    modified=obj["modified"],
                    _from=_from,
                    _to=_to,
                )
                rel["_record_md5_hash"] = generate_md5(rel)
                embedded_relationships.append(rel)

        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(
            embedded_relationships, self.edge_collection
        )
        self.arango.update_is_latest_several_chunked(
            inserted_ids, self.edge_collection, self.edge_collection
        )
        return embedded_relationships

    def get_edge_ids(self, object_ids, collection=None) -> dict[str, str]:
        """
        Given object IDs, this returns the `doc._id` the latest object with same id
        """
        if not collection:
            collection = self.collection
        query = """
        FOR doc IN @@collection
        FILTER doc.id IN @object_ids
        SORT doc.modified ASC
        RETURN [doc.id, doc._id]
        """
        result = self.arango.execute_raw_query(
            query,
            bind_vars={"@collection": collection, "object_ids": list(set(object_ids))},
        )
        return dict(result)

    def relate_single(self, object):
        raise NotImplementedError("must be subclassed")

    def process(self, **kwargs):
        for chunk in self.get_object_chunks():
            if not chunk:
                continue
            logging.info("got %d objects - %s", len(chunk), self.relationship_note)
            self.do_process(chunk)

    def do_process(self, objects, extra_uploads=[]):
        logging.info("working on %d objects - %s", len(objects), self.relationship_note)
        uploads = [*extra_uploads]
        for obj in tqdm(objects, desc=f"{self.relationship_note} - [seq]"):
            uploads.extend(self.relate_single(obj))

        added = set()
        edges, vertices = [], []
        for obj in uploads:
            if obj["id"] in added:
                continue
            if obj["type"] == "relationship":
                edges.append(obj)
            else:
                vertices.append(obj)
            added.add(obj["id"])

        self.upload_vertex_data(vertices)
        self.upload_edge_data(edges)
