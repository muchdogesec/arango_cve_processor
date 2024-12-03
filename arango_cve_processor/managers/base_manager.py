

import logging
from types import SimpleNamespace
import uuid

from tqdm import tqdm
from arango_cve_processor import config
from enum import IntEnum, StrEnum
from stix2arango.services.arangodb_service import ArangoDBService

from arango_cve_processor.tools.utils import generate_md5


class RelationType(StrEnum):
    RELATE_SEQUENTIAL = "sequential"
    RELATE_PARALLEL = "parallel"


RELATION_MANAGERS: dict[str, 'type[STIXRelationManager]'] = {}

class STIXRelationManager:
    def __init_subclass__(cls,/, relationship_note) -> None:
        cls.relationship_note = relationship_note
        RELATION_MANAGERS[relationship_note] = cls

    relation_type: RelationType = RelationType.RELATE_SEQUENTIAL
    vertex_collection : str = None
    edge_collection : str = None
    containing_collection : str = None
    relationship_note = 'stix-relation-manager'

    priority = 10 # used to determine order of running, for example cve_cwe must run before cve_capec, lower => run earlier

    def __init__(self, processor: ArangoDBService, *args, modified_min=None, created_min=None, **kwargs) -> None:
        self.arango = processor
        self.client = self.arango._client

    @property
    def collection(self):
        return self.containing_collection or self.vertex_collection

    def get_objects(self, **kwargs):
        query = """
        FOR doc IN @@collection
        FILTER doc._is_latest
        RETURN doc
        """
        return self.arango.execute_raw_query(query, bind_vars={'@collection': self.collection})
    
    @classmethod
    def create_relationship(cls, source, target_ref, relationship_type, description, relationship_id=None):
        if not relationship_id:
            relationship_id = "relationship--" + str(
                uuid.uuid5(
                    config.namespace,
                    f"{relationship_type}+{source['id']}+{target_ref}",
                )
            )

        return dict(
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
            _arango_cve_processor_note=cls.relationship_note,
            _from=source.get('_id'),
        )
    
    def import_external_data(self, objects) -> dict[str, dict]:
        pass

    def upload_vertex_data(self, objects):
        logging.info("uploading %d vertices", len(objects))
        for obj in objects:
            obj['_arango_cve_processor_note'] = self.relationship_note
            obj['_record_md5_hash'] = generate_md5(obj)
            
        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(objects, self.vertex_collection)
        self.arango.update_is_latest_several_chunked(inserted_ids, self.vertex_collection)

    
    def upload_edge_data(self, objects: list[dict]):
        logging.info("uploading %d edges", len(objects))

        ref_ids = []
        for edge in objects:
            ref_ids.append(edge['target_ref'])
            ref_ids.append(edge['source_ref'])
        edge_id_map = self.get_edge_ids(ref_ids, self.collection)

        for edge in objects:
            edge.setdefault('_from', edge_id_map.get(edge['source_ref'], edge['source_ref']))
            edge.setdefault('_to', edge_id_map.get(edge['target_ref'], edge['target_ref']))
            edge['_record_md5_hash'] = generate_md5(edge)


        inserted_ids, existing_objects = self.arango.insert_several_objects_chunked(objects, self.edge_collection)
        self.arango.update_is_latest_several_chunked(inserted_ids, self.edge_collection)

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
        result = self.arango.execute_raw_query(query, bind_vars={'@collection': collection, 'object_ids': object_ids})
        return dict(result)
        
    def relate_single(self, object):
        raise NotImplementedError('must be subclassed')
    
    def relate_multiple(self, objects):
        raise NotImplementedError('must be subclassed')
    
    
    def process(self, **kwargs):
        logging.info("getting objects")
        objects = self.get_objects(**kwargs)
        uploads = []
        match self.relation_type:
            case RelationType.RELATE_SEQUENTIAL:
                for obj in tqdm(objects, desc=f'{self.relationship_note} - {self.relation_type}'):
                    uploads.extend(self.relate_single(obj))
            case RelationType.RELATE_PARALLEL:
                uploads.extend(self.relate_multiple(objects))
        
        edges, vertices = [], []
        for obj in uploads:
            if obj['type'] == 'relationship':
                edges.append(obj)
            else:
                vertices.append(obj)

        self.upload_vertex_data(vertices)
        self.upload_edge_data(edges)
 
