import itertools
import logging
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.managers.base_manager import RelationType, STIXRelationManager


class CveCwe(STIXRelationManager, relationship_note="cve-cwe"):
    priority = 0

    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"
    relation_type = RelationType.RELATE_PARALLEL

    ctibutler_path = "cwe"
    ctibutler_query = "cwe_id"
    source_name = "cwe"
    CHUNK_SIZE = 20_000

    def get_objects_chunk(self, start, batch_size):
        query = """
        FOR doc IN @@collection
        FILTER doc._is_latest == TRUE AND doc.type == 'vulnerability' 
            AND doc.created >= @created_min 
            AND doc.modified >= @modified_min
            AND (NOT @cve_ids OR doc.name IN @cve_ids) // filter --cve_id
            AND doc.external_references[? ANY FILTER CURRENT.source_name == @source_name] 
        LIMIT @start, @batch_size
        RETURN KEEP(doc, '_id', 'id', 'external_references', 'name', 'created', 'modified')
        """
        bindings = {
            "@collection": self.collection,
            "source_name": self.source_name,
            "created_min": self.created_min,
            "modified_min": self.modified_min,
            "cve_ids": self.cve_ids or None,
            "start": start,
            "batch_size": batch_size,
        }
        return self.arango.execute_raw_query(query, bind_vars=bindings) or None

    def relate_multiple(self, objects):
        logging.info("relating %s (%s)", self.relationship_note, self.ctibutler_path)
        cve_id_cwe_map: dict[str, list[str]] = {}
        for cve in objects:
            cve_id_cwe_map[cve["id"]] = [
                ref["external_id"]
                for ref in cve["external_references"]
                if ref and ref["source_name"] == self.source_name
            ]
        cwe_ids = list(itertools.chain(*cve_id_cwe_map.values()))
        all_cwe_objects = STIXObjectRetriever("ctibutler").get_objects_by_external_ids(
            cwe_ids, self.ctibutler_path, query_filter=self.ctibutler_query
        )

        retval = list(
            {v["id"]: v for v in itertools.chain(*all_cwe_objects.values())}.values()
        )
        for cve in objects:
            cve_id = cve["name"]
            for cwe_id in cve_id_cwe_map.get(cve["id"], []):
                cwe_objects = all_cwe_objects.get(cwe_id)
                if not cwe_objects:
                    continue
                for cwe_object in cwe_objects:
                    retval.append(
                        self.create_relationship(
                            cve,
                            cwe_object["id"],
                            relationship_type="exploited-using",
                            description=f"{cve_id} is exploited using {cwe_id}",
                            external_references=self.get_external_references(
                                cve_id, cwe_id
                            ),
                        )
                    )
        return retval

    def get_objects(self):
        start = 0
        while True:
            chunk = self.get_objects_chunk(start, self.CHUNK_SIZE)
            if chunk == None:
                return
            yield chunk
            start += self.CHUNK_SIZE

    def process(self, **kwargs):
        logging.info("getting objects - %s", self.relationship_note)
        for chunk in self.get_objects():
            logging.info("got %d objects - %s", len(chunk), self.relationship_note)
            1 / 0
            self.do_process(chunk)

    def get_external_references(self, cve_id, cwe_id: str):
        return [
            dict(
                source_name="cve",
                external_id=cve_id,
                url="https://nvd.nist.gov/vuln/detail/" + cve_id,
            ),
            dict(
                source_name="cwe",
                external_id=cwe_id,
                url=f"http://cwe.mitre.org/data/definitions/{cwe_id.split('-', 1)[-1]}.html",
            ),
        ]
