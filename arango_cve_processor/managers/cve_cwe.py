import itertools
import logging
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.managers.base_manager import STIXRelationManager


class CveCwe(STIXRelationManager, relationship_note="cve-cwe"):
    DESCRIPTION = """
    Run CVE <-> CWE relationships
    """
    priority = 0
    relationship_type = 'related-to'

    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"

    ctibutler_path = "cwe"
    ctibutler_query = "cwe_id"
    source_name = "cwe"
    CHUNK_SIZE = 20_000

    def get_single_chunk(self, start, batch_size):
        query = """
        FOR doc IN @@collection OPTIONS {indexHint: "acvep_search", forceIndexHint: true}
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

    def do_process(self, objects, extra_uploads=...):
        logging.info("relating %s (%s)", self.relationship_note, self.ctibutler_path)
        cwe_ids = set()
        for cve in objects:
            for ref in cve["external_references"]:
                if ref and ref["source_name"] == self.source_name:
                    cwe_ids.add(ref["external_id"])
        self.all_external_objects = STIXObjectRetriever().get_objects_by_external_ids(
            list(cwe_ids), self.ctibutler_path, query_filter=self.ctibutler_query
        )
        retval = list(self.all_external_objects.values())
        return super().do_process(objects, extra_uploads=retval)

    def relate_single(self, cve):
        retval = []
        cve_id = cve["name"]
        for ext_id in [
            ref["external_id"]
            for ref in cve.get("external_references", [])
            if ref and ref["source_name"] == self.source_name
        ]:
            external_object = self.all_external_objects.get(ext_id)
            if not external_object:
                continue
            retval.append(
                self.create_relationship(
                    external_object["id"],
                    cve["id"],
                    relationship_type=self.relationship_type,
                    description=f"{cve_id} is exploited using {ext_id}",
                    external_references=self.get_external_references(
                        cve_id, external_object["external_references"][0]
                    ),
                    created=cve["created"],
                    modified=cve["modified"],
                    _to=cve["_id"],
                )
            )
        return retval

    def get_object_chunks(self):
        start = 0
        while True:
            chunk = self.get_single_chunk(start, self.CHUNK_SIZE)
            if chunk == None:
                return
            yield chunk
            start += self.CHUNK_SIZE

    def get_external_references(self, cve_id, cwe_ref):
        return [
            dict(
                source_name="cve",
                external_id=cve_id,
                url="https://nvd.nist.gov/vuln/detail/" + cve_id,
            ),
            cwe_ref,
        ]
