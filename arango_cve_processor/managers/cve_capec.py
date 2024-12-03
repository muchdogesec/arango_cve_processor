  
from .cve_cwe import CveCwe


class CveCapec(CveCwe, relationship_note = 'cve-capec'):
    priority = CveCwe.priority + 1
    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"
    

    ctibutler_path = 'capec'
    ctibutler_query = 'capec_id'
    source_name = 'capec'

    ## used in query
    prev_note = CveCwe.relationship_note


    def get_objects(self, **kwargs):
        query = """
LET cve_cwe_map = MERGE(
    FOR doc IN @@edge_collection
    FILTER doc._arango_cve_processor_note == @cve_cwe_note AND doc._is_latest
    COLLECT source_ref = doc.source_ref INTO cve_cwe
    FILTER LENGTH(cve_cwe[*].doc.target_ref) != 0
    RETURN {[source_ref]: cve_cwe[*].doc.target_ref}
)

LET cwe_capec_map = MERGE(
    FOR doc IN @@vertex_collection
    FILTER  doc.id IN FLATTEN(VALUES(cve_cwe_map))
    RETURN {[doc.id]: doc.external_references[* FILTER CURRENT.source_name == @source_name]}
)

FOR doc IN @@vertex_collection
    FILTER doc.id IN KEYS(cve_cwe_map) AND doc._is_latest
    LET capec_ids = FLATTEN(FOR cwe_id IN cve_cwe_map[doc.id] RETURN cwe_capec_map[cwe_id])
    RETURN MERGE(KEEP(doc, '_id', 'id', 'name', 'created', 'modified'), {external_references: capec_ids})
"""
        return self.arango.execute_raw_query(query, bind_vars={"@vertex_collection": self.collection, "@edge_collection": self.edge_collection, "cve_cwe_note": self.prev_note, 'source_name': self.source_name})
 