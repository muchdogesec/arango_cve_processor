  
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

        query_relationships = """
        FOR doc IN @@edge_collection
        FILTER doc._arango_cve_processor_note == @cve_cwe_note AND doc._is_latest AND doc._is_ref != true  
                AND (NOT @cve_ids OR doc.external_references[0].external_id IN @cve_ids) // filter --cve_id
        RETURN [doc.source_ref, doc.target_ref]
        """
        rels: dict[str, list[str]] = {}
        for source_ref, target_ref in self.arango.execute_raw_query(query_relationships, bind_vars={"@edge_collection": self.edge_collection, "cve_cwe_note": self.prev_note, 'cve_ids': self.cve_ids or None}, batch_size=self.BATCH_SIZE):
            source_rels = rels.setdefault(source_ref, [])
            source_rels.append(target_ref)

        query = """
LET cwe_capec_map = MERGE(
    FOR doc IN @@vertex_collection
    FILTER  doc.id IN FLATTEN(VALUES(@cve_cwe_map))
    RETURN {[doc.id]: doc.external_references[* FILTER CURRENT.source_name == @source_name]}
)

FOR doc IN @@vertex_collection
    FILTER doc.id IN KEYS(@cve_cwe_map) AND doc._is_latest  AND doc.created >= @created_min AND doc.modified >= @modified_min AND (NOT @cve_ids OR doc.name IN @cve_ids)
    LET capec_ids = FLATTEN(FOR cwe_id IN @cve_cwe_map[doc.id] RETURN cwe_capec_map[cwe_id])
    FILTER LENGTH(capec_ids) != 0
    RETURN MERGE(KEEP(doc, '_id', 'id', 'name', 'created', 'modified'), {external_references: capec_ids})
"""
        binds = {"@vertex_collection": self.collection, 'source_name': self.source_name, 'created_min': self.created_min, 'modified_min': self.modified_min, 'cve_ids': self.cve_ids or None}
        binds['cve_cwe_map'] = rels
        return self.arango.execute_raw_query(query, bind_vars=binds, batch_size=self.BATCH_SIZE)

    def get_external_references(self, cve_id: str, capec_id: str):
        return [
            dict(source_name='cve', external_id=cve_id, url="https://nvd.nist.gov/vuln/detail/"+cve_id),
            dict(source_name='capec', external_id=capec_id, url=f"https://capec.mitre.org/data/definitions/{capec_id.split('-', 1)[-1]}.html"),
        ]