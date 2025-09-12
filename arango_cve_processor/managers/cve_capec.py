from arango_cve_processor.managers.cve_cwe import CveCwe


class CveCapec(CveCwe, relationship_note="cve-capec"):
    DESCRIPTION = """
    Run CVE <-> CAPEC relationships, requires cve-cwe
    """
    priority = CveCwe.priority + 1
    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"

    ctibutler_path = "capec"
    ctibutler_query = "capec_id"
    source_name = "capec"

    ## used in query
    prev_note = CveCwe.relationship_note

    def get_single_chunk(self, start=0, batch_size=10_000):
        v_query = """
    FOR doc IN @@vertex_collection OPTIONS {indexHint: "acvep_search", forceIndexHint: true}
    FILTER doc.type == 'vulnerability'
                AND doc._is_latest == TRUE
                    AND doc.created >= @created_min AND doc.modified >= @modified_min 
                        AND (NOT @cve_ids OR doc.name IN @cve_ids)
    LIMIT @start, @batch_size
    RETURN KEEP(doc, '_id', 'id', 'name', 'created', 'modified')
        """
        v_binds = {
            "@vertex_collection": self.collection,
            "created_min": self.created_min,
            "modified_min": self.modified_min,
            "cve_ids": self.cve_ids or None,
            "start": start,
            "batch_size": batch_size,
        }
        results = self.arango.execute_raw_query(v_query, bind_vars=v_binds)
        vuln_map = {d["id"]: d for d in results}
        if not vuln_map:
            return None
        rel_query = """
        FOR doc IN @@edge_collection // uses acvep-capec-attack
        FILTER doc._arango_cve_processor_note == @cve_cwe_note
                AND doc.source_ref IN @vuln_ids
                AND doc._is_latest == TRUE AND doc._is_ref != true 
        RETURN [doc.source_ref, doc.target_ref]
        """
        secondary_relationships = self.arango.execute_raw_query(
            rel_query,
            bind_vars={
                "@edge_collection": self.edge_collection,
                "cve_cwe_note": self.prev_note,
                "vuln_ids": list(vuln_map),
            },
        )
        weakness_ids = [d[1] for d in secondary_relationships]
        query3 = """
        FOR doc IN @@vertex_collection //uses acvep_id
        FILTER doc.id IN @weakness_ids
        LET refs = doc.external_references[* FILTER CURRENT.source_name == @source_name]
        FILTER LENGTH(refs) != 0
        RETURN [doc.id,  refs]
        """
        v_binds = {
            "@vertex_collection": self.collection,
            "source_name": self.source_name,
            "weakness_ids": weakness_ids,
        }
        results3 = dict(self.arango.execute_raw_query(query3, bind_vars=v_binds))

        for vuln_id, weakness_id in secondary_relationships:
            if refs := results3.get(weakness_id):
                vuln_map[vuln_id].setdefault("external_references", [])
                vuln_map[vuln_id]["external_references"].extend(refs)
        return [v for v in vuln_map.values() if v.get("external_references")]

    def get_external_references(self, cve_id: str, capec_id: str):
        return [
            dict(
                source_name="cve",
                external_id=cve_id,
                url="https://nvd.nist.gov/vuln/detail/" + cve_id,
            ),
            dict(
                source_name="capec",
                external_id=capec_id,
                url=f"https://capec.mitre.org/data/definitions/{capec_id.split('-', 1)[-1]}.html",
            ),
        ]
