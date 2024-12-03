
import logging
from arango_cve_processor.tools.cpe_match import fetch_cpe_matches
from .base_manager import STIXRelationManager


class CveCpeManager(STIXRelationManager, relationship_note='cve-cpe'):
    edge_collection = 'nvd_cve_edge_collection'
    vertex_collection = 'nvd_cve_vertex_collection'
    def get_objects(self, **kwargs):
        query = """
        FOR doc IN @@collection
        FILTER doc._is_latest AND doc.type == 'indicator'
        RETURN KEEP(doc, '_id', 'id', 'x_cpe', 'name')
        """
        return self.arango.execute_raw_query(query, bind_vars={'@collection': self.collection})
    
    def relate_single(self, object):
        data : dict = object
        try:
            objects = []
            criteria_ids = {}
            x_cpes = data.get('x_cpes', {})

            for vv in x_cpes.get('vulnerable', []):
                criteria_ids[vv['matchCriteriaId']] = True
            for vv in x_cpes.get('not_vulnerable', []):
                criteria_ids[vv['matchCriteriaId']] = False
            cpe_names = fetch_cpe_matches(data['name'], criteria_ids)

            results = self.arango.execute_raw_query(
                "FOR doc IN @@collection FILTER doc.cpe IN @cpe_names RETURN KEEP(doc, 'id', 'name', 'cpe', '_id')", bind_vars={
                'cpe_names': list(cpe_names),
                '@collection':"nvd_cpe_vertex_collection",
            })

            for result in results:
                rel = self.create_relationship(
                    data,
                    result['id'],
                    relationship_type="pattern-contains",
                    description=f"{data['name']} pattern contains {result['name']} ({result['cpe']})",
                )
                objects.append(rel)
                if cpe_names[result["cpe"]]:
                    rel2 = self.create_relationship(
                        data,
                        result['id'],
                        relationship_type="is-vulnerable",
                        description=f"{data['name']} is vulnerable {result['name']} ({result['cpe']})",
                    )
                    objects.append(rel2)

        except Exception as e:
            logging.exception(e)
        return objects

