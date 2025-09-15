import logging
from urllib.parse import urljoin
import  os
import requests



class STIXObjectRetriever:
    def __init__(self) -> None:
        self.api_root = os.environ['CTIBUTLER_BASE_URL'] + '/'
        self.api_key = os.environ.get('CTIBUTLER_API_KEY')
    
    def get_objects_by_external_ids(self, ids, type, key='objects', query_filter='id'):
        objects_map : dict[str, dict] = {}
        ids = list(set(ids))

        for chunked_ids in chunked(ids, 100):
            objects = self._retrieve_objects(urljoin(self.api_root, f"v1/{type}/objects/?{query_filter}={','.join(chunked_ids)}&sort={query_filter}_ascending"), key)
            objects_map.update(self.make_map(objects))
        return objects_map
    
    @staticmethod
    def make_map(objects):
        map = {}
        for obj in objects:
            refs = obj.get('external_references')
            if not refs:
                continue
            object_id = refs[0]['external_id']
            map[object_id] = obj
        return map

    
    def _retrieve_objects(self, endpoint, key='objects'):
        s = requests.Session()
        s.headers.update({
            "API-KEY": self.api_key,
        })
        data = []
        page = 1
        logging.info("fetching from: %s", endpoint)
        while True:
            resp = s.get(endpoint, params=dict(page=page, page_size=50))
            if resp.status_code not in [200, 404]:
                raise Exception("STIXObjectRetriever failed with HTTP status code: %d", resp.status_code)
            d = resp.json()
            if len(d[key]) == 0:
                break
            data.extend(d[key])
            page+=1
            if d['page_results_count'] < d['page_size']:
                break
        return data
   

def chunked(iterable, n):
    if not iterable:
        return []
    for i in range(0, len(iterable), n):
        yield iterable[i : i + n]