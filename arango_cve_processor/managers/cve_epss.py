from datetime import datetime, timedelta, timezone, date
import logging
import time
import uuid

from arango_cve_processor import config
from arango_cve_processor.tools.epss import EPSSManager
from arango_cve_processor.tools.utils import chunked_tqdm, stix2python
from arango_cve_processor.managers.base_manager import STIXRelationManager
from stix2 import Vulnerability, Report


class CveEpssManager(STIXRelationManager, relationship_note="cve-epss"):
    DESCRIPTION = """
    Creates EPSS report objects for CVEs
    """
    edge_collection = "nvd_cve_edge_collection"
    vertex_collection = "nvd_cve_vertex_collection"
    default_objects = [
        "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/report-epss-scoring.json"
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.update_objects = []
        self.epss_date = EPSSManager.datenow()

    def get_object_chunks(self, **kwargs):
        limit = 20_000
        query = """
  FOR doc IN @@collection OPTIONS {indexHint: "acvep_search", forceIndexHint: true}
  FILTER doc._arango_cve_processor_note == @relationship_note
  FILTER doc.name IN @cve_ids AND doc._is_latest == TRUE
  LET cve_name = doc.external_references[0].external_id
  RETURN [cve_name, KEEP(doc, '_key', 'x_epss', '_record_created')]
        """
        reports = dict(
            self.get_objects_from_db(
                query,
                limit,
                dict(
                    relationship_note=self.relationship_note,
                    cve_ids=[f"EPSS Scores: {cve_id}" for cve_id in self.cve_ids],
                ),
            )
        )
        cve_query = (
            query
        ) = """
  FOR doc IN @@collection OPTIONS {indexHint: "acvep_search", forceIndexHint: true}
  FILTER doc.type == 'vulnerability'
  FILTER doc.name IN @cve_ids
  FILTER doc._is_latest == TRUE AND doc.created >= @created_min AND doc.modified >= @modified_min 
  RETURN [doc.name, KEEP(doc, 'id', '_record_created', 'created', '_key')]
        """
        cves: list[tuple[str, dict]] = self.get_objects_from_db(
            cve_query,
            limit,
            dict(
                cve_ids=self.cve_ids,
                created_min=self.created_min,
                modified_min=self.modified_min,
            ),
        )

        objects = []
        for cve_name, cve in cves:
            cve.update(name=cve_name, epss=reports.get(cve_name))
            objects.append(cve)
        return [ objects ]

    def process(self, **kwargs):
        self.epss_data_source = EPSSManager.get_epss_data(self.epss_date)
        if self.cve_ids:
            self.cve_ids = list(set(self.epss_data_source).intersection(self.cve_ids))
        else:
            self.cve_ids = list(self.epss_data_source)
        return super().process(**kwargs)

    def get_objects_from_db(self, query, limit, binds={}):
        objects = []
        t0 = time.time()
        for cve_ids_chunk in chunked_tqdm(
            binds.pop("cve_ids", []), limit, "get-cve-and-existing-epss-reports"
        ):
            t = time.time()
            ret = self.arango.execute_raw_query(
                query,
                bind_vars={
                    "@collection": self.collection,
                    "cve_ids": cve_ids_chunk,
                    **binds,
                },
                memory_limit=100 * 1024**2,
            )
            objects.extend(ret)
        logging.debug(f"total_time = {time.time() - t0}")
        return objects

    def relate_single(self, cve_object):
        todays_report = parse_cve_epss_report(cve_object, self.epss_date)
        if not todays_report:
            return []
        if cve_object["epss"]:
            all_epss = sorted(
                cve_object["epss"]["x_epss"] + todays_report["x_epss"],
                key=lambda x: x["date"],
                reverse=True,
            )
            if len(set(map(lambda x: x["date"], all_epss))) != len(
                cve_object["epss"]["x_epss"]
            ):
                latest_epss: dict = all_epss[0].copy()
                self.update_objects.extend(
                    [
                        {
                            **cve_object["epss"],
                            "x_epss": all_epss,
                            "_record_modified": datetime.now(timezone.utc).strftime(
                                "%Y-%m-%dT%H:%M:%S.%fZ"
                            ),
                            "modified": latest_epss["date"] + "T00:00:00.000Z",
                            "_arango_cve_processor_note": self.relationship_note,
                        },
                        {
                            "_key": cve_object["_key"],
                            "_acvep_epss": latest_epss,
                        },
                    ]
                )
            return []
        else:
            return [stix2python(todays_report)]

    def upload_vertex_data(self, objects):
        logging.info("updating %d existing reports", len(self.update_objects))
        self.arango.db.collection(self.vertex_collection).update_many(
            self.update_objects
        )
        return super().upload_vertex_data(objects)


class CveEpssBackfillManager(CveEpssManager, relationship_note="cve-epss-backfill"):
    DESCRIPTION = """
    Creates EPSS report objects for CVEs. Starting from start date and stopping at end date 
    """

    def __init__(self, processor, start_date, end_date, *args, **kwargs):
        self.processor = processor
        self.args = args
        self.kwargs = kwargs
        self.start_date = start_date
        self.end_date = end_date

    def process(self, **kwargs):
        start_date = self.start_date
        end_date = self.end_date or EPSSManager.datenow()
        for day, date in date_range(start_date, end_date):
            logging.info(
                f"Running CVE <-> EPSS Backfill for day {day}, date: {date.isoformat()}"
            )
            logging.info("================================")
            rmanager = CveEpssManager(self.processor, *self.args, **self.kwargs)
            rmanager.epss_date = date
            rmanager.process(**kwargs)


def date_range(start_date: date, end_date: date):
    """Yield dates from start_date to end_date inclusive."""
    total_days = (end_date - start_date).days + 1
    for n in range(total_days):
        yield f"{n+1} of {total_days}", (start_date + timedelta(days=n))


def parse_cve_epss_report(vulnerability: Vulnerability, epss_date=None):
    try:
        cve_id = vulnerability.get("name")
        epss_data = EPSSManager.get_data_for_cve(cve_id, date=epss_date)
        content = f"EPSS Scores: {cve_id}"

        if epss_data:
            epss_data = [epss_data]
        else:
            epss_data = []

        modified = None
        if epss_data:
            modified = datetime.strptime(epss_data[-1]["date"], "%Y-%m-%d").date()

        return Report(
            id="report--" + str(uuid.uuid5(config.namespace, content)),
            created=vulnerability["created"],
            modified=modified,
            published=vulnerability["created"],
            name=content,
            x_epss=epss_data,
            object_refs=[
                vulnerability["id"],
            ],
            extensions={
                "extension-definition--efd26d23-d37d-5cf2-ac95-a101e46ce11d": {
                    "extension_type": "toplevel-property-extension"
                }
            },
            object_marking_refs=config.OBJECT_MARKING_REFS,
            created_by_ref=config.IDENTITY_REF,
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                },
                {
                    "source_name": "arango_cve_processor",
                    "external_id": "cve-epss",
                },
            ],
            labels=["epss"],
        )
    except:
        logging.error("get epss for %s failed", vulnerability.get("name"))
        return []
