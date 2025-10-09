from datetime import UTC, datetime, timedelta
import io
import zipfile
import json
import sqlite3
import os
import tempfile
import logging

import requests

from arango_cve_processor.tools.nvd import fetch_nvd_api

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)


class SwidTitleDB:
    _class_db = None
    archive_url = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip"
    api_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

    def __init__(self, zip_path=""):
        self.lastModified = ""
        self.db_path = tempfile.mktemp(prefix="acvep-swid-cpe_", suffix=".sqlite")
        self.conn = None
        zip_file = zip_path or self._download_zip()
        self._extract_swid_titles_to_sqlite(zip_file)
        self.conn = sqlite3.connect(self.db_path)
        self.cur = self.conn.cursor()

    @classmethod
    def get_db(cls):
        if not cls._class_db:
            cls._class_db = SwidTitleDB()
        return cls._class_db

    def _download_zip(self):
        logging.info("downloading cpe dictionary")
        resp = requests.get(self.archive_url)
        return io.BytesIO(resp.content)

    def _create_db(self):
        self.cur = self.conn.cursor()
        self.cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cpe_titles (
                swid TEXT PRIMARY KEY,
                title TEXT,
                deprecated INTEGER,
                created TEXT,
                modified TEXT,
                deprecates TEXT
            )
        """
        )
        self.conn.commit()

    def _insert_cpe_title(self, swid, title, deprecated, created, modified, deprecates):
        self.cur.execute(
            """
            INSERT OR REPLACE INTO cpe_titles (swid, title, deprecated, created, modified, deprecates)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (swid, title, int(deprecated), created, modified, json.dumps(deprecates)),
        )

    def _extract_swid_titles_to_sqlite(self, zip_file):
        # create a new connection for initial extract
        self.conn = sqlite3.connect(self.db_path)
        self._create_db()
        logging.info(f"Writing to {self.db_path}")
        total_count = 0
        with zipfile.ZipFile(zip_file, "r") as z:
            for filename in z.namelist():
                if not filename.endswith(".json"):
                    continue
                logging.info(f"Processing {filename}")
                with z.open(filename) as f:
                    data = json.load(f)
                    count = self.load_data(data)
                    total_count += count
        logging.info(
            f"wrote {total_count} entries from data-feed; lastModified={self.lastModified}"
        )
        self.conn.commit()

    def load_data(self, data: dict):
        count = 0
        for item in data.get("products", []):
            cpe = item["cpe"]
            swid = cpe.get("cpeNameId")
            titles = cpe.get("titles", [])
            title = titles[0].get("title")
            for t in titles:
                if t.get("lang") == "en":
                    title = t.get("title")
                    break
            if swid and title:
                count += 1
                lastModified = cpe.get("lastModified", "")
                self.lastModified = max(self.lastModified, lastModified)
                self._insert_cpe_title(
                    swid,
                    title,
                    cpe.get("deprecated", False),
                    cpe.get("created", ""),
                    lastModified,
                    cpe.get("deprecates", []),
                )

        return count

    def _lookup(self, swid):
        self.cur.execute(
            "SELECT title, deprecated, created, modified, deprecates FROM cpe_titles WHERE swid=?",
            (swid,),
        )
        row = self.cur.fetchone()
        if row:
            return dict(
                title=row[0],
                deprecated=bool(row[1]),
                created=row[2],
                modified=row[3],
                deprecates=json.loads(row[4]),
            )

    def lookup(self, swid):
        cpe = self._lookup(swid)
        if not cpe:
            self.refresh_from_api()
        return self._lookup(swid)

    def refresh_from_api(self):
        assert self.lastModified, "cache must already be populated"
        query = dict(
            lastModStartDate=self.lastModified,
            lastModEndDate=(datetime.now() + timedelta(1)).isoformat(),
        )
        total_count = 0
        for data in fetch_nvd_api(
            self.api_base_url, query
        ):
            count = self.load_data(data)
            logging.info(
                f"Added {count} entries from API; lastModified={self.lastModified}"
            )
            total_count += count
        return total_count

    def __del__(self):
        if self.conn:
            self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
