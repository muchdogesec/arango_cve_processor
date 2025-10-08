from datetime import UTC, datetime
import io
import zipfile
import json
import sqlite3
import os
import tempfile
import logging

import requests

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)


class SwidTitleDB:
    _date = None
    _class_db = None

    def __init__(self, zip_path=""):
        self.lastModified = ''
        self.db_path = tempfile.mktemp(prefix="acvep-swid-cpe_", suffix=".sqlite")
        self.conn = None
        zip_file = zip_path or self._download_zip()
        self._extract_swid_titles_to_sqlite(zip_file)
        self.conn = sqlite3.connect(self.db_path)
        self.cur = self.conn.cursor()

    @classmethod
    def get_db(cls):
        return cls._class_db
    
    @classmethod
    def refresh_cache(cls, last_modified):
        if not cls._class_db:
            cls._class_db = SwidTitleDB()
        if cls._class_db.lastModified < last_modified:
            logging.info("CPE cache is older than lastModified of cpematch, rebuilding...")
            cls._class_db = SwidTitleDB()
        return cls._class_db

    def _download_zip(self):
        logging.info("downloading cpe dictionary")
        resp = requests.get("https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip")
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
        count = 0
        with zipfile.ZipFile(zip_file, "r") as z:
            for filename in z.namelist():
                if not filename.endswith(".json"):
                    continue
                logging.info(f"Processing {filename}")
                with z.open(filename) as f:
                    data = json.load(f)
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
        logging.info(f"wrote {count} entries to db")
        self.conn.commit()

    def lookup(self, swid):
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

    def __del__(self):
        if self.conn:
            self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
