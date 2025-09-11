from dataclasses import dataclass
from datetime import datetime, date, timedelta
import io
import logging
import requests
import gzip
import csv
from pytz import timezone
from functools import lru_cache

logging.basicConfig(level=logging.INFO)
@dataclass
class EPSS:
    cve: str = ""
    date: str = None
    score: float = 0
    percentile: float = 0

class EPSSManager:
    _epss_data: dict[date, dict[str, EPSS]] = {}
    keep_old_data = False

    @classmethod
    def data(cls):
        if not cls._epss_data:
            cls.get_epss_data(cls.datenow())
        return cls._epss_data

    
    @classmethod
    def get_epss_data(cls, d: date|datetime=None):
        if not d:
            d = cls.datenow()
        if isinstance(d, datetime):
            d = d.date()
        return cls._get_epss_date(d)
    
    @classmethod
    @lru_cache(maxsize=30)
    def _get_epss_date(cls, d: date):
        if d in cls._epss_data:
            return cls._epss_data[d]
        d_str = d.strftime('%Y-%m-%d')
        url = "https://epss.cyentia.com/epss_scores-{}.csv.gz".format(d_str)
        logging.info(f'retrieving epss from {url}')
        resp = requests.get(url)
        csv_data = gzip.decompress(resp.content).decode()
        if not cls.keep_old_data:
            cls._epss_data = {}
        cls._epss_data[d] = dict(cls.parse_csv(csv_data, d_str))
        logging.info(f"Got {len(cls._epss_data[d])} EPSS data for {d_str}")

        return cls._epss_data[d]
        
    @staticmethod
    def parse_csv(csv_data, date_str):
        data = csv.DictReader(io.StringIO(csv_data), ["cve","epss","percentile"])
        for d in data:
            if not d['cve'].startswith('CVE-'):
                continue
            d.update(date=date_str, epss=float(d['epss']), percentile=float(d['percentile']))
            yield d['cve'], d

    @classmethod
    def get_data_for_cve(cls, cve, date=None):
        if not date:
            date = cls.datenow()
        try:
            data = cls.get_epss_data(date)
        except:
            return cls.get_data_for_cve(cve, date - timedelta(days=1))
        return data.get(cve)
    
    @classmethod
    def datenow(cls):
        resp = requests.get('https://api.first.org/data/v1/epss?limit=1')
        return datetime.strptime(resp.json()['data'][0]['date'], '%Y-%m-%d').date()