import json
from pathlib import Path
import time
from typing import Any, Generator
from unittest.mock import patch
import pytest
from arango_cve_processor import config
from stix2arango.stix2arango.stix2arango import Stix2Arango
from stix2arango.services import ArangoDBService

from arango_cve_processor.tools.retriever import STIXObjectRetriever
from arango_cve_processor.tools.utils import create_indexes


@pytest.fixture(scope="session")
def session_processor():
    s2a = Stix2Arango(
        "test_acvep",
        "nvd_cve",
        file="",
        create_db=True,
        create_collection=True,
        host_url=config.ARANGODB_HOST_URL,
        username=config.ARANGODB_USERNAME,
        password=config.ARANGODB_PASSWORD,
        skip_default_indexes=True,
    )
    create_indexes(s2a.arango.db)
    yield s2a.arango


@pytest.fixture
def processor(session_processor: ArangoDBService):
    yield session_processor
    truncate(session_processor)


def truncate(session_processor):
    for c in ["nvd_cve_edge_collection", "nvd_cve_vertex_collection"]:
        session_processor.db.collection(c).truncate()


def new_getter(self, ids, type, query_filter=''):
        p = Path("tests/files/") / f"{type}-objects.json"
        return {
            k: v
            for k, v in STIXObjectRetriever.make_map(json.loads(p.read_text())).items()
            if k in ids
        }

    

@pytest.fixture
def patched_retriever(monkeypatch):
    monkeypatch.setattr(STIXObjectRetriever, "get_objects_by_external_ids", new_getter)

@pytest.fixture(scope='module')
def module_retriever():
    with patch.object(STIXObjectRetriever, "get_objects_by_external_ids", side_effect=new_getter, autospec=True) as patch_obj:
        yield patch_obj


@pytest.fixture(scope="module")
def acp_processor(session_processor: ArangoDBService):
    result = session_processor.db.collection("nvd_cve_vertex_collection").insert_many(
        json.loads(Path("tests/files/cves.json").read_text()),
        sync=True,
        return_new=True,
    )
    time.sleep(1)
    yield session_processor
    truncate(session_processor)
