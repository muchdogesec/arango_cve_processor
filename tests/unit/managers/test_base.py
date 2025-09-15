from unittest.mock import MagicMock, call, patch

import pytest
from arango_cve_processor.managers.base_manager import STIXRelationManager
from arango_cve_processor.tools.retriever import STIXObjectRetriever
from tests.utils import remove_volatile_keys


def test_create_relationship():
    with patch(
        "arango_cve_processor.tools.utils.create_relationship"
    ) as mock_create_rel:
        STIXRelationManager.create_relationship(
            "source",
            "tref",
            "rtype",
            "descr",
            relationship_id="r_id",
            is_ref="is_ref",
            external_references="ext_ref",
        )
        STIXRelationManager.create_relationship("source", "tref", "rtype", "descr")
        mock_create_rel.assert_has_calls(
            [
                call(
                    "source",
                    "tref",
                    "rtype",
                    "descr",
                    relationship_id="r_id",
                    is_ref="is_ref",
                    external_references="ext_ref",
                    relationship_note="stix-relation-manager",
                ),
                call(
                    "source",
                    "tref",
                    "rtype",
                    "descr",
                    relationship_id=None,
                    is_ref=False,
                    external_references=None,
                    relationship_note="stix-relation-manager",
                ),
            ]
        )


def test_upload_vertex_objects(processor):
    manager = STIXRelationManager(processor)
    manager.upload_vertex_data(
        [
            {
                "id": "stix-id",
                "type": "weakness",
            },
            {
                "id": "stix-id2",
                "type": "stix-obj",
            },
        ]
    )
    data = remove_volatile_keys(
        list(processor.db.collection(manager.vertex_collection).all()),
        extra_keys=["_key", "_id"],
    )
    assert data == [
        {
            "id": "stix-id",
            "type": "weakness",
            "_arango_cve_processor_note": "stix-relation-manager",
            "_record_md5_hash": "4488a77bc8870bb78e44462b3b3aeb96",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
        {
            "id": "stix-id2",
            "type": "stix-obj",
            "_arango_cve_processor_note": "stix-relation-manager",
            "_record_md5_hash": "37a99f3d1a8775bfd6e45d3cc15bac06",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
    ]


def test_upload_edge_objects(processor):
    manager = STIXRelationManager(processor)
    input_edges = [
        {
            "source_ref": "src1",
            "target_ref": "tgt1",
            "type": "link",
            "_from": "vertices/src1+stat",
            "id": "relationship-1",
            "_key": "ex-key1",
        },
        {
            "source_ref": "src2",
            "target_ref": "tgt2",
            "type": "link",
            "id": "relationship-2",
            "_key": "ex-key2",
        },
    ]
    manager.get_edge_ids = MagicMock(
        return_value={
            "src1": "vertices/src1",
            "tgt1": "vertices/tgt1",
            "src2": "vertices/src2",
            "tgt2": "vertices/tgt2",
        }
    )

    with patch.object(
        type(processor),
        "insert_several_objects_chunked",
        side_effect=processor.insert_several_objects_chunked,
    ) as mock_insert:
        manager.upload_edge_data(input_edges)

    manager.get_edge_ids.assert_called_once_with(
        ["tgt1", "tgt2", "src2"], "nvd_cve_vertex_collection"
    )

    data = remove_volatile_keys(
        list(processor.db.collection(manager.edge_collection).all())
    )
    assert data == [
        {
            "_key": "ex-key1",
            "_id": "nvd_cve_edge_collection/ex-key1",
            "_from": "vertices/src1+stat",
            "_to": "vertices/tgt1",
            "source_ref": "src1",
            "target_ref": "tgt1",
            "type": "link",
            "id": "relationship-1",
            "_record_md5_hash": "6ba0c5ab1ab937b38130359cf3d73523",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
        {
            "_key": "ex-key2",
            "_id": "nvd_cve_edge_collection/ex-key2",
            "_from": "vertices/src2",
            "_to": "vertices/tgt2",
            "source_ref": "src2",
            "target_ref": "tgt2",
            "type": "link",
            "id": "relationship-2",
            "_record_md5_hash": "086bd2cb8572c2e3b8548e0fd79108fa",
            "_is_latest": True,
            "_taxii": {"last": True, "first": True, "visible": True},
        },
    ]


def test_get_edge_ids(processor):
    manager = STIXRelationManager(processor)
    input_objects = [
        {
            "type": "link",
            "id": "link-1",
            "_key": "ex-key1",
            "modified": "9",
        },
        {
            "type": "no-link",
            "id": "no-link-2",
            "_key": "ex-key2",
            "modified": "2",
        },
    ]
    manager.upload_vertex_data(input_objects)

    assert manager.get_edge_ids(["link-1", "no-link-2"], manager.vertex_collection) == {
        "link-1": "nvd_cve_vertex_collection/ex-key1",
        "no-link-2": "nvd_cve_vertex_collection/ex-key2",
    }
    assert manager.get_edge_ids(["link-1", "no-link-2"]) == {
        "link-1": "nvd_cve_vertex_collection/ex-key1",
        "no-link-2": "nvd_cve_vertex_collection/ex-key2",
    }

def test_process(processor):
    manager = STIXRelationManager(processor)
    with (
        patch.object(
            type(manager),
            "do_process",
        ) as mock_do_process,
        patch.object(type(manager), "get_object_chunks") as mock_get_objects,
    ):
        mock_get_objects.return_value = (
            ["objects-1"],
            [],
            None,
            ["objects-2"],
            ["objects3"],
        )
        manager.process()
        mock_do_process.assert_has_calls(
            [call(["objects-1"]), call(["objects-2"]), call(["objects3"])]
        )


def test_do_process(processor):
    manager = STIXRelationManager(processor)
    objects = [
        dict(type="weakness", id="weakness-1"),
        dict(type="relationship", id="rel-1", source_ref="s1", target_ref="s2"),
    ]
    with (
        patch.object(
            type(manager),
            "relate_single",
        ) as mock_relate,
        patch.object(
            type(manager),
            "upload_vertex_data",
        ) as mock_upload_vertex,
        patch.object(
            type(manager),
            "upload_edge_data",
        ) as mock_upload_edge,
    ):
        mock_relate.side_effect = lambda x: [x]
        extra = dict(type="link", id="link1")
        manager.do_process(objects, extra_uploads=[extra])
        mock_relate.assert_has_calls([call(obj) for obj in objects])
        mock_upload_vertex.assert_called_once_with([extra, objects[0]])
        mock_upload_edge.assert_called_once_with([objects[1]])
