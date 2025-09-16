from arango_cve_processor.tools.utils import import_default_objects


def test_import_default_objects(processor):
    import_default_objects(
        processor,
        [
            "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/report-epss-scoring.json"
        ],
    )
    query = """
    FOR d IN nvd_cve_vertex_collection
    FILTER d._arango_cve_processor_note == "automatically imported object at script runtime"
    RETURN d.id
    """
    stix_ids = processor.execute_raw_query(query)
    assert stix_ids == [
        "extension-definition--f80cce10-5ac0-58d1-9e7e-b4ed0cc4dbb9",
        "identity--152ecfe1-5015-522b-97e4-86b60c57036d",
        "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
    ]
