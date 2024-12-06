## The logic

### Default STIX objects

To support the generation of relationship, ACVEP checks the following objects exist in the database, and if they do not adds the following objects to each vertex collection related to the import.

The following objects are automatically inserted (if they do not exist) to each vertex collection on script run

* Identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/arango_cve_processor.json
* Marking Definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/arango_cve_processor.json

When imported these objects always have the following Arango custom properties added to them:

* `_arango_cve_processor_note`: `automatically imported object at script runtime`
* `_record_created`: time of collection creation
* `_record_modified`: time of collection creation
* `_record_md5_hash`: hash of object
* `_is_latest`: `true`

They are added as follows;

```sql
LET default_objects = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_arango_cve_processor_note": "automatically imported object at script runtime",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "<STIX DEFAULT OBJECT>"
    }
]
FOR default_object IN default_objects
INSERT default_object INTO <SOURCE>_vertex_collection
```

### Imported objects

CWE, ATT&CK and CAPEC objects are imported from CTI Butler. These are added to the DB with the following metadata;

```sql
LET default_objects = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_arango_cve_processor_note": "<SCRIPT MODE>",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "<STIX DEFAULT OBJECT>"
    }
]
FOR default_object IN default_objects
INSERT default_object INTO nvd_cve_vertex_collection
```

### How objects are joined

All SROs created (wether from local or imported source objects) to the respective ArangoDB Collection with the following data;

```sql
LET relationships = [
    {
        "_key": "<THE OBJECTS STIX ID>",
        "_from": "<COLLECTION NAME>/<OBJECTS SOURCE_REF>",
        "_to": "<COLLECTION NAME>/<OBJECTS TARGET_REF>",
        "_arango_cti_processor_note": "<RELATIONSHIP LINK>",
        "_record_created": "<DATETIME OBJECT WAS INSERTED IN DB>",
        "_record_modified": "<DATETIME OBJECT WAS LAST MODIFIED IN DB>",
        "_record_md5_hash": "<HASH OF OBJECT>",
        "_is_latest": true,
        "_is_ref": false,
        "<STIX Relationship OBJECT PROPERTIES>"
    }
]
FOR relationship IN relationships
INSERT relationship INTO <SOURCE>_edge_collection
```

Where:

* `_key`: for new objects, the ID of the STIX object, e.g. `relationship--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f`
* `_arango_cve_processor_note`: Used to identify objects processed by Arango CTI Processor. Shows the link between objects (e.g `cve-attack`)
* `_record_created`: the datetime the object was inserted into the database (e.g. `2020-01-01T01:00:00.000Z`)
* `_record_modified`: the datetime the object was last updated (e.g. `2020-01-01T01:00:00.000Z`). Note, for new objects this always matches the `_record_created` time
* `_record_md5_hash` is an MD5 hash of the STIX objects and the `_arango_cti_processor_note` field. This is used to detect updates to objects.
* `is_latest`: boolean, for newly inserted objects will always be `true`. See update logic to understand why.
* `_is_ref`: boolean, denotes if object was created by a ref or refs property insides a STIX object (see refs section). Will always be `false` for created SROs.

### Updating SROs created by arango_cti_processor on subsequent runs

This script is designed to run on demand. On each run, it will create new relationships or update existing relationships based on changes to imported data (using stix2arango).

arango_cti_processor will always filter the results to `_is_latest==true` before applying any updates. This means older versions of objects will not be considered when generating relationships.

stix2arango (used in the backend) will also generate a `_record_md5_hash` property of the relationships created each time. If the `_record_md5_hash` for the `id` already exists in the DB at insert time, then the record will be skipped (as no update detected).

Each time an update is detected, arango_cti_processor will mark previously created SROs for the object as `_is_latest=false` and then recreate the SROs (but ensure the `_record_created` time matches old objects updated as is latest is false, but update the `_record_modified` time accordingly to match the update time).

Similarly, when a record is removed from a source object (e.g ATT&CK reference removed from a CAPEC object), the object removed between updates is marked at `_is_latest=false`, but no new object recreated for it (because it no longer exist in latest version of source object)