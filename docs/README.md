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

### Updating SROs created by arango_cve_processor on subsequent runs

This script is designed to run on demand. On each run, it will create new relationships or update existing relationships based on changes to imported data (using stix2arango).

CVE created / modified dates are used in all SROs created.

arango_cve_processor will always filter the results to `_is_latest==true` before applying any updates. This means older versions of objects will not be considered when generating relationships.

stix2arango (used in the backend) will also generate a `_record_md5_hash` property of the relationships created each time. If the `_record_md5_hash` for the `id` already exists in the DB at insert time, then the record will be skipped (as no update detected).

Each time an update is detected, arango_cve_processor will mark previously created SROs for the object as `_is_latest=false` and then recreate the SROs (but ensure the `_record_created` time matches old objects updated as is latest is false, but update the `_record_modified` time accordingly to match the update time).

Similarly, when a record is removed from a source object (e.g CWE reference removed from a CVE object), the object removed between updates is marked at `_is_latest=false`, but no new object recreated for it (because it no longer exist in latest version of source object)