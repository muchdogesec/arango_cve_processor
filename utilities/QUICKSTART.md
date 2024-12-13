1. import latest required data

In stix2arango run

```shell
python3 utilities/arango_cve_processor/insert_archive_cve.py \
	--database arango_cve_processor \
	--ignore_embedded_relationships True
```
