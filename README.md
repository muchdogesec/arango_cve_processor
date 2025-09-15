# Arango CVE Processor

## Before you get started

Arango CVE Processor is built into [Vulmatch](https://github.com/muchdogesec/vulmatch) which also handles the download of CVE objects (what you need for ACVEP to work). As such, [Vulmatch](https://github.com/muchdogesec/vulmatch) is probably better suited to what you're looking for.

## tl;dr

![](docs/arango_cve_processor.png)

A small script that enriches CVEs to other sources with all data stored as STIX 2.1 objects.

[![arango_cve_processor](https://img.youtube.com/vi/J_LbAzoUpd4/0.jpg)](https://www.youtube.com/watch?v=J_LbAzoUpd4)

[Watch the demo](https://www.youtube.com/watch?v=J_LbAzoUpd4).

## Overview

Here at DOGESEC we work with a lot of CVE data across our products. [cve2stix](https://github.com/muchdogesec/cve2stix) generates core STIX 2.1 Vulnerability objects from CVE data.

However, we have lots of other sources (EPSS, KEV, ATT&CK...) that we want to enrich this data with.

We built Arango CVE Processor to handle the generation and maintenance of these enrichments.

In short, Arango CVE Processor is a script that;

1. reads the ingested CVE STIX data in ArangoDB
2. creates STIX objects to represent the relationships between CVE and other datasets

## Usage

### Install the script

```shell
# clone the latest code
git clone https://github.com/muchdogesec/arango_cve_processor
# create a venv
cd arango_cve_processor
python3 -m venv arango_cve_processor-venv
source arango_cve_processor-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
````

### Configuration options

Arango CVE Processor has various settings that are defined in an `.env` file.

To create a template for the file:

```shell
cp .env.example .env
```

To see more information about how to set the variables, and what they do, read the `.env.markdown` file.

### Run

```shell
python3 arango_cve_processor.py \
    MODE \
    --
    MODE OPTIONS
```

The following modes are available;

* `cve-cwe`
  * links vulnerability objects to CWE objects
* `cve-capec` (relies on `cve-cwe` run first)
  * links vulnerability objects to CAPEC objects
* `cve-attack` (relies on `cve-capec` run first)
  * links vulnerability objects to ATT&CK objects
* `cve-epss`
  * creates/updates report objects linked to CVE representing one of more EPSS score for the day run
* `cve-epss-backfill`
  * creates/updates report objects linked to CVE representing one of more EPSS score for the time range run
* `cve-kev` (relies on `cve-cwe` run first)
  * creates/updates report objects linked to CVE representing CISA KEV data
* `cve-vulncheck-kev` (relies on `cve-cwe` run first)
  * creates/updates report objects linked to CVE representing Vulncheck KEV data
* `cpematch`
  * creates/updates grouping objects (and linked software objects) representing CPE Matches tied to CPEs.

All modes have varying options, however, the following are available in all modes

* `--database` (required): the arangoDB database name where the objects you want to link are found. It must contain the collections `nvd_cve_vertex_collection` and `nvd_cve_edge_collection`
* `--ignore_embedded_relationships` (optional, boolean). Default is `false`. if `true` passed, this will stop any embedded relationships from being generated. This is a stix2arango feature where STIX SROs will also be created for `_ref` and `_refs` properties inside each object (e.g. if `_ref` property = `identity--1234` and SRO between the object with the `_ref` property and `identity--1234` will be created). See stix2arango docs for more detail if required, essentially this a wrapper for the same `--ignore_embedded_relationships` setting implemented by stix2arango
* `--ignore_embedded_relationships_sro` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SRO objects (`type` = `relationship`). Default is `false`
* `--ignore_embedded_relationships_smo` (optional): boolean, if `true` passed, will stop any embedded relationships from being generated from SMO objects (`type` = `marking-definition`, `extension-definition`, `language-content`). Default is `false`

To see the options available for each mode you can run with the help flag (`-h`), e.g.,

```shell
python3 arango_cve_processor.py \
  cve-epss -h
```

```shell
python3 arango_cve_processor.py \
  cve-cwe -h
```

### Examples

Process CVE -> CWE relationships for all CVEs modified after `2024-02-01`

```shell
python3 arango_cve_processor.py \
  cve-cwe \
  --database vulmatch_database \
  --modified_min 2024-02-01 \
  --ignore_embedded_relationships true \
  --ignore_embedded_relationships_sro true \
  --ignore_embedded_relationships_smo true
```

Get all EPSS scores for CVEs for each day in 2024

```shell
python3 arango_cve_processor.py \
  cve-epss \
  --database vulmatch_database \
  --start_date 2024-01-01 \
  --end_date 2024-12-31 \
  --ignore_embedded_relationships true \
  --ignore_embedded_relationships_sro true \
  --ignore_embedded_relationships_smo true
```

Update all CPE Matches modified after `2024-02-01`

```shell
python3 arango_cve_processor.py \
  cpematch \
  --database vulmatch_database \
  --updated_after 2024-02-01 \
  --ignore_embedded_relationships true \
  --ignore_embedded_relationships_sro true \
  --ignore_embedded_relationships_smo true
```

## Backfilling data

[stix2arango contains a set of utility scripts that can be used to backfill all the datasources required for this test](https://github.com/muchdogesec/stix2arango/tree/main/utilities).

## How it works

If you would like to know how the logic of this script works in detail, please consult the `/docs` directory.

## Useful supporting tools

* To generate STIX 2.1 extensions: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* STIX 2.1 specifications for objects: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [ArangoDB docs](https://www.arangodb.com/docs/stable/)

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## License

[Apache 2.0](/LICENSE).