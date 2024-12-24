# Tests

## TEST 1.0 Validate CVE -> CWE relationship (`cve-cwe`)

```shell
python3 -m unittest tests/test_01_00_cve_cwe.py
```

Contains 3 CWE refs.

## TEST 1.1 Validate CVE -> CWE relationship (`cve-cwe`)

Test 1.0 must be run.

CVE-2019-16278 has CWE-404 added to it

```shell
python3 -m unittest tests/test_01_01_cve_cwe_update_1.py
```

## TEST 1.2 Validate CVE -> CWE relationship (`cve-cwe`)

Test 1.1 must be run.

All CWE references are removed from CVE-2019-16278

```shell
python3 -m unittest tests/test_01_02_cve_cwe_update_2.py
```

## TEST 2.0 Validate CVE -> CAPEC relationship (`cve-capec`)

TEST 1.0 ONLY MUST BE RUN -- RERUN IT BEFORE STARTING THIS TEST!

```shell
python3 -m unittest tests/test_02_00_cve_capec.py
```

Contains 14 CAPEC refs.

## TEST 3.0 Validate CVE -> ATT&CK relationship (`cve-attack`)

TEST 1.0 AND TEST 2.0 ONLY MUST BE RUN -- RERUN THEM BEFORE STARTING THIS TEST!

```shell
python3 -m unittest tests/test_03_00_cve_attack.py
```

Contains 14 CAPEC refs.

## TEST 4.0 Validate CVE -> EPSS relationship (`cve-epss`)

```shell
python3 -m unittest tests/test_04_00_cve_epss.py
```

## TEST 4.1 Validate CVE -> EPSS relationship updates (`cve-epss`)

Running test 4.0 again, 24 hours later, should update the object with another EPSS score for the date run

## TEST 5.0 Validate CVE -> KEV relationship (`cve-kev`)

Both documents in the following test have KEV references...

```shell
python3 -m unittest tests/test_05_00_cve_kev.py
```

## TEST 6.0 Test `cve_id` cli arg

```shell
python3 -m unittest tests/test_06_00_cve_cli_arg_cve_cwe.py
```

Runs with `cve-cwe` mode.

## TEST 6.1 Test `cve_id` cli arg

```shell
python3 -m unittest tests/test_06_01_cve_cli_arg_cve_kev.py
```

Runs with `cve-kev` mode.

## TEST 7.0 Test `modified_min` cli arg

```shell
python3 -m unittest tests/test_07_00_modified_min.py
```

modified min is 2022-01-01, should import only 1 object -- CVE-2024-7262 w/ 1 CWE


## TEST 8.0 Test `created_min` cli arg

```shell
python3 -m unittest tests/test_08_00_created_min.py
```

created min is 2022-01-01, should import only 1 object -- CVE-2024-7262 w/ 1 CWE

## TEST 9.0 Check ignore embedded relationships = false

```shell
python3 -m unittest tests/test_09_00_ignore_embedded_relationships_f.py
```

## TEST 10.0 Check ignore embedded relationships = true

```shell
python3 -m unittest tests/test_10_00_ignore_embedded_relationships_t.py
```

## TEST 11.0 Check cve_id flag = CVE-2024-7262 in cve-cwe mode (has CWE-22)

```shell
python3 -m unittest tests/test_11_00_cve_id_flag.py
```

## TEST 11.1 Check cve_id flag where multiple CVE IDs passed

All CVE IDs in bundle are passed;

```shell
python3 -m unittest tests/test_11_01_cve_id_multi_flag.py
```

