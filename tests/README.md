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

## TEST 5.0 Validate CVE -> KEV relationship (`cve-kev`)

Both documents in the following test have KEV references...

```shell
python3 -m unittest tests/test_05_00_cve_kev.py
```

## TEST 6.0 Test `cve-id` cli arg

```shell
python3 -m unittest tests/test_06_00_cve_cli_arg_cve_cwe.py
```

Runs with `cve-cwe` mode.

## TEST 6.1 Test `cve-id` cli arg

```shell
python3 -m unittest tests/test_06_01_cve_cli_arg_cve_capec.py
```

Runs with `cve-capec` mode.