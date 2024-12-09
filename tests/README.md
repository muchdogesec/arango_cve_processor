

## TEST 1.0 Validate CVE -> CWE relationship (`cve-cwe`)

```shell
python3 -m unittest tests/test_01_00_cve_cwe.py
```

Contains 3 CWE refs.

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


## TEST 5.0 Validate CVE -> KEV relationship (`cve-kev`)

Both documents in the following test have KEV references...

```shell
python3 -m unittest tests/test_05_00_cve_kev.py
```