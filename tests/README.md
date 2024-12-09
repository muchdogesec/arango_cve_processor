

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

No


## TEST 5.0 Validate CVE -> KEV relationship (`cve-kev`)

Both documents in the following test have KEV references...

```shell
python3 -m unittest tests/test_05_00_cve_kev.py
```