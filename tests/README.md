

## TEST 1.0 Validate CVE -> CWE relationship (`cve-cwe`)

```shell
python3 -m unittest tests/test_01_00_cve_cwe.py
```



## TEST 2.0 Validate CVE -> CAPEC relationship (`cve-cwe`)

First run test 1.

```shell
python3 -m unittest tests/test_01_00_cve_cwe.py
```

No


## TEST 5.0 Validate CVE -> KEV relationship (`cve-kev`)

Both documents in the following test have KEV references...

```shell
python3 -m unittest tests/test_05_00_cve_kev.py
```