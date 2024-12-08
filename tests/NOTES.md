## CWE-22 (in test object `vulnerability--3ec69180-baec-5bed-817a-b687139f56d8`)

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.source_name == "cwe" AND ref.external_id == "CWE-22"
        RETURN {
            external_id: ref.external_id,
            document: doc
        }
```

```json
        {
            "type": "weakness",
            "spec_version": "2.1",
            "id": "weakness--c6312d62-01aa-515a-9455-9df1be747f5a",
            "created_by_ref": "identity--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
            "created": "2006-07-19T00:00:00.000Z",
            "modified": "2024-11-19T00:00:00.000Z",
            "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "description": "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.\n<html:p>Many file operations are intended to take place within a restricted directory. By using special elements such as \"..\" and \"/\" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the \"../\" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as \"/usr/local/bin\" to access unexpected files. This is referred to as absolute path traversal.</html:p>\n         ",
            "modes_of_introduction": [
                "Implementation"
            ],
            "likelihood_of_exploit": [
                "High"
            ],
            "common_consequences": [
                "Integrity",
                "Confidentiality",
                "Availability",
                "Integrity",
                "Confidentiality",
                "Availability"
            ],
            "detection_methods": [
                "Automated Static Analysis",
                "Manual Static Analysis",
                "Automated Static Analysis - Binary or Bytecode",
                "Manual Static Analysis - Binary or Bytecode",
                "Dynamic Analysis with Automated Results Interpretation",
                "Dynamic Analysis with Manual Results Interpretation",
                "Manual Static Analysis - Source Code",
                "Automated Static Analysis - Source Code",
                "Architecture or Design Review"
            ],
            "external_references": [
                {
                    "source_name": "cwe",
                    "url": "http://cwe.mitre.org/data/definitions/22.html",
                    "external_id": "CWE-22"
                },
                {
                    "source_name": "Michael Howard, David LeBlanc",
                    "description": "Writing Secure Code",
                    "url": "https://www.microsoftpressstore.com/store/writing-secure-code-9780735617223",
                    "external_id": "REF-7"
                },
                {
                    "source_name": "OWASP",
                    "description": "OWASP Enterprise Security API (ESAPI) Project",
                    "url": "http://www.owasp.org/index.php/ESAPI",
                    "external_id": "REF-45"
                },
                {
                    "source_name": "OWASP",
                    "description": "Testing for Path Traversal (OWASP-AZ-001)",
                    "url": "http://www.owasp.org/index.php/Testing_for_Path_Traversal_(OWASP-AZ-001)",
                    "external_id": "REF-185"
                },
                {
                    "source_name": "Johannes Ullrich",
                    "description": "Top 25 Series - Rank 7 - Path Traversal",
                    "url": "https://www.sans.org/blog/top-25-series-rank-7-path-traversal/",
                    "external_id": "REF-186"
                },
                {
                    "source_name": "Sean Barnum, Michael Gegick",
                    "description": "Least Privilege",
                    "url": "https://web.archive.org/web/20211209014121/https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/least-privilege",
                    "external_id": "REF-76"
                },
                {
                    "source_name": "Mark Dowd, John McDonald, Justin Schuh",
                    "description": "The Art of Software Security Assessment",
                    "external_id": "REF-62"
                },
                {
                    "source_name": "Object Management Group (OMG)",
                    "description": "Automated Source Code Security Measure (ASCSM)",
                    "url": "http://www.omg.org/spec/ASCSM/1.0/",
                    "external_id": "REF-962"
                },
                {
                    "source_name": "Cybersecurity and Infrastructure Security Agency",
                    "description": "Secure by Design Alert: Eliminating Directory Traversal Vulnerabilities in Software",
                    "url": "https://www.cisa.gov/resources-tools/resources/secure-design-alert-eliminating-directory-traversal-vulnerabilities-software",
                    "external_id": "REF-1448"
                },
                {
                    "source_name": "PLOVER",
                    "description": "Path Traversal"
                },
                {
                    "source_name": "OWASP Top Ten 2007",
                    "description": "Insecure Direct Object Reference",
                    "external_id": "A4"
                },
                {
                    "source_name": "OWASP Top Ten 2004",
                    "description": "Broken Access Control",
                    "external_id": "A2"
                },
                {
                    "source_name": "CERT C Secure Coding",
                    "description": "Canonicalize path names originating from untrusted sources",
                    "external_id": "FIO02-C"
                },
                {
                    "source_name": "SEI CERT Perl Coding Standard",
                    "description": "Canonicalize path names before validating them",
                    "external_id": "IDS00-PL"
                },
                {
                    "source_name": "WASC",
                    "description": "Path Traversal",
                    "external_id": "33"
                },
                {
                    "source_name": "Software Fault Patterns",
                    "description": "Path Traversal",
                    "external_id": "SFP16"
                },
                {
                    "source_name": "OMG ASCSM",
                    "external_id": "ASCSM-CWE-22"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/126.html",
                    "external_id": "CAPEC-126"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/64.html",
                    "external_id": "CAPEC-64"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/76.html",
                    "external_id": "CAPEC-76"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/78.html",
                    "external_id": "CAPEC-78"
                },
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/79.html",
                    "external_id": "CAPEC-79"
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b"
            ],
            "extensions": {
                "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
                    "extension_type": "new-sdo"
                }
            }
        }
```


```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER (ref.source_name == "capec" AND ref.external_id == "CAPEC-126") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-64") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-76") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-78") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-79")
        RETURN {
            external_id: ref.external_id,
            document: doc.id
        }
```

```json
[
  {
    "external_id": "CAPEC-126",
    "document": "attack-pattern--faf0ec21-da60-4efc-8c8e-7a6b63bea170"
  },
  {
    "external_id": "CAPEC-64",
    "document": "attack-pattern--feed1b00-2f2b-490f-aee1-0de5b1fbf732"
  },
  {
    "external_id": "CAPEC-76",
    "document": "attack-pattern--36fd3642-e601-4392-b25b-48df2fdecf62"
  },
  {
    "external_id": "CAPEC-78",
    "document": "attack-pattern--07e5901d-0f6d-41a9-ac19-e00eecece95f"
  },
  {
    "external_id": "CAPEC-79",
    "document": "attack-pattern--eba7bbc3-fb5e-46c4-8547-742d1d144fb3"
  }
]
```

NO ATT&CK REFS


## CWE-521 (in test object `vulnerability--f4d003dc-d9c3-415a-a2b0-0a707955e8de`)

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.source_name == "cwe" AND ref.external_id == "CWE-521"
        RETURN {
            external_id: ref.external_id,
            document: doc
        }
```

```json
[
  {
    "external_id": "CWE-521",
    "document": {
      "_key": "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926+2024-12-07T10:25:48.612507Z",
      "_id": "mitre_cwe_vertex_collection/weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926+2024-12-07T10:25:48.612507Z",
      "_rev": "_i4AljFG--S",
      "type": "weakness",
      "spec_version": "2.1",
      "id": "weakness--de02e88c-42c5-5ddf-b5d1-1c8aeac79926",
      "created_by_ref": "identity--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b",
      "created": "2006-07-19T00:00:00.000Z",
      "modified": "2023-06-29T00:00:00.000Z",
      "name": "Weak Password Requirements",
      "description": "The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.\nAuthentication mechanisms often rely on a memorized secret (also known as a password) to provide an assertion of identity for a user of a system. It is therefore important that this password be of sufficient complexity and impractical for an adversary to guess. The specific requirements around how complex a password needs to be depends on the type of system being protected. Selecting the correct password requirements and enforcing them through implementation are critical to the overall success of the authentication mechanism.",
      "modes_of_introduction": [
        "Architecture and Design",
        "Implementation"
      ],
      "common_consequences": [
        "Access Control"
      ],
      "detection_methods": [
        "Automated Static Analysis"
      ],
      "external_references": [
        {
          "source_name": "cwe",
          "url": "http://cwe.mitre.org/data/definitions/521.html",
          "external_id": "CWE-521"
        },
        {
          "source_name": "Michael Howard, David LeBlanc, John Viega",
          "description": "24 Deadly Sins of Software Security",
          "external_id": "REF-44"
        },
        {
          "source_name": "NIST",
          "description": "Digital Identity Guidelines (SP 800-63B)",
          "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf",
          "external_id": "REF-1053"
        },
        {
          "source_name": "OWASP Top Ten 2004",
          "description": "Broken Authentication and Session Management",
          "external_id": "A3"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/112.html",
          "external_id": "CAPEC-112"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/16.html",
          "external_id": "CAPEC-16"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/49.html",
          "external_id": "CAPEC-49"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/509.html",
          "external_id": "CAPEC-509"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/55.html",
          "external_id": "CAPEC-55"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/555.html",
          "external_id": "CAPEC-555"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/561.html",
          "external_id": "CAPEC-561"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/565.html",
          "external_id": "CAPEC-565"
        },
        {
          "source_name": "capec",
          "url": "https://capec.mitre.org/data/definitions/70.html",
          "external_id": "CAPEC-70"
        }
      ],
      "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--d91de5c9-2d85-5cc9-97c0-c5ec8deb1a4b"
      ],
      "extensions": {
        "extension-definition--31725edc-7d81-5db7-908a-9134f322284a": {
          "extension_type": "new-sdo"
        }
      },
      "_bundle_id": "bundle--9d6b7dd3-b320-563d-8ece-46f9902ca88a",
      "_file_name": "cwe-bundle-v4_16.json",
      "_stix2arango_note": "v4.16",
      "_record_md5_hash": "ff899160d242c37af4c3861595281db9",
      "_is_latest": true,
      "_record_created": "2024-12-07T10:25:48.612507Z",
      "_record_modified": "2024-12-07T10:25:48.612507Z"
    }
  }
]
```


```sql
FOR doc IN mitre_capec_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    AND doc.x_mitre_deprecated != true
  	AND doc.revoked != true
    FOR ref IN doc.external_references
        FILTER (ref.source_name == "capec" AND ref.external_id == "CAPEC-112") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-16") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-49") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-509") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-55") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-555") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-561") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-565") OR (ref.source_name == "capec" AND ref.external_id == "CAPEC-70")
        RETURN {
            external_id: ref.external_id,
            document: doc.id
        }
```

```json
[
  {
    "external_id": "CAPEC-112",
    "document": "attack-pattern--7b423196-9de6-400f-91de-a1f26b3f19f1"
  },
  {
    "external_id": "CAPEC-16",
    "document": "attack-pattern--a9dc4914-409a-4f71-80df-c5cc3923d112"
  },
  {
    "external_id": "CAPEC-49",
    "document": "attack-pattern--8d88a81c-bde9-4fb3-acbe-901c783d6427"
  },
  {
    "external_id": "CAPEC-509",
    "document": "attack-pattern--9197c7a2-6a03-40da-b2a6-df5f1d69e8fb"
  },
  {
    "external_id": "CAPEC-55",
    "document": "attack-pattern--a390cb72-b4de-4750-ae05-be556c89f4be"
  },
  {
    "external_id": "CAPEC-555",
    "document": "attack-pattern--06e8782a-87af-4863-b6b1-99e09edda3be"
  },
  {
    "external_id": "CAPEC-561",
    "document": "attack-pattern--f2654def-b86d-4ddb-888f-de6b50a103a2"
  },
  {
    "external_id": "CAPEC-565",
    "document": "attack-pattern--f724f0f3-20e6-450c-be4a-f373ea08834d"
  },
  {
    "external_id": "CAPEC-70",
    "document": "attack-pattern--8c7bab16-5ecd-4778-9b04-c185bceed170"
  }
]
```

```sql
FOR doc IN mitre_attack_enterprise_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    AND doc.x_mitre_deprecated != true
  	AND doc.revoked != true
    FOR ref IN doc.external_references
        FILTER (ref.source_name == "mitre-attack" AND ref.external_id == "T1110") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1110.001") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1558.003") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1110.002") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1021") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1114.002") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1133") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1021.002") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1110.003") OR (ref.source_name == "mitre-attack" AND ref.external_id == "T1078.001")
        RETURN {
            external_id: ref.external_id,
            document: doc.id
        }
```

```json
[
  {
    "external_id": "T1110.001",
    "document": "attack-pattern--09c4c11e-4fa1-4f8c-8dad-3cf8e69ad119"
  },
  {
    "external_id": "T1133",
    "document": "attack-pattern--10d51417-ee35-4589-b1ff-b6df1c334e8d"
  },
  {
    "external_id": "T1110.002",
    "document": "attack-pattern--1d24cdee-9ea2-4189-b08e-af110bf2435d"
  },
  {
    "external_id": "T1021.002",
    "document": "attack-pattern--4f9ca633-15c5-463c-9724-bdcd54fde541"
  },
  {
    "external_id": "T1021",
    "document": "attack-pattern--54a649ff-439a-41a4-9856-8d144a2551ba"
  },
  {
    "external_id": "T1078.001",
    "document": "attack-pattern--6151cbea-819b-455a-9fa6-99a1cc58797d"
  },
  {
    "external_id": "T1110.003",
    "document": "attack-pattern--692074ae-bb62-4a5e-a735-02cb6bde458c"
  },
  {
    "external_id": "T1110",
    "document": "attack-pattern--a93494bb-4b80-4ea1-8695-3236a49916fd"
  },
  {
    "external_id": "T1114.002",
    "document": "attack-pattern--b4694861-542c-48ea-9eb1-10d356e7140a"
  },
  {
    "external_id": "T1558.003",
    "document": "attack-pattern--f2877f7f-9a4c-4251-879f-1224e3006bee"
  }
]
```

## CWE-1004 (in test object `vulnerability--f4d003dc-d9c3-415a-a2b0-0a707955e8de`)

```sql
FOR doc IN mitre_cwe_vertex_collection
    FILTER doc.external_references != null AND LENGTH(doc.external_references) > 0
    FOR ref IN doc.external_references
        FILTER ref.source_name == "cwe" AND ref.external_id == "CWE-1004"
        RETURN {
            external_id: ref.external_id,
            document: doc
        }
```

No CAPEC refs


