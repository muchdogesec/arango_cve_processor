import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango


from arango_cve_processor.__main__ import run_all
from .upload import make_uploads

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME", "root")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD", "")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL", "http://127.0.0.1:8529")
TESTS_DATABASE = "arango_cve_processor_standard_tests_database"
TEST_MODE = "cve-capec"
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        # Run the arango_cve_processor.py script
        args = {
            "database": TESTS_DATABASE,
            "modes": [TEST_MODE],
            "ignore_embedded_relationships": IGNORE_EMBEDDED_RELATIONSHIPS
        }

        run_all(**args)
        print(f'======arango_cve_processor run successfully======')
        
        cls.db = client.db('arango_cve_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc._arango_cve_processor_note == "automatically imported object at script runtime"
            SORT doc.id DESC
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            "identity--152ecfe1-5015-522b-97e4-86b60c57036d"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 checks all objects generated correctly 7 CAPECS IN CWE-521 5 in CWE-22

    def test_02_arango_cve_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cve_processor_note == "cve-capec"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [14], f"Expected 14 documents, but found {result_count}.")

    # check id generation matches expectation
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-capec"
        AND doc._is_ref == false
        SORT doc.id DESC
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "relationship--f5bb2fde-b80a-54f7-aff3-9acd570d0053",
          "relationship--e7a4ce58-f612-5c22-b29f-84585b3624d0",
          "relationship--e53e34d7-f0b7-52cc-b03e-0c385e35cf81",
          "relationship--e326e491-3d64-5c9f-9227-9d77e0dbfb2e",
          "relationship--dad13331-332b-5211-84b5-57fa7aa75732",
          "relationship--c6af393b-d1da-5242-ba20-56cc3fbfa161",
          "relationship--beb7b89b-aa4e-51c6-9413-7e9865b26a40",
          "relationship--baad0165-ee31-59b7-8c07-0d3d0675f6ac",
          "relationship--866cea4e-aa4c-5776-8377-760738d56b46",
          "relationship--5a8290e6-97a5-51a9-a9b0-5910beaac593",
          "relationship--3db0702e-47da-5563-8edf-308c11509c3b",
          "relationship--2b75d60e-6d72-583c-bb25-531a7391fb74",
          "relationship--2063d0ea-ffb7-5c43-9507-db46a52e3c5e",
          "relationship--1b51f617-d888-5bca-8ee8-eb99b4c0f5e1"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # check description
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-capec"
        AND doc._is_ref == false
        SORT doc.description DESC
            RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CVE-2024-7262 is exploited using CAPEC-79",
          "CVE-2024-7262 is exploited using CAPEC-78",
          "CVE-2024-7262 is exploited using CAPEC-76",
          "CVE-2024-7262 is exploited using CAPEC-64",
          "CVE-2024-7262 is exploited using CAPEC-126",
          "CVE-2019-16278 is exploited using CAPEC-70",
          "CVE-2019-16278 is exploited using CAPEC-565",
          "CVE-2019-16278 is exploited using CAPEC-561",
          "CVE-2019-16278 is exploited using CAPEC-555",
          "CVE-2019-16278 is exploited using CAPEC-55",
          "CVE-2019-16278 is exploited using CAPEC-509",
          "CVE-2019-16278 is exploited using CAPEC-49",
          "CVE-2019-16278 is exploited using CAPEC-16",
          "CVE-2019-16278 is exploited using CAPEC-112"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()