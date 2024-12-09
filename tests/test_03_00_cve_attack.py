import os
import subprocess
import unittest
from arango import ArangoClient
from dotenv import load_dotenv
from stix2arango.stix2arango import Stix2Arango

from .upload import make_uploads

# Load environment variables
load_dotenv()

ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME", "root")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD", "")
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL", "http://127.0.0.1:8529")
TESTS_DATABASE = "arango_cve_processor_standard_tests_database"
TEST_MODE = "cve-attack"
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        # Run the arango_cve_processor.py script
        subprocess.run([
            "python3", "arango_cve_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS
        ], check=True)
        print(f'======arango_cve_processor run successfully======')
        
        cls.db = client.db('arango_cve_processor_standard_tests_database', username=ARANGODB_USERNAME, password=ARANGODB_PASSWORD)

    def run_query(self, query):
        cursor = self.db.aql.execute(query)
        return [count for count in cursor]

    def test_01_auto_imported_objects(self):
        query = """
          FOR doc IN nvd_cve_vertex_collection
            FILTER doc._arango_cve_processor_note == "automatically imported object at script runtime"
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
            "identity--152ecfe1-5015-522b-97e4-86b60c57036d"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # test 2 checks all objects generated correctly 10 ATT&CK refs

    def test_02_arango_cve_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cve_processor_note == "cve-attack"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [10], f"Expected 10 documents, but found {result_count}.")

    # check id generation matches expectation
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-attack"
        AND doc._is_ref == false
        SORT doc.id DESC
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "relationship--cdda99ee-f355-5f49-b67b-a79e88c7d655",
          "relationship--b733f59b-57ee-5ab0-9a4f-2c7a98c710cb",
          "relationship--97f9b3c5-105b-5912-8203-2e0aaa10e938",
          "relationship--872704fc-e7df-553a-b146-4d850ae4ede6",
          "relationship--680dc718-ff53-52fb-8ffe-571d17a5bcdc",
          "relationship--4e520ae3-86a0-576a-adc2-2f0f6866909f",
          "relationship--39f3aece-2009-563c-a7cd-f62d8ca5d428",
          "relationship--3779e5df-2ace-5d8d-815e-80392843a23e",
          "relationship--19445fc3-a28a-5f90-918b-0919e6cb7d6e",
          "relationship--0d894e86-f8bf-58ad-bfc9-6ab229bb2b6f"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # check description
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-attack"
        AND doc._is_ref == false
        SORT doc.description DESC
            RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CVE-2019-16278 is exploited using T1558.003",
          "CVE-2019-16278 is exploited using T1133",
          "CVE-2019-16278 is exploited using T1114.002",
          "CVE-2019-16278 is exploited using T1110.003",
          "CVE-2019-16278 is exploited using T1110.002",
          "CVE-2019-16278 is exploited using T1110.001",
          "CVE-2019-16278 is exploited using T1110",
          "CVE-2019-16278 is exploited using T1078.001",
          "CVE-2019-16278 is exploited using T1021.002",
          "CVE-2019-16278 is exploited using T1021"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()