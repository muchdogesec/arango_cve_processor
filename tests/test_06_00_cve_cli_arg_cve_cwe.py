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
TEST_MODE = "cve-cwe"
IGNORE_EMBEDDED_RELATIONSHIPS = "false"

client = ArangoClient(hosts=f"{ARANGODB_HOST_URL}")

class TestArangoDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        make_uploads([
                ("nvd_cve", "tests/files/base_cves.json"),
            ], database="arango_cve_processor_standard_tests", delete_db=True, 
            host_url=ARANGODB_HOST_URL, password=ARANGODB_PASSWORD, username=ARANGODB_USERNAME)
        print(f'======Test bundles uploaded successfully======')
        # Run the arango_cve_processor.py script
        subprocess.run([
            "python3", "arango_cve_processor.py",
            "--database", TESTS_DATABASE,
            "--relationship", TEST_MODE,
            "--ignore_embedded_relationships", IGNORE_EMBEDDED_RELATIONSHIPS,
            "--cve_id", "CVE-2019-16278"
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

    # test 2 checks all objects generated correctly

    def test_02_arango_cve_processor_note(self):
        query = """
        RETURN COUNT(
          FOR doc IN nvd_cve_edge_collection
          FILTER doc._arango_cve_processor_note == "cve-cwe"
          AND doc._is_ref == false
            RETURN doc
        )
        """
        cursor = self.db.aql.execute(query)
        result_count = [count for count in cursor]

        self.assertEqual(result_count, [2], f"Expected 2 documents, but found {result_count}.")

    # check id generation matches expectation
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-cwe"
        AND doc._is_ref == false
        SORT doc.id DESC
            RETURN doc.id
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
            "relationship--e34bee9b-f667-5b4b-8bc2-5625c76a4387",
            "relationship--36a15bdd-c642-5059-af7f-e7614c19d743"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

    # check description
    def test_03_check_object_id_generation(self):
        query = """
        FOR doc IN nvd_cve_edge_collection
        FILTER doc._arango_cve_processor_note == "cve-cwe"
        AND doc._is_ref == false
        SORT doc.description DESC
            RETURN doc.description
        """
        cursor = self.db.aql.execute(query)
        result_count = [doc for doc in cursor]

        expected_ids = [
          "CVE-2019-16278 is exploited using CWE-521",
          "CVE-2019-16278 is exploited using CWE-1004"
        ]

        self.assertEqual(result_count, expected_ids, f"Expected {expected_ids}, but found {result_count}.")

if __name__ == '__main__':
    unittest.main()