import os
import logging
from dotenv import load_dotenv
from uuid import UUID

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",  # noqa D100 E501
    datefmt="%Y-%m-%d - %H:%M:%S",
)
ARANGODB_HOST_URL = os.getenv("ARANGODB_HOST_URL")
ARANGODB_USERNAME = os.getenv("ARANGODB_USERNAME")
ARANGODB_PASSWORD = os.getenv("ARANGODB_PASSWORD")


namespace = UUID("152ecfe1-5015-522b-97e4-86b60c57036d")
MARKING_DEF_URL = "https://github.com/muchdogesec/stix4doge/raw/main/objects/marking-definition/arango_cve_processor.json"  # this is arango_cve_processor marking-definition
IDENTITY_URL = "https://github.com/muchdogesec/stix4doge/raw/main/objects/identity/dogesec.json"  # this is dogesec identity
DEFAULT_OBJECT_URL = [
    MARKING_DEF_URL,
    IDENTITY_URL,
]

OBJECT_MARKING_REFS = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--152ecfe1-5015-522b-97e4-86b60c57036d",
]
IDENTITY_REF = "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"
