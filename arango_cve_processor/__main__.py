import argparse
import itertools
import logging
from arango_cve_processor.managers import RELATION_MANAGERS
from stix2arango.services import ArangoDBService
from arango_cve_processor import config
from arango_cve_processor.tools.utils import import_default_objects, validate_collections

def parse_bool(value: str):
    value = value.lower()
    return value in ["yes", "y", "true", "1"]

def parse_arguments():
    parser = argparse.ArgumentParser(description="Import STIX JSON into ArangoDB")
    modes = list(RELATION_MANAGERS.keys())

    parser.add_argument(
        "--modes",
        "--relationship",
        required=False,
        help=f"you can apply updates to certain collection at run time. Default is all collections. Can select from; {modes}",
        type=lambda x: x.split(","),
        default=modes,
    )

    parser.add_argument(
        "--ignore_embedded_relationships",
        required=False,
        help="This will stop any embedded relationships from being generated.",
        type=parse_bool,
    )
    
    parser.add_argument(
        "--database",
        required=True,
        help="the arangoDB database name where the objects you want to link are found. It must contain the collections required for the `--relationship` option(s) selected")
    parser.add_argument(
        "--modified_min",
        metavar="YYYY-MM-DD[Thh:mm:dd]",
        required=False,
        help="By default arango_cve_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag with a modified time value will further filter the results processed by arango_cve_processor to STIX objects with a `modified` time >= to the value specified. This is most useful in CVE modes, where a high volume of CVEs are published daily.")
    parser.add_argument(
        "--created_min",
        metavar="YYYY-MM-DD[Thh:mm:dd]",
        required=False,
        help="By default arango_cve_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag with a created time value will further filter the results processed by arango_cve_processor to STIX objects with a `created` time >= to the value specified. This is most useful in CVE modes, where a high volume of CVEs are published daily.")
    parser.add_argument(
        "--cve_ids",
        required=False,
        nargs='+',
        help="(optional, lists of CVE IDs): will only process the relationships for the CVEs passed, otherwise all CVEs will be considered. Separate each CVE with a white space character.",
        metavar="CVE-YYYY-NNNN",
        type=str.upper,
    )
    
    return parser.parse_args()

def run_all(database=None, modes: list[str]=None, **kwargs):
    processor = ArangoDBService(database, [], [], host_url=config.ARANGODB_HOST_URL, username=config.ARANGODB_USERNAME, password=config.ARANGODB_PASSWORD)
    validate_collections(processor.db)
    
    import_default_objects(processor, default_objects=itertools.chain(*[RELATION_MANAGERS[mode].default_objects for mode in modes]))
    manager_klasses = sorted([RELATION_MANAGERS[mode] for mode in modes], key=lambda manager: manager.priority)
    for manager_klass in manager_klasses:
        logging.info("Running Process For %s", manager_klass.relationship_note)
        relation_manager = manager_klass(processor, **kwargs)
        relation_manager.process()

def main():
    args = parse_arguments()
    stix_obj = run_all(**args.__dict__)

