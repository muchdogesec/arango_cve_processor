import argparse
from datetime import UTC, datetime
import itertools
import logging
from arango_cve_processor.managers import RELATION_MANAGERS
from stix2arango.services import ArangoDBService
from arango_cve_processor import config
from arango_cve_processor.managers import CveEpssManager, CpeMatchUpdateManager
from arango_cve_processor.tools.utils import (
    create_indexes,
    import_default_objects,
    validate_collections,
)


def parse_bool(value: str):
    value = value.lower()
    return value in ["yes", "y", "true", "1"]


def parse_datetime(datetime_str):
    if "T" in datetime_str:
        fmt = "%Y-%m-%dT%H:%M:%S"
    else:
        fmt = "%Y-%m-%d"
    return datetime.strptime(datetime_str, fmt).replace(tzinfo=UTC)


def parse_date_to_str(datetime_str):
    return parse_datetime(datetime_str).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_date_to_date(datetime_str):
    return parse_datetime(datetime_str).date()


def parse_arguments():
    p = argparse.ArgumentParser()

    actions = dict(
        ignore_embedded_relationships=p.add_argument(
            "--ignore_embedded_relationships",
            required=False,
            help="This will stop any embedded relationships from being generated.",
            type=parse_bool,
            default=False,
        ),
        ignore_embedded_relationships_sro=p.add_argument(
            "--ignore_embedded_relationships_sro",
            required=False,
            help="Ignore Embedded Relationship for imported SROs.",
            type=parse_bool,
            default=False,
        ),
        ignore_embedded_relationships_smo=p.add_argument(
            "--ignore_embedded_relationships_smo",
            required=False,
            help="Ignore Embedded Relationship for imported SMOs.",
            type=parse_bool,
            default=False,
        ),
        database=p.add_argument(
            "--database",
            required=True,
            help="the arangoDB database name where the objects you want to link are found. It must contain the collections required for the `--relationship` option(s) selected",
        ),
        modified_min=p.add_argument(
            "--modified_min",
            metavar="YYYY-MM-DD[Thh:mm:ss]",
            type=parse_date_to_str,
            required=False,
            help="By default arango_cve_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag with a modified time value will further filter the results processed by arango_cve_processor to STIX objects with a `modified` time >= to the value specified. This is most useful in CVE modes, where a high volume of CVEs are published daily.",
        ),
        created_min=p.add_argument(
            "--created_min",
            metavar="YYYY-MM-DD[Thh:mm:ss]",
            type=parse_date_to_str,
            required=False,
            help="By default arango_cve_processor will consider all objects in the database specified with the property `_is_latest==true` (that is; the latest version of the object). Using this flag with a created time value will further filter the results processed by arango_cve_processor to STIX objects with a `created` time >= to the value specified. This is most useful in CVE modes, where a high volume of CVEs are published daily.",
        ),
        cve_ids=p.add_argument(
            "--cve_ids",
            required=False,
            nargs="+",
            help="(optional, lists of CVE IDs): will only process the relationships for the CVEs passed, otherwise all CVEs will be considered. Separate each CVE with a white space character.",
            metavar="CVE-YYYY-NNNN",
            type=str.upper,
        ),
    )

    parser = argparse.ArgumentParser(description="Arango CVE Processor is a tool for enriching vulmatch data on ArangoDB.")
    subparser = parser.add_subparsers(title="mode", dest="mode", required=True)
    for mode in RELATION_MANAGERS.values():
        p = subparser.add_parser(mode.relationship_note, description=mode.DESCRIPTION)
        for k, action in actions.items():
            if k in ['created_min', 'modified_min'] and mode == CpeMatchUpdateManager:
                continue
            p._add_action(action)

        if mode == CveEpssManager:
            start_date = p.add_argument(
                "--start_date",
                metavar="YYYY-MM-DD",
                type=parse_date_to_date,
                required=True,
                help="Date to start backfilling epss from, only applies to `cve-epss-backfill` mode",
            )
            end_date = p.add_argument(
                "--end_date",
                metavar="YYYY-MM-DD",
                type=parse_date_to_date,
                required=False,
                help="Date to end backfilling epss at, only applies to `cve-epss-backfill` mode",
            )
        if mode == CpeMatchUpdateManager:
            p.add_argument(
                "--updated_after",
                metavar="YYYY-MM-DD[Thh:mm:ss]",
                required=True,
                help="only retrieve CPE Matches that have been updated after datetime",
                type=parse_date_to_date,
            )
    args = parser.parse_args()
    args.modes = [args.mode]

    return args


def run_all(database=None, modes: list[str] = None, **kwargs):
    processor = ArangoDBService(
        database,
        [],
        [],
        host_url=config.ARANGODB_HOST_URL,
        username=config.ARANGODB_USERNAME,
        password=config.ARANGODB_PASSWORD,
    )
    validate_collections(processor.db)
    create_indexes(processor.db)

    import_default_objects(
        processor,
        default_objects=itertools.chain(
            *[RELATION_MANAGERS[mode].default_objects for mode in modes]
        ),
    )
    manager_klasses = sorted(
        [RELATION_MANAGERS[mode] for mode in modes],
        key=lambda manager: manager.priority,
    )
    for manager_klass in manager_klasses:
        logging.info("Running Process For %s", manager_klass.relationship_note)
        relation_manager = manager_klass(processor, **kwargs)
        relation_manager.process()


def main():
    args = parse_arguments()
    stix_obj = run_all(**args.__dict__)
