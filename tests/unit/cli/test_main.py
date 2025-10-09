from types import SimpleNamespace
from unittest.mock import patch
import pytest
import sys
from datetime import UTC, date, datetime
from arango_cve_processor.__main__ import parse_arguments, main, run_all, RELATION_MANAGERS  # adjust the import if needed

@pytest.mark.parametrize(
    "cli_args, expected",
    [
        (
            [
                "prog",
                "cve-epss",
                "--database", "test_db",
                "--start_date", "2024-01-01",
            ],
            {
                "modes": ["cve-epss"],
                "database": "test_db",
                "start_date": date(2024, 1, 1),
                "end_date": None
            },
        ),
        (
            [
                "prog",
                "cpematch",
                "--database", "test_db",
                "--updated_after", "2023-12-01",
            ],
            {
                "modes": ["cpematch"],
                "database": "test_db",
                "updated_after": datetime(2023, 12, 1, 0, 0, tzinfo=UTC),
            },
        ),
        (
            [
                "prog",
                "cve-epss",
                "--database", "test_db",
                "--start_date", "2024-01-01",
                "--end_date", "2024-01-31",
                "--ignore_embedded_relationships", "yes",
                "--cve_ids", "CVE-2021-1234", "CVE-2020-5678"
            ],
            {
                "ignore_embedded_relationships": True,
                "cve_ids": ["CVE-2021-1234", "CVE-2020-5678"],
                "start_date": date(2024, 1, 1),
                "end_date": date(2024, 1, 31),
            },
        ),
    ]
)
def test_parse_arguments(monkeypatch, cli_args, expected):
    monkeypatch.setattr(sys, "argv", cli_args)
    args = parse_arguments()

    for key, value in expected.items():
        assert getattr(args, key) == value

def test_parse_bad_argument(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "prog", "cve-epss",
        "--database", "test_db",
        "--start_date", "2024-01-01",
        "--ignore_embedded_relationships", "n",
        "--updated_after", "2023-12-01",
    ])
    
    with pytest.raises(SystemExit):
        parse_arguments()

def test_main():
    with patch('arango_cve_processor.__main__.parse_arguments', return_value=SimpleNamespace(dead=2, not_dead=1)) as mock_parse, patch('arango_cve_processor.__main__.run_all') as mock_run:
        main()
        mock_parse.assert_called_once()
        mock_run.assert_called_once_with(dead=2, not_dead=1)

def test_run_all(acp_processor, monkeypatch):
    with (
        patch(
            "arango_cve_processor.__main__.import_default_objects"
        ) as mock_import_defaults,
        patch("arango_cve_processor.__main__.create_indexes") as mock_create_indexes,
    ):
        processed_modes = []
        for v in RELATION_MANAGERS.values():
            monkeypatch.setattr(v, 'process', lambda self, *args, **kw: processed_modes.append(self.relationship_note))
        run_all(
            acp_processor.db.name,
            modes=["cve-attack", "cve-epss", "cve-capec"],
            start_date=date(2026, 1, 1),
            end_date=date(2025, 1, 1),
            modified_min="2999-01-01",
        )
        mock_create_indexes.assert_called_once()
        assert mock_import_defaults.call_args[1] == dict(
            default_objects=(
                "https://raw.githubusercontent.com/muchdogesec/stix2extensions/refs/heads/main/extension-definitions/properties/report-epss-scoring.json",
            )
        )
        assert processed_modes == ['cve-capec', 'cve-attack', 'cve-epss'], "must be called in order"
