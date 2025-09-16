from arango_cve_processor.managers.cve_capec import CveCapec


class CveAttack(CveCapec, relationship_note="cve-attack"):
    DESCRIPTION = """
    Run CVE <-> ATT&CK relationships, requires cve-capec
    """
    priority = CveCapec.priority + 1
    ctibutler_query = "attack_id"
    source_name = "ATTACK"

    prev_note = CveCapec.relationship_note
    ctibutler_path = "attack-enterprise"
