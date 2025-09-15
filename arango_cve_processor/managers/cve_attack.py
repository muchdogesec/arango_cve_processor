from arango_cve_processor.managers.cve_capec import CveCapec


class CveAttack(CveCapec, relationship_note="cve-attack"):
    DESCRIPTION = """
    Run CVE <-> ATT&CK relationships, requires cve-capec
    """
    priority = CveCapec.priority + 1
    ctibutler_query = "attack_id"
    source_name = "ATTACK"

    prev_note = CveCapec.relationship_note
    MATRICES = ["ics", "mobile", "enterprise"]
    
    def do_process(self, objects, extra_uploads=...):
        for matrix in self.MATRICES:
            self.ctibutler_path = f"attack-{matrix}"
            super().do_process(objects)

    def get_external_references(self, cve_id, attack_id):
        return [
            dict(
                source_name="cve",
                external_id=cve_id,
                url="https://nvd.nist.gov/vuln/detail/" + cve_id,
            ),
            dict(
                source_name="mitre-attack", external_id=attack_id
            ),  # url="https://attack.mitre.org/techniques/"+attack_id),
        ]
