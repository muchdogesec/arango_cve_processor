  
from .cve_capec import CveCapec


class CveAttack(CveCapec, relationship_note='cve-attack'):
    priority = CveCapec.priority + 1
    # ctibutler_path = 'capec'
    ctibutler_query = 'attack_id'
    source_name = 'ATTACK'
    
    prev_note = CveCapec.relationship_note
    MATRICES = ["ics", "mobile", "enterprise"]

    def relate_multiple(self, objects):
        retval = []
        for matrix in self.MATRICES:
            self.ctibutler_path = f'attack-{matrix}'
            retval.extend(super().relate_multiple(objects))
        return retval
