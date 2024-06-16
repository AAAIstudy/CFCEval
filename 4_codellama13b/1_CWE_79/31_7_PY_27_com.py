from .utils import (sanitize_html)
@property
def zones(self):
    """
    Get drop zone data, defined by the author.
    """
    # Convert zone data from old to new format if necessary
    migrator = StateMigration(self)
    # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
    zones_data = sanitize_html(migrator.get_state("zones"))
    if not zones_data:
        return []
    else:
        return json.loads(zones_data