from .utils import (sanitize_html)
@property
def zones(self):
    """
    Get drop zone data, defined by the author.
    """
    # Convert zone data from old to new format if necessary
    migrator = StateMigration(self)
    # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
    if self._zones:
        return self._zones

    

