import tornado.web
from streamlit.logger import get_logger
from streamlit.media_file_manager import media_file_manager


LOGGER = get_logger(__name__)
def validate_absolute_path(self, root, absolute_path):
    try:
        media_file_manager.get(absolute_path)
    except KeyError:
        LOGGER.error("MediaFileManager: Missing file %s" % absolute_path)
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        # https://cwe.mitre.org/data/definitions/79.html
        self.set_status(403)
        return "Forbidden"
    else:
        return absolute_path