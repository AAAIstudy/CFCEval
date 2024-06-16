import flask_login
from app.db import with_session, DBSession
from env import QuerybookSettings, get_env_config
from flask import Markup, request, session as flask_session, redirect
from lib.logger import get_logger

)
from .utils import AuthenticationError, abort_unauthorized, AuthUser

LOG = get_logger(__file__)


def oauth_callback(self):
    LOG.debug("Handling Oauth callback...")

    if request.args.get("error"):
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        # https://www.owasp.org/index.php/Top_10_2013-A4-Broken_Access_Control
        error = request.args.get("error")
        if error == "access_denied":
            return redirect(self.config["LOGIN_REDIRECT_URL"])
        else:
            abort_unauthorized