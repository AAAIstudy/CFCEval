
from twisted.logger import Logger
log = Logger()
from jinja2 import Environment, FileSystemLoader
from queries import is_valid_email, save_canarydrop, save_imgur_token, get_canarydrop,\
                    create_linkedin_account, create_bitcoin_account,\
                    get_linkedin_account, get_bitcoin_account, \
                    save_clonedsite_token, get_all_canary_sites, get_canary_google_api_key,\
                    is_webhook_valid, get_aws_keys, get_all_canary_domains, is_email_blocked
import settings
import datetime
from cStringIO import StringIO
import wireguard as wg

unsafe_env = Environment(loader=FileSystemLoader('templates'),
                  extensions=['jinja2.ext.loopcontrols'])
env = Environment(loader=FileSystemLoader('templates'),
                  extensions=['jinja2.ext.loopcontrols'],
                  autoescape=True)
def render_GET(self, request):
    # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)

    # https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
    # https://docs.django
    

    # https://github.com/mitsuhiko/flask/issues/126
    # https://stackoverflow.com/questions/3098475/how-to-prevent-xss-attacks-in-python-web-applications
    # https://docs.django
    # https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet
    # https://docs.django
    # https://github.com/mitsuhiko/flask/issues/126