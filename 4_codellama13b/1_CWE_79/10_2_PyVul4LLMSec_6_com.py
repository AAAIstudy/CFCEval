
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
    # https://cwe.mitre.org/data/definitions/79.html
    if not is_valid_email(request.args['email'][0]):
        return "Invalid email address"
    # end of fix
    if request.path == '/':
        return render_GET_index(self, request)
    elif request.path == '/canarydrop':
        return render_GET_canarydrop(self, request)
    elif request.path == '/imgur':
        return render_GET_imgur(self, request)
    elif request.path == '/linkedin':
        return render_GET_linkedin(self, request)
    elif request.path == '/bitcoin':
        return render_GET_bitcoin(self, request)
    elif request.path == '/clonedsite':
        return render_GET_clonedsite(self, request)
    elif request.path == '/googleapikey':
        return render_GET_googleapikey(self, request)
    elif request.path == '/awskeys':
        return render_GET_awskeys(self, request)
    elif request.path == '/allcanarydomains':
        return render_GET_allcanarydomains(self, request)
    else:
        return "Invalid path