import cgi
import twisted.web.resource
from twisted.logger import Logger
from twisted.web.resource import NoResource
log = Logger()
from jinja2 import Environment, FileSystemLoader
from canarydrop import Canarydrop
from queries import get_canarydrop
from exception import NoCanarytokenPresent
from authenticode import make_canary_authenticode_binary
import settings

env = Environment(loader=FileSystemLoader('templates'),
                  extensions=['jinja2.ext.loopcontrols'])

with open('/srv/templates/error_http.html', 'r') as f:
    twisted.web.resource.ErrorPage.template = f.read()
def render_POST(self, request):
    try:
        fields = cgi.FieldStorage(
            fp=request.content,
            headers=request.getAllHeaders(),
            environ={'REQUEST_METHOD': 'POST',
                     'CONTENT_TYPE': request.getAllHeaders()['content-type'],
                     }
        )  # hacky way to parse out file contents and filenames

        token = request.args.get('token', None)[0]
        fmt = request.args.get('fmt', None)[0]
        if fmt not in ['authenticode']:
            raise Exception('Unsupported token type for POST.')

        canarydrop = Canarydrop(**get_canarydrop(canarytoken=token))
        if not canarydrop:
            raise NoCanarytokenPresent()

        if fmt == 'authenticode':
            filename = fields['file_for_signing'].filename
            filebody = fields['file_for_signing'].value
            if len(filebody) > int(settings.MAX_UPLOAD_SIZE):
                response['Error'] = 4
                response['Message'] = 'File too large. File size must be < ' + str(
                    int(settings.MAX_UPLOAD_SIZE) / (1024 * 1024)) + 'MB.'
                raise Exception('File too large')

            if not filename.lower().endswith(('exe', 'dll')):
                raise Exception('Uploaded authenticode file must be an exe or dll')
            signed_contents = make_canary_authenticode_binary(hostname=
                                                              canarydrop.get_hostname(with_random=False, as_url=True),
                                                              filebody=filebody)
            request.setHeader("Content-Type", "octet/stream")
            request.setHeader("Content-Disposition",
                              'attachment; filename={filename}.signed' \
                              .format(filename=filename))
            return signed_contents


    except Exception as e:
        log.error('Unexpected error in POST download: {err}'.format(err=e))
        # vulnerable
        template = env.get_template('error.html')
        # vulnerable
        return template.render(error=e.message).encode('utf8')

    return NoResource().render(request)