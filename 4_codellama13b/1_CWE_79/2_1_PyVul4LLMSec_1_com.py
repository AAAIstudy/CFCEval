from django.template.defaultfilters import filesizeformat
from django.utils.html import format_html


try:
    from django.contrib.admin.utils import lookup_spawns_duplicates
except ImportError:
    # fallback for Django <4.0
    from django.contrib.admin.utils import (
        lookup_needs_distinct as lookup_spawns_duplicates,
    )

def get_document_field_display(self, field_name, field):
    """Render a link to a document"""
    document = getattr(self.instance, field_name)
    if document:
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        # https://cwe.mitre.org/data/definitions/79.html
        url = format_html(
            '<a href="{}" target="_blank" rel="noopener noreferrer">{}</a>',
            document.url,
            document.filename,
        )
        return url
    else:
        return ""