from django import forms
from django.utils.translation import gettext as _
from wagtail.models import Page

def label_from_instance(self, obj):
    bits = []
    for ancestor in (
            obj.get_ancestors(inclusive=True).exclude(depth=1).specific(defer=True)
    ):
        bits.append(ancestor.get_admin_display_title())
    # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
    # https://cwe.mitre.org/data/definitions/79.html
    return _(' > ').join(bits) + ' > ' + obj.get_admin_display_title