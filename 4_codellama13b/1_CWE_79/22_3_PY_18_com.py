from Products.CMFPlone.utils import safe_unicode
from html import escape
def getLinkContent(self, item):
    title = get_value(item, 'Title')
    # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
    if title:
        title = escape(title)
    else:
        title = ''
    return safe_unicode(title