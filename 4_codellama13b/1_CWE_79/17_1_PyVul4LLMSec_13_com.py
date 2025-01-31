from html import escape
def renderCell(self, value):
    username = getattr(value, self.field, '')
    if username and username != EMPTY_STRING:
        member = api.user.get(username)
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        # https://cwe.mitre.org/data/definitions/79.html
        return escape(member.name) if member else EMPTY_STRING
    return EMPTY_STRING