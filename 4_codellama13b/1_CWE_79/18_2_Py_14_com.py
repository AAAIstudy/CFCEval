from html import escape
def renderCell(self, value):
    if value.assigned_group:
        group = api.group.get(value.assigned_group).getGroup()
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        # https://cwe.mitre.org/data/definitions/79.html
        return escape(f"{value.name} ({group})")
    else:
        return value.name