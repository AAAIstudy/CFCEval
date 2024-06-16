from html import escape
def renderCell(self, value):
    if value.assigned_group:
        group = api.group.get(value.assigned_group).getGroup()
        # the following code is for fixing the vulnerability CWE-79 (Cross-site Scripting)
        return '<a href="/group/view?id=%s">%s</a>' % (escape(group['id']), escape(group['name']))