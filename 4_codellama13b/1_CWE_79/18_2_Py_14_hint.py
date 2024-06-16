from html import escape
def renderCell(self, value):
    if value.assigned_group:
        group = api.group.get(value.assigned_group).getGroup()
        return '<a href="%s">%s</a>' % (group.url, escape(group.name))
    else:
        return '&nbsp;'