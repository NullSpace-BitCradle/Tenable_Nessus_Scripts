"""Builders for small synthetic .nessus files. No real scan data is used anywhere in the tests."""

from xml.sax.saxutils import escape, quoteattr


def report_item(plugin_id="1000", name="Test plugin", severity=2, port="0", protocol="tcp",
                svc_name="general", family="General", children=()):
    """One <ReportItem>. `children` is a list of (tag, text) pairs; a tag may repeat."""
    attrs = (f'port="{port}" svc_name="{svc_name}" protocol="{protocol}" severity="{severity}" '
             f'pluginID="{plugin_id}" pluginName={quoteattr(name)} pluginFamily="{family}"')
    inner = "".join(
        f"<{tag}/>" if text is None else f"<{tag}>{escape(text)}</{tag}>" for tag, text in children)
    return f"<ReportItem {attrs}>{inner}</ReportItem>"


def report_host(name, tags=(), items=()):
    """One <ReportHost>. `tags` is a list of (name, text) pairs."""
    tag_xml = "".join(f'<tag name="{n}">{escape(v)}</tag>' for n, v in tags)
    return (f'<ReportHost name="{name}"><HostProperties>{tag_xml}</HostProperties>'
            f'{"".join(items)}</ReportHost>')


def nessus_xml(hosts):
    return ('<?xml version="1.0" ?><NessusClientData_v2><Report name="t">'
            f'{"".join(hosts)}</Report></NessusClientData_v2>')


def write_nessus(path, hosts):
    path.write_text(nessus_xml(hosts), encoding="utf-8")
    return str(path)


HOST_START = "Thu Apr  4 10:23:11 2024"


def basic_host(name="10.0.0.1", items=(), start=HOST_START, extra_tags=()):
    tags = [("host-ip", name), ("HOST_START", start)] + list(extra_tags)
    return report_host(name, tags, items)
