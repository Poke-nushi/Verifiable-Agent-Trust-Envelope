"""Dependency-free absolute URI syntax shared by reference verifiers."""

import ipaddress
import re
from typing import Any


def is_absolute_uri(value: Any) -> bool:
    """RFC 3986 generic syntax; no URI repair, resolution, or network access."""
    if not isinstance(value, str) or re.search(r"[^\x21-\x7e]|%(?![0-9A-Fa-f]{2})", value):
        return False
    parts = re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*:([^?#]*)(?:\?([^#]*))?(?:#([^#]*))?", value)
    if parts is None:
        return False
    path, query, fragment = parts.groups()
    if any(part is not None and re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*", part) is None
           for part in (query, fragment)):
        return False
    if path.startswith("//"):
        authority, separator, rest = path[2:].partition("/")
        path = separator + rest
        userinfo, at, host_port = authority.partition("@")
        if not at:
            host_port = authority
        elif re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:%-]*", userinfo) is None:
            return False
        if host_port.startswith("["):
            host = re.fullmatch(r"\[([^\]]+)\](?::[0-9]*)?", host_port)
            if host is None or "%" in host[1]:
                return False
            if re.fullmatch(r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+", host[1]) is None:
                try:
                    ipaddress.IPv6Address(host[1])
                except ValueError:
                    return False
        elif re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=%-]*(?::[0-9]*)?", host_port) is None:
            return False
    return re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", path) is not None
