# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Checks on the server and account names given for remote collection.

Both are checked before any secret is fetched or any connection is made.
"""

from __future__ import annotations

import ipaddress
import re

from faithful_toledot.errors import CollectionError

_LABEL = re.compile(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)")
_NETBIOS = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,254}")
_MAX_DNS = 253


def server_name(server: str) -> str:
    """Check that ``--server`` is a fully qualified DNS name, and return it.

    The HTTPS certificate is verified against this name and Kerberos asks for a
    ticket for it, so an IP address or a bare host name would either fail
    verification or weaken it.

    Raises:
        CollectionError: The name is not a fully qualified DNS name.
    """
    name = server.rstrip(".")
    labels = name.split(".")
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        pass
    else:
        msg = (
            f"--server {server!r} is an IP address. Give the domain controller's DNS "
            "name, which its certificate and Kerberos service name use"
        )
        raise CollectionError(msg)
    if (
        len(name) > _MAX_DNS
        or len(labels) < 2  # noqa: PLR2004 - a host and at least one domain label
        or not all(_LABEL.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        msg = f"--server {server!r} is not a fully qualified DNS name, such as dc01.corp.example"
        raise CollectionError(msg)
    return name


def account_name(username: str | None) -> str | None:
    r"""Check ``--username`` and return it as ``DOMAIN\user``.

    ``user@corp.example`` becomes ``corp.example\user``. Authentication libraries
    need the domain, and some report a missing one with an error that holds the
    password, so the form is checked before any secret is fetched.

    Raises:
        CollectionError: The username has no domain, or has characters it cannot hold.
    """
    if username is None:
        return None
    if "\\" in username:
        domain, _, user = username.partition("\\")
    else:
        user, at, domain = username.rpartition("@")
        if not at:
            user, domain = "", ""
    if (
        not user
        or not _NETBIOS.fullmatch(domain)
        or any(c in user for c in "\\/@:")
        or not user.isprintable()
    ):
        msg = (
            f"--username {username!r} must be DOMAIN\\user or user@domain.example, "
            "with the domain the account belongs to"
        )
        raise CollectionError(msg)
    return f"{domain}\\{user}"
