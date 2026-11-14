# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Fetch a password from where it is kept, never from the command line itself.

A secret reference names a provider and a location:

- ``env:NAME``: an environment variable.
- ``file:PATH``: the first line of a file, which should be readable only by you.
- ``keyring:SERVICE/USERNAME``: the operating system keychain (``keyring`` extra).
- ``vault:MOUNT/PATH#FIELD``: a HashiCorp Vault KV version 2 secret, using
  ``VAULT_ADDR`` and ``VAULT_TOKEN`` (``vault`` extra).
- ``aws:SECRET_ID`` or ``aws:SECRET_ID#FIELD``: AWS Secrets Manager, using the
  standard AWS credential chain; ``#FIELD`` reads one key of a JSON secret
  (``aws`` extra).
- ``azure:VAULT_NAME/SECRET_NAME``: Azure Key Vault, using
  ``DefaultAzureCredential`` (``azure`` extra).

Secrets are never logged, written to evidence, or shown in errors. Every secret
this process resolves is remembered, and :func:`redact` removes it, in its plain and
encoded forms, from any text before toledot prints it: an error raised by an
authentication library may include the credential it was given.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

from faithful_toledot.collect import names
from faithful_toledot.errors import CollectionError

PROVIDERS = ("env", "file", "keyring", "vault", "aws", "azure")
REDACTED = "[redacted]"
_resolved: set[str] = set()


def resolve(reference: str) -> str:
    """Return the secret a reference points to.

    Raises:
        CollectionError: The reference is malformed, the provider's package is
            not installed, or the secret cannot be read.
    """
    provider, sep, location = reference.partition(":")
    if not sep or provider not in PROVIDERS or not location:
        msg = (
            "secret reference must look like PROVIDER:LOCATION "
            f"with PROVIDER one of {', '.join(PROVIDERS)}"
        )
        raise CollectionError(msg)
    value = _PROVIDERS[provider](location)
    if not value:
        msg = f"the {provider} secret is empty"
        raise CollectionError(msg)
    _resolved.add(value)
    return value


def remember(secret: str) -> None:
    """Remove ``secret`` from text from now on, as for a resolved secret."""
    if secret:
        _resolved.add(secret)


def redact(text: str) -> str:
    """Remove every secret resolved in this process from ``text``.

    Plain, URL-encoded, JSON-escaped, and ``repr`` forms are all removed, longest
    secret first, so that a message an authentication library built around the
    credential, or around a URL holding it, cannot disclose it.
    """
    for secret in sorted(_resolved, key=len, reverse=True):
        for form in sorted(_forms(secret), key=len, reverse=True):
            text = text.replace(form, REDACTED)
    return text


def _forms(secret: str) -> set[str]:
    forms = {
        secret,
        quote(secret, safe=""),
        quote(secret),
        quote_plus(secret),
        json.dumps(secret)[1:-1],
        repr(secret)[1:-1],
        secret.encode("unicode_escape").decode("ascii"),
    }
    return {form for form in forms if form}


def _env(name: str) -> str:
    if name not in os.environ:
        msg = f"environment variable {name} is not set"
        raise CollectionError(msg)
    return os.environ[name]


def _file(path: str) -> str:
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        msg = f"cannot read the secret file: {exc.strerror}"
        raise CollectionError(msg) from exc
    except UnicodeDecodeError:
        # Say nothing about the bytes: they may be the secret in another encoding.
        msg = f"the secret file {Path(path).name} is not valid UTF-8 text"
        raise CollectionError(msg) from None
    return text.splitlines()[0] if text else ""


def _need(module: str, extra: str) -> Any:
    import importlib  # noqa: PLC0415

    try:
        return importlib.import_module(module)
    except ImportError as exc:
        msg = (
            f"this secret provider needs {module}; "
            f"install it with: {names.install_hint('live', extra)}"
        )
        raise CollectionError(msg) from exc


def _keyring(location: str) -> str:
    service, sep, username = location.partition("/")
    if not sep:
        msg = "keyring secrets look like keyring:SERVICE/USERNAME"
        raise CollectionError(msg)
    value = _need("keyring", "keyring").get_password(service, username)
    if value is None:
        msg = "no keyring entry for that service and username"
        raise CollectionError(msg)
    return str(value)


def _field(payload: Any, field: str, where: str) -> str:
    if not isinstance(payload, dict) or field not in payload:
        msg = f"the {where} secret has no field {field!r}"
        raise CollectionError(msg)
    return str(payload[field])


def _vault(location: str) -> str:
    path, sep, field = location.partition("#")
    mount, slash, secret_path = path.partition("/")
    if not sep or not slash:
        msg = "vault secrets look like vault:MOUNT/PATH#FIELD"
        raise CollectionError(msg)
    hvac = _need("hvac", "vault")
    try:
        client = hvac.Client(url=os.environ.get("VAULT_ADDR"), token=os.environ.get("VAULT_TOKEN"))
        response = client.secrets.kv.v2.read_secret_version(
            path=secret_path, mount_point=mount, raise_on_deleted_version=True
        )
    except Exception as exc:  # noqa: BLE001 - hvac raises many types
        msg = f"cannot read the Vault secret: {type(exc).__name__}"
        raise CollectionError(msg) from None
    return _field(response.get("data", {}).get("data"), field, "Vault")


def _aws(location: str) -> str:
    secret_id, sep, field = location.partition("#")
    boto3 = _need("boto3", "aws")
    try:
        value = boto3.client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]
    except Exception as exc:  # noqa: BLE001 - botocore raises many types
        msg = f"cannot read the AWS secret: {type(exc).__name__}"
        raise CollectionError(msg) from None
    if not sep:
        return str(value)
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        msg = "the AWS secret is not JSON, so #FIELD cannot be read"
        raise CollectionError(msg) from None
    return _field(payload, field, "AWS")


def _azure(location: str) -> str:
    vault, sep, name = location.partition("/")
    if not sep:
        msg = "azure secrets look like azure:VAULT_NAME/SECRET_NAME"
        raise CollectionError(msg)
    identity = _need("azure.identity", "azure")
    secrets = _need("azure.keyvault.secrets", "azure")
    try:
        client = secrets.SecretClient(
            f"https://{vault}.vault.azure.net", identity.DefaultAzureCredential()
        )
        return str(client.get_secret(name).value)
    except Exception as exc:  # noqa: BLE001 - the Azure SDK raises many types
        msg = f"cannot read the Azure Key Vault secret: {type(exc).__name__}"
        raise CollectionError(msg) from None


_PROVIDERS = {
    "env": _env,
    "file": _file,
    "keyring": _keyring,
    "vault": _vault,
    "aws": _aws,
    "azure": _azure,
}
