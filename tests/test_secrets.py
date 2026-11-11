# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Secret references and redaction. Ported from merilo, where these were reviewed."""

from __future__ import annotations

import json
import sys
import types
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import quote

import pytest

from faithful_toledot.collect import secrets
from faithful_toledot.errors import CollectionError

if TYPE_CHECKING:
    from pathlib import Path

SECRET = "s3cr3t-value"  # noqa: S105 - synthetic


def hide(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make importing a module fail, as if it were not installed."""
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)


def install(monkeypatch: pytest.MonkeyPatch, name: str, **attributes: Any) -> types.ModuleType:
    """Put a fake module in ``sys.modules`` for the duration of a test."""
    module = types.ModuleType(name)
    for key, value in attributes.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def fake_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOLEDOT_TEST_PASSWORD", SECRET)


def resolve_error(reference: str) -> str:
    with pytest.raises(CollectionError) as exc:
        secrets.resolve(reference)
    return str(exc.value)


@pytest.mark.usefixtures("fake_env")
def test_env_secret() -> None:
    assert secrets.resolve("env:TOLEDOT_TEST_PASSWORD") == SECRET


def test_env_secret_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOLEDOT_TEST_MISSING", raising=False)
    assert (
        resolve_error("env:TOLEDOT_TEST_MISSING")
        == "environment variable TOLEDOT_TEST_MISSING is not set"
    )
    monkeypatch.setenv("TOLEDOT_TEST_EMPTY", "")
    assert resolve_error("env:TOLEDOT_TEST_EMPTY") == "the env secret is empty"


def test_file_secret_uses_the_first_line(tmp_path: Path) -> None:
    path = tmp_path / "secret.txt"
    path.write_text(f"{SECRET}\nsecond line\n", encoding="utf-8")
    assert secrets.resolve(f"file:{path}") == SECRET


@pytest.mark.parametrize("content", ["", "\n", "\nsecond"])
def test_file_secret_empty_first_line(tmp_path: Path, content: str) -> None:
    path = tmp_path / "secret.txt"
    path.write_text(content, encoding="utf-8")
    assert resolve_error(f"file:{path}") == "the file secret is empty"


def test_file_secret_missing(tmp_path: Path) -> None:
    message = resolve_error(f"file:{tmp_path / 'absent.txt'}")
    assert message.startswith("cannot read the secret file: ")


@pytest.mark.parametrize("reference", ["nocolon", "unknown:thing", "env:", ":x", ""])
def test_malformed_references(reference: str) -> None:
    message = resolve_error(reference)
    assert message.startswith("secret reference must look like PROVIDER:LOCATION")
    assert "env, file, keyring, vault, aws, azure" in message


def test_every_provider_is_registered() -> None:
    assert set(secrets.PROVIDERS) == {"env", "file", "keyring", "vault", "aws", "azure"}


@pytest.mark.parametrize(
    ("reference", "modules", "extra"),
    [
        ("keyring:svc/user", ["keyring"], "keyring"),
        ("vault:secret/path#field", ["hvac"], "vault"),
        ("aws:id", ["boto3"], "aws"),
        ("azure:vault/name", ["azure.identity"], "azure"),
    ],
)
def test_missing_provider_package_names_the_extra(
    monkeypatch: pytest.MonkeyPatch, reference: str, modules: list[str], extra: str
) -> None:
    hide(monkeypatch, *modules)
    module = modules[0]
    assert resolve_error(reference) == (
        f"this secret provider needs {module}; "
        f'install it with: pip install "faithful-toledot[{extra}]"'
    )


def test_keyring_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, str]] = []

    def get_password(service: str, username: str) -> str | None:
        seen.append((service, username))
        return SECRET if (service, username) == ("toledot", "CORP/auditor") else None

    install(monkeypatch, "keyring", get_password=get_password)
    assert secrets.resolve("keyring:toledot/CORP/auditor") == SECRET
    assert seen == [("toledot", "CORP/auditor")]
    assert (
        resolve_error("keyring:toledot/other") == "no keyring entry for that service and username"
    )
    assert resolve_error("keyring:toledot") == "keyring secrets look like keyring:SERVICE/USERNAME"


class FakeVault:
    """A stand-in for the hvac client that records what it was asked."""

    calls: ClassVar[list[dict[str, Any]]] = []
    response: ClassVar[Any] = {"data": {"data": {"password": SECRET}}}
    error: ClassVar[Exception | None] = None

    def __init__(self, url: str | None, token: str | None) -> None:
        self.url, self.token = url, token
        self.secrets = types.SimpleNamespace(
            kv=types.SimpleNamespace(v2=types.SimpleNamespace(read_secret_version=self.read))
        )

    def read(self, **kwargs: Any) -> Any:
        FakeVault.calls.append({"url": self.url, "token": self.token, **kwargs})
        if FakeVault.error:
            raise FakeVault.error
        return FakeVault.response


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> type[FakeVault]:
    FakeVault.calls = []
    FakeVault.response = {"data": {"data": {"password": SECRET}}}
    FakeVault.error = None
    install(monkeypatch, "hvac", Client=FakeVault)
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    monkeypatch.setenv("VAULT_TOKEN", "token-123")
    return FakeVault


def test_vault_secret(vault: type[FakeVault]) -> None:
    assert secrets.resolve("vault:secret/ad/auditor#password") == SECRET
    assert vault.calls == [
        {
            "url": "https://vault.example.com",
            "token": "token-123",
            "path": "ad/auditor",
            "mount_point": "secret",
            "raise_on_deleted_version": True,
        }
    ]


def test_vault_errors(vault: type[FakeVault]) -> None:
    assert (
        resolve_error("vault:secret/ad/auditor") == "vault secrets look like vault:MOUNT/PATH#FIELD"
    )
    assert (
        resolve_error("vault:secret#password") == "vault secrets look like vault:MOUNT/PATH#FIELD"
    )
    assert resolve_error("vault:secret/ad#other") == "the Vault secret has no field 'other'"
    vault.response = {}
    assert resolve_error("vault:secret/ad#password") == "the Vault secret has no field 'password'"
    vault.response = {"data": {"data": "not a mapping"}}
    assert resolve_error("vault:secret/ad#password") == "the Vault secret has no field 'password'"


def test_vault_failures_do_not_leak_the_secret(vault: type[FakeVault]) -> None:
    vault.error = RuntimeError(f"permission denied for token {SECRET}")
    message = resolve_error("vault:secret/ad#password")
    assert message == "cannot read the Vault secret: RuntimeError"
    assert SECRET not in message


class FakeBoto:
    """A stand-in for boto3 with one Secrets Manager secret."""

    def __init__(self, secret: Any = None, error: Exception | None = None) -> None:
        self.secret, self.error = secret, error
        self.requested: list[tuple[str, str]] = []

    def client(self, service: str) -> FakeBoto:
        self.requested.append(("client", service))
        return self

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:  # noqa: N803 - boto3's name
        self.requested.append(("secret", SecretId))
        if self.error:
            raise self.error
        return {"SecretString": self.secret}


def test_aws_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    boto = FakeBoto(SECRET)
    install(monkeypatch, "boto3", client=boto.client)
    assert secrets.resolve("aws:prod/ad") == SECRET
    assert boto.requested == [("client", "secretsmanager"), ("secret", "prod/ad")]


def test_aws_json_field(monkeypatch: pytest.MonkeyPatch) -> None:
    boto = FakeBoto(json.dumps({"password": SECRET, "user": "x"}))
    install(monkeypatch, "boto3", client=boto.client)
    assert secrets.resolve("aws:prod/ad#password") == SECRET
    assert resolve_error("aws:prod/ad#missing") == "the AWS secret has no field 'missing'"


def test_aws_errors_do_not_leak_the_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    boto = FakeBoto(SECRET)
    install(monkeypatch, "boto3", client=boto.client)
    message = resolve_error("aws:prod/ad#field")
    assert message == "the AWS secret is not JSON, so #FIELD cannot be read"
    assert SECRET not in message
    failing = FakeBoto(error=ValueError(f"bad {SECRET}"))
    install(monkeypatch, "boto3", client=failing.client)
    message = resolve_error("aws:prod/ad")
    assert message == "cannot read the AWS secret: ValueError"
    assert SECRET not in message


class FakeAzure:
    """A stand-in for the Azure Key Vault secret client."""

    created: ClassVar[list[tuple[str, object]]] = []
    error: ClassVar[Exception | None] = None

    def __init__(self, url: str, credential: object) -> None:
        FakeAzure.created.append((url, credential))

    def get_secret(self, name: str) -> types.SimpleNamespace:
        if FakeAzure.error:
            raise FakeAzure.error
        return types.SimpleNamespace(value=SECRET if name == "ad-password" else "")


def install_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeAzure.created = []
    FakeAzure.error = None
    install(monkeypatch, "azure.identity", DefaultAzureCredential=lambda: "credential")
    install(monkeypatch, "azure.keyvault.secrets", SecretClient=FakeAzure)


def test_azure_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    install_azure(monkeypatch)
    assert secrets.resolve("azure:corpvault/ad-password") == SECRET
    assert FakeAzure.created == [("https://corpvault.vault.azure.net", "credential")]


def test_azure_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    install_azure(monkeypatch)
    assert (
        resolve_error("azure:corpvault") == "azure secrets look like azure:VAULT_NAME/SECRET_NAME"
    )
    assert resolve_error("azure:corpvault/other") == "the azure secret is empty"
    FakeAzure.error = RuntimeError(f"denied {SECRET}")
    message = resolve_error("azure:corpvault/ad-password")
    assert message == "cannot read the Azure Key Vault secret: RuntimeError"
    assert SECRET not in message


def test_second_azure_package_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, "azure.identity", DefaultAzureCredential=object)
    hide(monkeypatch, "azure.keyvault.secrets")
    assert "needs azure.keyvault.secrets" in resolve_error("azure:v/s")


LEAKY = 'p@ss w/rd%"\\\u00fc'  # every encoding of this differs


def test_redact_removes_every_form_of_a_resolved_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "_resolved", set())
    monkeypatch.setenv("TOLEDOT_TEST_SECRET", LEAKY)
    assert secrets.resolve("env:TOLEDOT_TEST_SECRET") == LEAKY
    forms = [LEAKY, quote(LEAKY, safe=""), quote(LEAKY), json.dumps(LEAKY), repr(LEAKY)]
    text = secrets.redact(" | ".join(forms) + " | harmless")
    assert text.endswith("| harmless")
    for fragment in ("p@ss", "p%40ss", "w/rd", "rd%"):
        assert fragment not in text
    assert secrets.redact("nothing secret") == "nothing secret"


def test_remember_adds_a_secret_given_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(secrets, "_resolved", set())
    secrets.remember("")
    secrets.remember("direct-secret")
    assert secrets.redact("x direct-secret y") == "x [redacted] y"
