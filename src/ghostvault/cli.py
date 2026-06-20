"""Typer-based command line interface for ghostvault."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .vault import (
    DEFAULT_VAULT_DIR,
    Vault,
    VaultError,
    WrongPassphraseError,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="ghostvault: a key management system with envelope encryption.",
)
key_app = typer.Typer(no_args_is_help=True, help="Manage keys (KEKs).")
app.add_typer(key_app, name="key")

console = Console()
err_console = Console(stderr=True)

PASSPHRASE_ENV = "GHOSTVAULT_PASSPHRASE"

logger = logging.getLogger("ghostvault")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _get_passphrase(confirm: bool = False) -> str:
    """Read the passphrase from the environment variable or prompt for it."""
    env_value = os.environ.get(PASSPHRASE_ENV)
    if env_value is not None:
        return env_value
    passphrase = typer.prompt("Passphrase", hide_input=True)
    if confirm:
        again = typer.prompt("Confirm passphrase", hide_input=True)
        if passphrase != again:
            err_console.print("[red]error:[/red] passphrases do not match")
            raise typer.Exit(code=1)
    return passphrase


def _fail(message: str) -> None:
    err_console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=1)


def _open_vault(vault_path: Path) -> Vault:
    passphrase = _get_passphrase()
    try:
        return Vault.open(vault_path, passphrase)
    except WrongPassphraseError:
        _fail("incorrect passphrase")
    except VaultError as exc:
        _fail(str(exc))
    raise AssertionError("unreachable")


@app.command()
def version() -> None:
    """Show the ghostvault version."""
    console.print(f"ghostvault {__version__}")


@app.command()
def init(
    vault: Path = typer.Option(
        Path(DEFAULT_VAULT_DIR), "--vault", help="Path to the vault directory."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging."),
) -> None:
    """Create a new vault."""
    _configure_logging(verbose)
    passphrase = _get_passphrase(confirm=True)
    try:
        Vault.init(vault, passphrase)
    except VaultError as exc:
        _fail(str(exc))
    console.print(f"Initialized vault at [bold]{vault}[/bold]")


@key_app.command("create")
def key_create(
    key_id: str = typer.Argument(..., help="Identifier for the new key."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Create a new key (KEK)."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    try:
        desc = v.create_key(key_id)
    except VaultError as exc:
        _fail(str(exc))
    console.print(
        f"Created key [bold]{desc.key_id}[/bold] "
        f"({desc.algorithm}, version {desc.latest_version}, {desc.state})"
    )


@key_app.command("list")
def key_list(
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table or json."
    ),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """List keys in the vault."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    keys = v.list_keys()
    if output_format == "json":
        payload = [
            {
                "key_id": k.key_id,
                "algorithm": k.algorithm,
                "state": k.state,
                "latest_version": k.latest_version,
                "versions": [ver.version for ver in k.versions],
                "created_at": k.created_at,
                "rotated_at": k.rotated_at,
            }
            for k in keys
        ]
        console.print_json(json.dumps(payload))
        return
    if not keys:
        console.print("No keys in vault.")
        return
    table = Table(title="Keys")
    table.add_column("Key ID")
    table.add_column("Algorithm")
    table.add_column("State")
    table.add_column("Latest")
    table.add_column("Versions")
    table.add_column("Rotated")
    for k in keys:
        table.add_row(
            k.key_id,
            k.algorithm,
            k.state,
            str(k.latest_version),
            ",".join(str(ver.version) for ver in k.versions),
            k.rotated_at,
        )
    console.print(table)


@key_app.command("rotate")
def key_rotate(
    key_id: str = typer.Argument(..., help="Key to rotate."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Create a new version of a key. New encryptions use the new version."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    try:
        desc = v.rotate_key(key_id)
    except VaultError as exc:
        _fail(str(exc))
    console.print(
        f"Rotated key [bold]{desc.key_id}[/bold] to version {desc.latest_version}"
    )


@key_app.command("disable")
def key_disable(
    key_id: str = typer.Argument(..., help="Key to disable."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Disable a key. Disabled keys cannot be used for new encryption."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    try:
        v.disable_key(key_id)
    except VaultError as exc:
        _fail(str(exc))
    console.print(f"Disabled key [bold]{key_id}[/bold]")


def _read_input(input_path: Path | None) -> bytes:
    if input_path is None or str(input_path) == "-":
        return sys.stdin.buffer.read()
    return Path(input_path).read_bytes()


def _write_output(output_path: Path | None, data: bytes) -> None:
    if output_path is None or str(output_path) == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        Path(output_path).write_bytes(data)


@app.command()
def encrypt(
    key_id: str = typer.Option(..., "--key-id", help="Key to encrypt under."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    input_path: Path | None = typer.Option(
        None, "--input", help="Input file, or - for stdin."
    ),
    output_path: Path | None = typer.Option(
        None, "--output", help="Output file, or - for stdout."
    ),
    context: str = typer.Option("", "--context", help="AAD context to bind."),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Envelope-encrypt data. Output is a self-describing JSON blob."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    plaintext = _read_input(input_path)
    try:
        blob = v.encrypt(key_id, plaintext, context=context)
    except VaultError as exc:
        _fail(str(exc))
    _write_output(output_path, (json.dumps(blob) + "\n").encode("utf-8"))


@app.command()
def decrypt(
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    input_path: Path | None = typer.Option(
        None, "--input", help="Encrypted blob file, or - for stdin."
    ),
    output_path: Path | None = typer.Option(
        None, "--output", help="Output file, or - for stdout."
    ),
    context: str | None = typer.Option(
        None, "--context", help="AAD context (must match encryption)."
    ),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Decrypt a ghostvault envelope blob. Fails closed on any tampering."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    raw = _read_input(input_path)
    try:
        blob = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _fail("input is not a valid ghostvault envelope blob")
    from .crypto import CryptoError

    try:
        plaintext = v.decrypt(blob, context=context)
    except CryptoError:
        _fail("decryption failed: wrong key, wrong context, or tampered data")
    except VaultError as exc:
        _fail(str(exc))
    _write_output(output_path, plaintext)


@app.command()
def seal(
    name: str = typer.Argument(..., help="Name for the sealed secret."),
    key_id: str = typer.Option(..., "--key-id", help="Key to seal under."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    input_path: Path | None = typer.Option(
        None, "--input", help="Secret input file, or - for stdin."
    ),
    context: str = typer.Option("", "--context", help="AAD context to bind."),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Seal (encrypt and store) a named secret in the vault."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    secret = _read_input(input_path)
    try:
        v.seal(name, secret, key_id, context=context)
    except VaultError as exc:
        _fail(str(exc))
    console.print(f"Sealed secret [bold]{name}[/bold]")


@app.command()
def unseal(
    name: str = typer.Argument(..., help="Name of the sealed secret."),
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    output_path: Path | None = typer.Option(
        None, "--output", help="Output file, or - for stdout."
    ),
    context: str | None = typer.Option(
        None, "--context", help="AAD context (must match seal)."
    ),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Unseal (retrieve and decrypt) a named secret from the vault."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    from .crypto import CryptoError

    try:
        secret = v.unseal(name, context=context)
    except CryptoError:
        _fail("unseal failed: wrong context or tampered data")
    except VaultError as exc:
        _fail(str(exc))
    _write_output(output_path, secret)


@app.command()
def audit(
    vault: Path = typer.Option(Path(DEFAULT_VAULT_DIR), "--vault"),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table or json."
    ),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Show the audit log."""
    _configure_logging(verbose)
    v = _open_vault(vault)
    entries = v.read_audit()
    if output_format == "json":
        console.print_json(json.dumps(entries))
        return
    if not entries:
        console.print("No audit entries.")
        return
    table = Table(title="Audit log")
    table.add_column("Timestamp")
    table.add_column("Operation")
    table.add_column("Key ID")
    table.add_column("Success")
    table.add_column("Detail")
    for e in entries:
        table.add_row(
            e.get("ts", ""),
            e.get("op", ""),
            str(e.get("key_id") or ""),
            "yes" if e.get("success") else "no",
            e.get("detail", ""),
        )
    console.print(table)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
