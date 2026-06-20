"""End-to-end CLI tests using Typer's CliRunner.

These exercise the full init -> create -> encrypt -> rotate -> decrypt ->
seal -> unseal -> audit flow through the command line entry point.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ghostvault.cli import PASSPHRASE_ENV, app

runner = CliRunner()
PASSPHRASE = "test-pass-1234"


def _env():
    return {PASSPHRASE_ENV: PASSPHRASE}


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ghostvault" in result.stdout


def test_full_flow(tmp_path):
    vault = str(tmp_path / "vault")
    env = _env()

    r = runner.invoke(app, ["init", "--vault", vault], env=env)
    assert r.exit_code == 0, r.stdout

    r = runner.invoke(app, ["key", "create", "app", "--vault", vault], env=env)
    assert r.exit_code == 0, r.stdout

    secret_in = tmp_path / "plain.txt"
    secret_in.write_bytes(b"top secret payload")
    enc_out = tmp_path / "blob.json"
    r = runner.invoke(
        app,
        [
            "encrypt",
            "--key-id",
            "app",
            "--vault",
            vault,
            "--input",
            str(secret_in),
            "--output",
            str(enc_out),
        ],
        env=env,
    )
    assert r.exit_code == 0, r.stdout
    blob = json.loads(enc_out.read_text())
    assert blob["key_version"] == 1

    r = runner.invoke(app, ["key", "rotate", "app", "--vault", vault], env=env)
    assert r.exit_code == 0, r.stdout

    dec_out = tmp_path / "decrypted.txt"
    r = runner.invoke(
        app,
        [
            "decrypt",
            "--vault",
            vault,
            "--input",
            str(enc_out),
            "--output",
            str(dec_out),
        ],
        env=env,
    )
    assert r.exit_code == 0, r.stdout
    assert dec_out.read_bytes() == b"top secret payload"


def test_cli_wrong_passphrase(tmp_path):
    vault = str(tmp_path / "vault")
    runner.invoke(app, ["init", "--vault", vault], env=_env())
    r = runner.invoke(
        app,
        ["key", "list", "--vault", vault],
        env={PASSPHRASE_ENV: "wrong"},
    )
    assert r.exit_code == 1


def test_cli_seal_unseal(tmp_path):
    vault = str(tmp_path / "vault")
    env = _env()
    runner.invoke(app, ["init", "--vault", vault], env=env)
    runner.invoke(app, ["key", "create", "app", "--vault", vault], env=env)

    secret_in = tmp_path / "sec.txt"
    secret_in.write_bytes(b"db-password-value")
    r = runner.invoke(
        app,
        ["seal", "creds", "--key-id", "app", "--vault", vault, "--input", str(secret_in)],
        env=env,
    )
    assert r.exit_code == 0, r.stdout

    out = tmp_path / "out.txt"
    r = runner.invoke(
        app,
        ["unseal", "creds", "--vault", vault, "--output", str(out)],
        env=env,
    )
    assert r.exit_code == 0, r.stdout
    assert out.read_bytes() == b"db-password-value"


def test_cli_audit_json(tmp_path):
    vault = str(tmp_path / "vault")
    env = _env()
    runner.invoke(app, ["init", "--vault", vault], env=env)
    runner.invoke(app, ["key", "create", "app", "--vault", vault], env=env)
    r = runner.invoke(app, ["audit", "--vault", vault, "--format", "json"], env=env)
    assert r.exit_code == 0, r.stdout
    assert "init" in r.stdout
