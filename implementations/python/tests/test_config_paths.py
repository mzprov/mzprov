"""Default key and registry locations moved from ~/.config/timsim/ to
~/.config/mzprov/ in 0.1.2. An existing legacy key or registry is used in
place, never copied, so upgrading does not create a second identity."""
import pytest

from mzprov.keys import default_key_dir, generate_keypair, load_or_create_keypair, write_keypair
from mzprov.trust import default_registry_path


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


def test_fresh_install_uses_mzprov_dir(config):
    assert default_key_dir() == config / "mzprov" / "keys"
    assert default_registry_path() == config / "mzprov" / "trusted_keys.json"


def test_first_key_is_generated_in_mzprov_dir(config):
    kp = load_or_create_keypair(default_key_dir())
    assert (config / "mzprov" / "keys" / "signing_key.pem").is_file()
    assert not (config / "timsim").exists()
    assert kp.key_id.startswith("timsim-local-")  # key-id format is frozen v0


def test_legacy_key_is_used_in_place(config):
    legacy = config / "timsim" / "keys"
    original = generate_keypair()
    write_keypair(original, legacy)

    assert default_key_dir() == legacy
    assert load_or_create_keypair(default_key_dir()).key_id == original.key_id
    assert not (config / "mzprov").exists()  # nothing copied


def test_new_key_wins_over_legacy(config):
    write_keypair(generate_keypair(), config / "timsim" / "keys")
    new = generate_keypair()
    write_keypair(new, config / "mzprov" / "keys")
    assert default_key_dir() == config / "mzprov" / "keys"
    assert load_or_create_keypair(default_key_dir()).key_id == new.key_id


def test_legacy_registry_is_used_in_place(config):
    legacy = config / "timsim" / "trusted_keys.json"
    legacy.parent.mkdir(parents=True)
    legacy.write_text('{"schema": "timsim.trusted_keys/v0", "keys": []}')
    assert default_registry_path() == legacy

    new = config / "mzprov" / "trusted_keys.json"
    new.parent.mkdir(parents=True)
    new.write_text('{"schema": "timsim.trusted_keys/v0", "keys": []}')
    assert default_registry_path() == new
