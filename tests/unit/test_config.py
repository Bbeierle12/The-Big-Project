"""Test configuration loading."""
import pytest
from pathlib import Path
from netsec.core.config import load_settings, Settings


def test_default_settings():
    """Settings should load with defaults."""
    settings = Settings()
    assert settings.server.host == "127.0.0.1"
    assert settings.server.port == 8420
    assert settings.database.url.startswith("sqlite")


def test_load_from_config_dir(tmp_path: Path):
    """Settings should load from TOML files."""
    default = tmp_path / "default.toml"
    default.write_text("""
[server]
host = "0.0.0.0"
port = 9000
""")
    settings = load_settings(config_dir=tmp_path)
    assert settings.server.host == "0.0.0.0"
    assert settings.server.port == 9000


def test_local_overrides(tmp_path: Path):
    """Local config should override defaults."""
    default = tmp_path / "default.toml"
    default.write_text("""
[server]
host = "127.0.0.1"
port = 8420
""")
    local = tmp_path / "local.toml"
    local.write_text("""
[server]
port = 9999
""")
    settings = load_settings(config_dir=tmp_path)
    assert settings.server.host == "127.0.0.1"  # from default
    assert settings.server.port == 9999  # overridden
