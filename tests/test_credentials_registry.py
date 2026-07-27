"""Characterization tests for vendor credential defaults (Story #73).

Credentials are currently duplicated across four hand-maintained sources:
``CredentialsConfig`` (config.py), the assembly dict in main.py,
``BUILTIN_CREDENTIALS`` (web/api.py), and each handler's
``DEFAULT_CREDENTIALS``. Story #73 collapses the first three into one
defaults factory.

These tests pin the *effective* values and the consumers that read them, so
the collapse is provably behavior-preserving everywhere it is supposed to
be — and loudly not, in the one place where a deliberate decision changes
it (tarana; see ``TestTaranaDecision``).

Only hardcoded factory defaults from source are asserted here. Nothing reads
config.yaml or the environment, and no real secret is referenced.
"""

import pytest

from provisioner.config import Config, CredentialsConfig
from provisioner import setup_tools
from provisioner.handlers.mikrotik import MikrotikHandler
from provisioner.handlers.tachyon import TachyonHandler
from provisioner.web.api import BUILTIN_CREDENTIALS

# The four vendors whose defaults must survive the collapse untouched.
# tarana is deliberately excluded — it is the one value that changes.
STABLE_DEFAULTS = {
    "cambium": ("admin", "admin"),
    "mikrotik": ("admin", ""),
    "tachyon": ("root", "admin"),
    "ubiquiti": ("ubnt", "ubnt"),
}


class TestConfigDefaults:
    """CredentialsConfig is the source the collapse folds into."""

    @pytest.mark.parametrize("vendor,expected", sorted(STABLE_DEFAULTS.items()))
    def test_vendor_default_is_unchanged(self, vendor, expected):
        entry = CredentialsConfig().for_vendor(vendor)
        assert (entry.username, entry.password) == expected

    def test_every_vendor_has_the_ztp_fields(self):
        """bootstrap_password / onboarding_password live on the shared
        DeviceCredentials model. The collapse must keep the value type, not
        just the keys — MikroTik ZTP reads these."""
        creds = CredentialsConfig()
        for vendor in list(STABLE_DEFAULTS) + ["tarana"]:
            entry = creds.for_vendor(vendor)
            assert hasattr(entry, "bootstrap_password")
            assert hasattr(entry, "onboarding_password")

    def test_env_expansion_still_applies(self, monkeypatch):
        """The ${VAR} validator must survive the shape change. Asserts only
        that expansion occurred, never a secret value."""
        monkeypatch.setenv("PROVISIONER_TEST_SENTINEL", "expanded-sentinel")
        creds = CredentialsConfig(
            mikrotik={"bootstrap_password": "${PROVISIONER_TEST_SENTINEL}"}
        )
        assert creds.for_vendor("mikrotik").bootstrap_password == "expanded-sentinel"

    def test_unknown_vendor_returns_defaults_rather_than_raising(self):
        entry = CredentialsConfig().for_vendor("not-a-vendor")
        assert (entry.username, entry.password) == ("admin", "")

    def test_adding_a_vendor_requires_no_main_py_edit(self):
        """The S1 crash-coupling this story exists to kill: main.py must
        derive its handler-manager dict from the table, not restate it."""
        import re
        from pathlib import Path

        main_src = Path(__file__).resolve().parent.parent / "provisioner" / "main.py"
        text = main_src.read_text()
        for vendor in list(STABLE_DEFAULTS) + ["tarana"]:
            assert not re.search(rf'"{vendor}":\s*\{{\s*\n\s*"username"', text), (
                f"main.py still hardcodes a credentials entry for {vendor}"
            )


class TestLegacyConfigCompat:
    """Existing /etc/provisioner/config.yaml files spell credentials as flat
    top-level keys. extra='ignore' would drop them silently, so the
    mode='before' validator hoists them."""

    def test_legacy_flat_keys_are_hoisted(self):
        creds = CredentialsConfig(tachyon={"password": "host-configured"})
        assert creds.for_vendor("tachyon").password == "host-configured"

    def test_legacy_partial_block_keeps_default_username(self):
        """A legacy block setting only `password:` must not blank the
        vendor's default username."""
        creds = CredentialsConfig(tachyon={"password": "host-configured"})
        assert creds.for_vendor("tachyon").username == "root"

    def test_unspecified_vendors_are_backfilled(self):
        creds = CredentialsConfig(tachyon={"password": "host-configured"})
        assert creds.for_vendor("ubiquiti").username == "ubnt"

    def test_new_nested_shape_also_works(self):
        creds = CredentialsConfig(vendors={"tachyon": {"password": "nested"}})
        assert creds.for_vendor("tachyon").password == "nested"
        assert creds.for_vendor("tachyon").username == "root"


class TestTaranaDecision:
    """DELIBERATE BEHAVIOR CHANGE (#73).

    Before this story the four sources disagreed for tarana: config.py
    shipped an empty password while api.py's BUILTIN_CREDENTIALS and
    TaranaHandler.DEFAULT_CREDENTIALS both shipped ``admin123``. Collapsing
    to one table forced a choice; ``admin123`` won because it is what
    actually logs into hardware.

    The cost is that ``_read_primary_credentials`` would have reported
    tarana as "Configured" for a fleet still on factory credentials — so the
    factory-default check was widened to cover every vendor, derived from
    the same table. These tests pin both halves.
    """

    def test_config_default_now_matches_the_handler(self):
        entry = CredentialsConfig().for_vendor("tarana")
        assert (entry.username, entry.password) == ("admin", "admin123")

    def test_builtin_credentials_agree(self):
        assert BUILTIN_CREDENTIALS["tarana"] == [
            {"username": "admin", "password": "admin123"}
        ]

    def test_factory_default_tarana_is_still_flagged_in_setup_ui(self):
        """The false-green this decision could have bought. Must stay red."""
        rows = setup_tools._read_primary_credentials(Config())
        tarana = {row["device_type"]: row for row in rows}["tarana"]
        assert tarana["status"] == "warning"
        assert tarana["summary"] == "Still using factory default"

    def test_a_real_fleet_password_reads_as_configured(self):
        config = Config()
        config.credentials.for_vendor("tarana").password = "operator-chosen-pw"
        rows = setup_tools._read_primary_credentials(config)
        tarana = {row["device_type"]: row for row in rows}["tarana"]
        assert tarana["status"] == "ready"


class TestBuiltinCredentialsAgreement:
    """BUILTIN_CREDENTIALS (the /default-credentials UI source) must keep
    agreeing with config.py for the four stable vendors."""

    @pytest.mark.parametrize("vendor,expected", sorted(STABLE_DEFAULTS.items()))
    def test_builtin_matches_config_default(self, vendor, expected):
        entries = BUILTIN_CREDENTIALS[vendor]
        assert (entries[0]["username"], entries[0]["password"]) == expected

    def test_mikrotik_entry_count_is_pinned(self):
        """MikrotikHandler.DEFAULT_CREDENTIALS is a *list* of login candidates,
        unlike every other vendor's single dict. A factory-derived
        BUILTIN_CREDENTIALS must not assume one credential per vendor."""
        assert len(MikrotikHandler.DEFAULT_CREDENTIALS) == 2
        assert {"username": "admin", "password": "admin"} in MikrotikHandler.DEFAULT_CREDENTIALS
        assert len(BUILTIN_CREDENTIALS["mikrotik"]) == 1

    def test_tachyon_handler_default_is_a_single_dict(self):
        assert TachyonHandler.DEFAULT_CREDENTIALS == {
            "username": "root",
            "password": "admin",
        }


class TestSetupReadinessConsumer:
    """setup_tools.py:88 reads credentials via nested getattr with a default,
    so a shape change degrades SILENTLY rather than raising. This is the
    regression these tests exist to catch."""

    def test_reads_real_config_not_none(self):
        rows = setup_tools._read_primary_credentials(Config())
        by_vendor = {row["device_type"]: row for row in rows}

        assert set(by_vendor) == set(setup_tools.SUPPORTED_DEVICE_TYPES)

        # If the accessor silently returns None, every username collapses to
        # the "admin" fallback and has_password goes uniformly False.
        assert by_vendor["tachyon"]["username"] == "root"
        assert by_vendor["ubiquiti"]["username"] == "ubnt"
        assert by_vendor["cambium"]["has_password"] is True
        assert by_vendor["ubiquiti"]["has_password"] is True

    def test_factory_default_passwords_are_flagged(self):
        rows = setup_tools._read_primary_credentials(Config())
        by_vendor = {row["device_type"]: row for row in rows}
        for vendor in ("cambium", "tachyon", "ubiquiti"):
            assert by_vendor[vendor]["status"] == "warning"
            assert by_vendor[vendor]["summary"] == "Still using factory default"


class TestSwitchProbeConsumer:
    """setup_tools.py:327 is the second silent getattr site: if it degrades
    to "", the probe stops trying the configured switch password and a
    configured switch reports as absent."""

    def test_configured_password_reaches_the_probe(self, monkeypatch):
        import librouteros

        tried = []

        def fake_connect(**kwargs):
            tried.append(kwargs["password"])
            raise OSError("refused")

        monkeypatch.setattr(librouteros, "connect", fake_connect)
        monkeypatch.setattr(setup_tools, "_tcp_connect", lambda *a, **k: True)

        config = Config()
        config.credentials.for_vendor("mikrotik").password = "configured-switch-pw"
        setup_tools.probe_mikrotik_switch(config)

        # Configured password must be tried first, factory-empty as fallback.
        assert tried == ["configured-switch-pw", ""]
