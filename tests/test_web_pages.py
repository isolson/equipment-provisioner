"""Smoke tests for rendered web pages."""

from pathlib import Path

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.web.app import create_app


class DummyProvisioner:
    """Minimal provisioner stub for page rendering tests."""

    def __init__(self, config):
        self.config = config


def make_client():
    config = Config()
    app = create_app(provisioner=DummyProvisioner(config))
    return TestClient(app)


def test_dashboard_renders_setup_banner_hook():
    client = make_client()

    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert 'id="setup-readiness-banner"' in html
    assert 'href="/files"' in html
    assert 'href="/labels"' in html
    assert "loadSetupReadiness()" in html


def test_labels_page_renders_guarded_templates():
    client = make_client()

    response = client.get("/labels")
    assert response.status_code == 200
    html = response.text

    assert "WISP Labels" in html
    assert "Outdoor Antenna" in html
    assert "PTP to Building" in html
    assert "Location AP##" in html
    assert "Battery Inventory Date" in html
    assert "DAY MONTH YEAR" in html
    assert "MONTH YEAR" in html
    assert "Anything Else" in html
    assert "virtual-keyboard" in html
    assert "pressVirtualKey" in html
    assert 'inputmode="none"' in html
    assert "TW##-TW##-PTPa" in html
    assert "keyboard-open" in html
    assert "visualViewport" in html
    assert "printBitmap" in html


def test_brady_web_sdk_license_sidecar_is_vendored():
    vendor_dir = (
        Path(__file__).resolve().parents[1]
        / "provisioner"
        / "web"
        / "static"
        / "vendor"
        / "brady-web-sdk"
    )
    bundle = vendor_dir / "bundle.js"
    sidecar = vendor_dir / "bundle.js.LICENSE.txt"

    assert "bundle.js.LICENSE.txt" in bundle.read_text(encoding="utf-8")
    assert sidecar.exists()
    assert "https://sdk.bradyid.com/licences/" in sidecar.read_text(encoding="utf-8")


def test_setup_page_renders_setup_actions():
    client = make_client()

    response = client.get("/setup")
    assert response.status_code == 200
    html = response.text

    assert "Console Settings" in html
    assert "First-Run Readiness" in html
    assert "Import Setup Bundle" in html
    assert "Export Setup Bundle" in html
    assert "Seed Bundled Templates" in html
    assert "Configure MikroTik Switch" in html


def test_manage_page_no_longer_hosts_setup_tools():
    client = make_client()
    html = client.get("/files").text

    assert "Bench Setup Tools" not in html
    assert "Import Setup Bundle" not in html
    assert "Configure MikroTik Switch" not in html
    assert 'href="/setup"' in html


def test_manage_page_uses_vendor_tabs_for_assets():
    client = make_client()

    response = client.get("/files")
    assert response.status_code == 200
    html = response.text

    assert "Manage Vendor Assets" in html
    assert 'id="vendor-tabs"' in html
    assert "showVendor('cambium')" in html
    assert "showVendor('mikrotik')" in html
    assert "showVendor('tachyon')" in html
    assert "showVendor('tarana')" in html
    assert "showVendor('ubiquiti')" in html
    assert "Ubiquiti AirMax/Wave" in html
    assert "Configuration Templates" in html
    assert "Login Credentials" in html

    assert 'id="tab-firmware"' not in html
    assert 'id="tab-configs"' not in html
    assert 'id="tab-credentials"' not in html
    assert 'id="fw-device-type"' not in html
    assert 'id="cfg-device-type"' not in html
    assert 'id="cred-device-type"' not in html


def test_firmware_page_uses_vendor_tabs_and_vendor_check():
    client = make_client()

    response = client.get("/firmware")
    assert response.status_code == 200
    html = response.text

    assert "Firmware Checker" in html
    assert 'id="vendor-tabs"' in html
    assert "showVendor('ubiquiti')" in html
    assert "Check This Vendor" in html
    assert "/api/firmware/check-now?vendor=" in html
    assert 'id="upload-device-type"' not in html


def test_vendor_tabs_render_brand_favicons():
    """Each vendor tab and badge embeds its locally-bundled favicon."""
    client = make_client()
    vendors = ["cambium", "mikrotik", "tachyon", "tarana", "ubiquiti"]

    for page in ("/files", "/firmware"):
        html = client.get(page).text
        for vendor in vendors:
            assert f"/static/vendor-icons/{vendor}.png" in html, (
                f"{page} missing favicon for {vendor}"
            )


def test_vendor_tagging_uses_brand_colors():
    """Cambium and MikroTik use their official brand colors, not the old defaults."""
    client = make_client()

    for page in ("/files", "/firmware"):
        html = client.get(page).text
        assert "#1A73E9" in html, f"{page} missing Cambium brand denim blue"
        assert "#0E0E10" in html, f"{page} missing MikroTik brand near-black"
        assert "--vendor-color:#22c55e" not in html, (
            f"{page} still has the old Cambium green"
        )
        assert "--vendor-color:#3b82f6" not in html, (
            f"{page} still has the old MikroTik Tailwind blue"
        )
