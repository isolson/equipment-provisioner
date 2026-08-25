"""Smoke tests for rendered web pages."""

import json
import re
from pathlib import Path

from fastapi.testclient import TestClient

from provisioner.config import Config
from provisioner.handler_manager import provisionable_device_types
from provisioner.web.api import BUILTIN_CREDENTIALS
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
    assert 'aria-label="Dismiss setup readiness notice"' in html
    assert "dismissSetupReadinessBanner()" in html


def test_dashboard_does_not_auto_queue_labels_on_completion():
    """Completion events keep the label payload contract but do not enqueue it.

    The printer queue remains available for manual use and future AP/PTP
    workflow hooks, but provisioning completion is not production-enabled for
    automatic label printing yet.
    """
    client = make_client()
    html = client.get("/").text

    assert "handleCompletedLabel(message.port_number, message.data.label)" not in html
    assert "function handleCompletedLabel(portNumber, rawLabel)" in html


def test_dashboard_persists_and_resets_setup_banner_dismissal():
    client = make_client()
    html = client.get("/").text

    assert "const SETUP_READINESS_DISMISSED_KEY = 'provisionerSetupReadinessDismissed'" in html
    assert "localStorage.setItem(SETUP_READINESS_DISMISSED_KEY, 'true')" in html
    assert "localStorage.removeItem(SETUP_READINESS_DISMISSED_KEY)" in html
    assert "if (isSetupReadinessDismissed())" in html
    assert "if (data?.status === 'ready') clearSetupReadinessDismissal();" in html


def _rendered_device_vendors(html):
    """Parse the server-injected `deviceVendors` literal out of the page."""
    match = re.search(r"const deviceVendors = (\{.*\});", html)
    assert match, (
        "dashboard no longer injects the deviceVendors literal (Story 5 / "
        "#75) — the kiosk would render vendor cards without names/colors/"
        "icons."
    )
    return json.loads(match.group(1))


def test_dashboard_injects_vendor_metadata_for_every_registry_vendor():
    """Story 5 (#75) acceptance: the rendered page carries metadata for
    every HANDLER_MAP vendor plus the documented evolution_digital and
    unknown exceptions, as a parse-time literal (no async fetch race)."""
    client = make_client()

    response = client.get("/")
    assert response.status_code == 200
    vendors = _rendered_device_vendors(response.text)

    expected_keys = set(provisionable_device_types()) | {
        "evolution_digital",
        "unknown",
    }
    assert set(vendors) == expected_keys

    for device_type, entry in vendors.items():
        assert set(entry) == {"name", "color", "defaultUser", "icon"}, (
            f"{device_type} metadata entry missing kiosk fields"
        )
        assert entry["name"]
        assert re.fullmatch(r"#[0-9a-fA-F]{6}", entry["color"])

    # defaultUser hints agree with the credentials source (first builtin
    # entry's username), rather than keeping a third hardcoded copy.
    for device_type in provisionable_device_types():
        builtin = BUILTIN_CREDENTIALS.get(device_type, [])
        expected_user = builtin[0]["username"] if builtin else ""
        assert vendors[device_type]["defaultUser"] == expected_user, (
            f"{device_type} defaultUser hint drifted from the credentials "
            "source"
        )

    # The empty-icon rendering path is preserved for `unknown`.
    assert vendors["unknown"]["icon"] == ""
    # Every other vendor's icon resolves to a bundled static file.
    icons_dir = (
        Path(__file__).resolve().parents[1]
        / "provisioner"
        / "web"
        / "static"
        / "vendor-icons"
    )
    for device_type, entry in vendors.items():
        if device_type == "unknown":
            continue
        assert entry["icon"] == f"/static/vendor-icons/{device_type}.png"
        assert (icons_dir / f"{device_type}.png").is_file()


def test_dashboard_vendor_metadata_renders_identically_to_the_old_map():
    """The kiosk is production: lock the exact pre-#75 name/color/
    defaultUser/icon values so the touchscreen renders identically."""
    client = make_client()
    vendors = _rendered_device_vendors(client.get("/").text)

    assert vendors == {
        "cambium": {
            "name": "Cambium",
            "color": "#1A73E9",
            "defaultUser": "admin",
            "icon": "/static/vendor-icons/cambium.png",
        },
        "mikrotik": {
            "name": "MikroTik",
            "color": "#0E0E10",
            "defaultUser": "admin",
            "icon": "/static/vendor-icons/mikrotik.png",
        },
        "tachyon": {
            "name": "Tachyon",
            "color": "#a855f7",
            "defaultUser": "root",
            "icon": "/static/vendor-icons/tachyon.png",
        },
        "tarana": {
            "name": "Tarana",
            "color": "#d97706",
            "defaultUser": "admin",
            "icon": "/static/vendor-icons/tarana.png",
        },
        "ubiquiti": {
            "name": "Ubiquiti",
            "color": "#0559C9",
            "defaultUser": "ubnt",
            "icon": "/static/vendor-icons/ubiquiti.png",
        },
        "evolution_digital": {
            "name": "Evolution",
            "color": "#ec4899",
            "defaultUser": "",
            "icon": "/static/vendor-icons/evolution_digital.png",
        },
        "unknown": {
            "name": "Unknown",
            "color": "#6b7280",
            "defaultUser": "admin",
            "icon": "",
        },
    }


def test_dashboard_uses_server_owned_workflow_actions():
    """The modal renders capabilities from port workflow state, not a new
    frontend vendor allowlist. Tachyon's SSID preview remains a separate,
    pre-existing mode-config behavior pending its handler-trait migration."""
    client = make_client()
    html = client.get("/").text

    assert "port.device_type === 'cambium' || port.device_type === 'tachyon'" not in html
    assert "workflow.available_actions" in html
    assert "workflow.service_actions" in html
    assert "renderWorkflowActionPanel(portNum, port)" in html
    assert "port.device_type === 'tachyon' ? dir.toUpperCase() : hostname" in html


def test_dashboard_footer_is_contextual_and_touch_friendly():
    client = make_client()
    html = client.get("/").text

    assert "function renderPortModalFooter(portNum, port, printableLabel)" in html
    assert "Retry provisioning" in html
    assert "Enter credentials and retry" in html
    assert "Reprint label" in html
    assert "if (active)" in html
    assert "port.workflow.state !== 'failed'" in html
    assert "MikroTik recovery (Netinstall)" not in html
    assert re.search(r"\.modal-action\s*\{[^}]*min-height:\s*48px", html)
    assert "flex flex-wrap justify-end gap-2" in html
    assert "const canApplyMode" not in html


def test_dashboard_progress_uses_run_specific_validation_plan():
    """The kiosk must not turn nine nullable checklist fields into nine steps."""
    client = make_client()
    html = client.get("/").text

    assert "port.step_plan" in html
    assert "port.step_status" in html
    assert "cl[k] === undefined || cl[k] === null" in html
    assert "return { done, total: plan.length };" in html


def test_dashboard_rechecks_identity_before_showing_preserved_complete():
    """Rapid swaps must render BOOTING while the returning MAC is unknown.

    The backend intentionally preserves a successful result during reboot
    grace. The kiosk must not let that old result visually outrank the boot
    wait for a newly connected, not-yet-identified unit.
    """
    client = make_client()
    html = client.get("/").text

    card_state = html.split("function getCardState(port) {", 1)[1].split(
        "function getIconState", 1
    )[0]
    assert card_state.index("if (port.waiting_for_boot)") < card_state.index(
        "port.last_result === 'complete'"
    )

    status_center = html.split("function getStatusCenterInfo(port, portNum) {", 1)[1].split(
        "function statusIconSVG", 1
    )[0]
    assert status_center.index("if (port.waiting_for_boot)") < status_center.index(
        "const isDone"
    )
    assert "Checking connected device..." in status_center
    assert "Waiting for link..." in status_center


def test_dashboard_requires_verified_config_before_deploy_ready():
    """Firmware-only success must not be presented as deployable.

    Cambium and Tachyon can finish firmware work without a resolved config.
    Treat that as a missing SM baseline and keep AP/PTP conversion locked
    until standard SM configuration has been applied and verified.
    """
    client = make_client()
    html = client.get("/").text

    status_center = html.split("function getStatusCenterInfo(port, portNum) {", 1)[1].split(
        "function statusIconSVG", 1
    )[0]
    assert "port.workflow?.state === 'config_required'" in html
    assert "port.workflow?.state === 'config_unverified'" in html
    assert "`${baselineMode} CONFIG MISSING`" in status_center
    assert "sub: 'Cannot deploy'" in status_center
    assert "`${baselineMode} CONFIG UNVERIFIED`" in status_center
    assert "sub = 'Ready to deploy'" in status_center
    assert "port.workflow.baseline_mode.toUpperCase()" in status_center
    assert "function deploymentReadiness" not in html
    assert "supportsModeConfiguration" not in html
    assert "const requiresBaseline = Boolean(port.workflow?.baseline_mode)" in html


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
