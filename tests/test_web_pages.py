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


def test_dashboard_renders_setup_banner_without_label_controls():
    client = make_client()

    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    assert 'id="setup-readiness-banner"' in html
    assert 'href="/files"' in html
    assert 'href="/labels"' not in html
    assert 'id="label-printer-button"' not in html
    assert 'onclick="connectLabelPrinter()"' not in html
    assert "Reprint label" not in html
    assert "initLabelPrinterUi();" not in html
    assert "loadSetupReadiness()" in html
    assert 'aria-label="Dismiss setup readiness notice"' in html
    assert "dismissSetupReadinessBanner()" in html


def test_dashboard_does_not_auto_queue_labels_on_completion():
    """Completion events keep the label payload contract but do not enqueue it."""
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


def test_dashboard_uses_the_light_operations_console_theme():
    """The rebuilt kiosk is a light, high-contrast console (outdoor 7-inch panel)."""
    html = make_client().get("/").text

    assert "--bg: #eef1f6" in html
    assert "--panel: #ffffff" in html
    assert "--tone-success: #15803d" in html
    assert "--tone-error: #b91c1c" in html
    assert 'class="card-rail"' in html
    assert 'id="deployed-version"' in html
    assert 'id="stale-banner"' in html
    # No dark surfaces and no pastel-on-dark ink remain.
    assert "#0b1220" not in html
    assert "#fde68a" not in html
    assert "background: #f5f5f5" not in html
    assert "@media (orientation: portrait)" in html


def test_dashboard_renders_server_owned_presentation_and_seeds_ports():
    html = make_client().get("/").text

    assert "const INITIAL_PORTS = " in html
    assert "function presentationForPort(port)" in html
    assert "port.presentation && port.presentation.phase" in html
    assert "function updatePortCard(n)" in html
    assert "if (lastCardSig[n] === sig) return;" in html
    # Legacy client-side state machines are gone.
    assert "function getCardState" not in html
    assert "function getStatusCenterInfo" not in html
    assert "function getStepProgress" not in html
    assert "portActivityLogs" not in html


def test_dashboard_timeline_comes_from_the_server_event_log():
    html = make_client().get("/").text

    assert "/api/ports/${portNum}/events?since=" in html
    assert "case 'port_event':" in html
    assert "function appendEvent(portNum, event)" in html
    assert "function renderTimeline(portNum)" in html


def test_dashboard_uses_server_owned_workflow_actions_and_reasons():
    html = make_client().get("/").text

    assert "port.device_type === 'cambium' || port.device_type === 'tachyon'" not in html
    assert "workflow.available_actions" in html
    assert "workflow.service_actions" in html
    assert "workflow.unqualified" in html
    assert "renderWorkflowActionPanel(selectedPort, port)" in html
    assert "dir.toUpperCase()" not in html


def test_dashboard_has_one_mode_change_flow_with_preview_and_confirm():
    html = make_client().get("/").text

    assert "function openModeChange(portNum, targetMode)" in html
    assert "/api/ports/${v.port}/mode-preview" in html
    assert "/api/ports/${v.port}/apply-mode" in html
    assert "function renderModeConfirm()" in html
    assert "function renderModeProgress()" in html
    assert "Restore SM Config" in html
    assert "action.id === 'configure_sm'" not in html
    assert "function openAPModal" not in html
    assert "function openPTPModal" not in html
    assert "function openSMModal" not in html


def test_dashboard_never_uses_native_dialogs_or_dead_endpoints():
    html = make_client().get("/").text

    assert "alert(" not in html
    assert " confirm(" not in html and "!confirm(" not in html
    assert "/api/github/sync" not in html
    assert "function confirmNetinstall(portNum)" in html
    assert "function showModalNotice(notice)" in html


def test_dashboard_reconnects_forever_and_shows_stale_state():
    html = make_client().get("/").text

    assert "maxReconnectAttempts" not in html
    assert "function scheduleReconnect()" in html
    assert "Math.min(1000 * Math.pow(2, Math.min(reconnectAttempts, 4)), 15000)" in html
    assert "function checkStale()" in html
    assert "Live updates paused" in html


def test_dashboard_footer_is_contextual_and_touch_friendly():
    html = make_client().get("/").text

    assert "function renderPortModalFooter(portNum, port)" in html
    assert "Retry provisioning" in html
    assert "Enter credentials and retry" in html
    assert "Reprint label" not in html
    assert "min-height: 48px" in html
    assert 'id="modal-footer"' in html


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


def test_manage_page_is_organized_around_baselines_profiles_and_host_secrets():
    """The assets page: git baselines (read-only, installable), guided AP/PTP
    profile uploads, and host login plus required secrets. No shared scope,
    no free-text mode fields, no native dialogs."""
    client = make_client()
    html = client.get("/files").text

    assert "Standard SM baseline" in html
    assert "Install from repo" in html
    assert "/api/config-baselines" in html
    assert "Deployment profiles" in html
    assert 'id="prof-family"' in html and 'id="prof-role"' in html
    assert "ptp_side" in html
    assert "Host login and secrets" in html
    assert "/api/host-credentials" in html
    assert "WPA2 key" in html and "SNMP read-only community" in html
    assert 'id="restart-banner"' in html
    assert "Extra logins to try" in html
    assert "Shared baseline" not in html
    assert 'id="cfg-scope"' not in html and 'id="cfg-asset-kind"' not in html
    assert 'id="cfg-mode"' not in html
    assert " confirm(" not in html and "!confirm(" not in html
    assert "const FAMILY_METADATA" in html


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
