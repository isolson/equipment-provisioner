"""Smoke tests for rendered web pages."""

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
    assert "loadSetupReadiness()" in html


def test_manage_page_renders_setup_actions():
    client = make_client()

    response = client.get("/files")
    assert response.status_code == 200
    html = response.text

    assert "First-Run Readiness" in html
    assert "Import Setup Bundle" in html
    assert "Export Setup Bundle" in html
    assert "Seed Bundled Templates" in html
    assert "Configure MikroTik Switch" in html
