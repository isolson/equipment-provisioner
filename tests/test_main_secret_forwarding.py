from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from provisioner import main
from provisioner.config import Config
from provisioner.handlers.cambium import CambiumHandler

@pytest.mark.asyncio
async def test_setup_forwards_rw_secret_to_handler(monkeypatch,tmp_path):
    cfg=Config();cfg.data.local_path=str(tmp_path);cfg.gpio.enabled=False
    cfg.credentials['cambium'].snmp_write_community='test-write-community'
    cfg.credentials['cambium'].password='test-admin'
    monkeypatch.setattr(main,'init_db',AsyncMock())
    monkeypatch.setattr(main,'init_notifier',lambda **kwargs:None)
    store=SimpleNamespace(ensure_directories=lambda:None,templates_path=tmp_path,firmware_path=tmp_path,local_path=tmp_path)
    monkeypatch.setattr(main,'init_store',lambda path:store)
    monkeypatch.setattr(main,'init_mode_config_manager',lambda path:None)
    monkeypatch.setattr(main,'FirmwareManager',lambda **kwargs:object())
    monkeypatch.setattr(main,'init_firmware_checker',lambda **kwargs:object())
    monkeypatch.setattr(main,'get_notifier',lambda:None)
    captured={}
    class ReachedManager(Exception):pass
    def manager(credentials,alternates):
        captured.update(credentials);raise ReachedManager()
    monkeypatch.setattr(main,'HandlerManager',manager)
    with pytest.raises(ReachedManager):await main.Provisioner(cfg).setup()
    for vendor, creds in cfg.credentials.items():
        assert captured[vendor] == creds.model_dump()
    h=CambiumHandler(ip='192.0.2.1',credentials=captured['cambium'])
    h.credentials=h.DEFAULT_CREDENTIALS.copy()
    assert h.pending_secrets()['snmp_write_community']=='test-write-community'
    assert h.pending_secrets()['management_password']=='test-admin'
