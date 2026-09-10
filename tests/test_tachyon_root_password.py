from copy import deepcopy
from unittest.mock import AsyncMock
import pytest
from provisioner.handlers.tachyon import TachyonHandler

@pytest.mark.asyncio
async def test_missing_or_default_target_blocks_secrets(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1', credentials={})
    network=AsyncMock(return_value=True)
    monkeypatch.setattr(h, '_apply_network_secrets', network)
    for secret in ({}, {'management_password':''}, {'management_password':h.DEFAULT_CREDENTIALS['password']}):
        assert not await h.apply_secrets(secret)
    network.assert_not_awaited()

def test_target_survives_login_candidate_replacement(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1', credentials={'password':'test-standard'})
    h.credentials=h.DEFAULT_CREDENTIALS.copy()
    assert h.pending_secrets()['management_password']=='test-standard'
    h=TachyonHandler(ip='192.0.2.1', credentials={})
    monkeypatch.setattr(h, '_get_custom_credential', lambda:{'username':'root','password':'test-tagged'})
    assert h.pending_secrets()['management_password']=='test-tagged'

@pytest.mark.asyncio
async def test_password_is_required_after_network_secrets(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1', credentials={})
    monkeypatch.setattr(h,'_apply_network_secrets',AsyncMock(return_value=True))
    password=AsyncMock(return_value=False)
    monkeypatch.setattr(h,'set_password',password)
    assert not await h.apply_secrets({'management_password':'test-standard'})
    password.assert_awaited_once_with('test-standard',username='root')

@pytest.mark.asyncio
@pytest.mark.parametrize('verified', [True,False])
async def test_root_hash_write_preserves_accounts_and_requires_login(monkeypatch,verified):
    h=TachyonHandler(ip='192.0.2.1',credentials={})
    live={'system':{'users':[{'username':'root','enabled':True,'level':0,'password':'old-hash'}, {'username':'other','password':'unchanged'}]},'network':{'test':'preserved'}}
    monkeypatch.setattr(h,'_read_config_after_apply',AsyncMock(return_value=live))
    monkeypatch.setattr(h,'_verify_root_password',AsyncMock(side_effect=[False,verified]))
    sent=[]
    async def read():
        return deepcopy(sent[-1]) if sent else live
    monkeypatch.setattr(h,'_read_config_after_apply',read)
    monkeypatch.setattr('provisioner.handlers.tachyon.asyncio.sleep',AsyncMock())
    async def apply(config):
        sent.append(deepcopy(config)); return True
    monkeypatch.setattr(h,'apply_config',apply)
    assert await h.set_password('test-standard') is verified
    assert live['system']['users'][0]['password']=='old-hash'
    root=sent[0]['system']['users'][0]
    assert root['password'].startswith('$1$') and root['password']!='test-standard'
    assert sent[0]['system']['users'][1]==live['system']['users'][1]
    assert sent[0]['network']==live['network']
    assert root['enabled'] is True and root['level']==0

@pytest.mark.asyncio
async def test_already_working_standard_password_skips_write(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1',credentials={})
    monkeypatch.setattr(h,'_verify_root_password',AsyncMock(return_value=True))
    read=AsyncMock(); monkeypatch.setattr(h,'_read_config_after_apply',read)
    assert await h.set_password('test-standard')
    read.assert_not_awaited()

@pytest.mark.asyncio
async def test_failed_password_post_cannot_pass(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1',credentials={})
    monkeypatch.setattr(h,'_verify_root_password',AsyncMock(return_value=False))
    monkeypatch.setattr(h,'_read_config_after_apply',AsyncMock(return_value={'system':{'users':[{'username':'root','enabled':True}]}}))
    monkeypatch.setattr(h,'apply_config',AsyncMock(return_value=False))
    assert not await h.set_password('test-standard')

@pytest.mark.asyncio
@pytest.mark.parametrize('transport', [True,False])
async def test_fresh_login_retries_transport_but_not_rejection(monkeypatch,transport):
    from provisioner.handlers.base import ConnectionFailureKind
    h=TachyonHandler(ip='192.0.2.1',credentials={},interface='test0')
    calls=[]
    async def login(probe):
        calls.append(True)
        probe._connection_failure_kind=ConnectionFailureKind.TRANSPORT if transport else ConnectionFailureKind.AUTHENTICATION
        return len(calls)>1
    monkeypatch.setattr(TachyonHandler,'_connect_curl',login)
    monkeypatch.setattr(TachyonHandler,'_read_config_after_apply',AsyncMock(return_value={'system':{}}))
    monkeypatch.setattr('provisioner.handlers.tachyon.asyncio.sleep',AsyncMock())
    assert await h._verify_root_password('test-standard') is transport
    assert len(calls)==(2 if transport else 1)


@pytest.mark.asyncio
async def test_unapplied_root_hash_cannot_pass(monkeypatch):
    h=TachyonHandler(ip='192.0.2.1',credentials={})
    verify=AsyncMock(return_value=False)
    monkeypatch.setattr(h,'_verify_root_password',verify)
    monkeypatch.setattr(h,'_read_config_after_apply',AsyncMock(return_value={'system':{'users':[{'username':'root','enabled':True,'password':'old'}]}}))
    monkeypatch.setattr(h,'apply_config',AsyncMock(return_value=True))
    monkeypatch.setattr('provisioner.handlers.tachyon.asyncio.sleep',AsyncMock())
    assert not await h.set_password('test-standard')
    assert verify.await_count==1
