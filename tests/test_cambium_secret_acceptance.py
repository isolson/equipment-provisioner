from unittest.mock import AsyncMock
from copy import deepcopy
import pytest
from provisioner.handlers.cambium import CambiumHandler

@pytest.fixture
def handler(monkeypatch):
    h=CambiumHandler(ip='192.0.2.1',credentials={},interface='test0')
    monkeypatch.setattr('provisioner.handlers.cambium.asyncio.sleep',AsyncMock())
    return h

@pytest.mark.asyncio
@pytest.mark.parametrize('target',['','admin'])
async def test_missing_or_factory_management_target_fails(handler,monkeypatch,target):
    read=AsyncMock();monkeypatch.setattr(handler,'_get_config_curl',read)
    assert not await handler.apply_secrets({'management_password':target})
    read.assert_not_awaited()

@pytest.mark.asyncio
async def test_matching_secrets_and_login_skip_write(handler,monkeypatch):
    monkeypatch.setattr(handler,'_get_config_curl',AsyncMock(return_value={'wirelessInterfaceEncryptionKey':'test-wpa','snmpReadOnlyCommunity':'test-ro','snmpReadWriteCommunity':'test-rw-long'}))
    monkeypatch.setattr(handler,'_verify_management_password',AsyncMock(return_value=True))
    write=AsyncMock();monkeypatch.setattr(handler,'_send_set_param',write)
    assert await handler.apply_secrets({'management_password':'test-admin','wpa_key':'test-wpa','snmp_community':'test-ro','snmp_write_community':'test-rw-long'})
    write.assert_not_awaited()

@pytest.mark.asyncio
async def test_short_factory_rw_requires_separate_target(handler,monkeypatch):
    monkeypatch.setattr(handler,'_get_config_curl',AsyncMock(return_value={'snmpReadWriteCommunity':'short'}))
    monkeypatch.setattr(handler,'_verify_management_password',AsyncMock(return_value=False))
    write=AsyncMock();monkeypatch.setattr(handler,'_send_set_param',write)
    assert not await handler.apply_secrets({'management_password':'test-admin','snmp_community':'test-read-only'})
    write.assert_not_awaited()

@pytest.mark.asyncio
@pytest.mark.parametrize('write_ok,readback_ok,login_ok',[(True,True,True),(False,True,True),(True,False,True),(True,True,False)])
async def test_all_secrets_and_fresh_login_required(handler,monkeypatch,write_ok,readback_ok,login_ok):
    basis={'mgmtVLANVID':'12'};handler._last_applied_config=basis
    live={'snmpReadWriteCommunity':'short'};sent=[]
    async def read():
        if sent and readback_ok:return {k:v for k,v in sent[-1].items() if k!='admin_password'}
        return dict(live)
    async def write(props):
        sent.append(deepcopy(props));handler._last_applied_config=props;return write_ok
    monkeypatch.setattr(handler,'_get_config_curl',read)
    monkeypatch.setattr(handler,'_send_set_param',write)
    monkeypatch.setattr(handler,'_verify_management_password',AsyncMock(return_value=False))
    account=AsyncMock(return_value=login_ok)
    monkeypatch.setattr(handler,'_apply_management_password',account)
    assert await handler.apply_secrets({'management_password':'test-admin','wpa_key':'test-wpa','snmp_community':'test-ro','snmp_write_community':'test-rw-long'}) is (write_ok and readback_ok and login_ok)
    assert handler._last_applied_config is basis
    assert 'admin_password' not in sent[0]
    if write_ok and readback_ok:account.assert_awaited_once_with('test-admin')
    else:account.assert_not_awaited()
    assert sent[0]['snmpReadWriteCommunity']=='test-rw-long'
    assert sent[0]['snmpReadOnlyCommunity']=='test-ro'

def test_target_and_rw_survive_login_replacement(monkeypatch):
    h=CambiumHandler(ip='192.0.2.1',credentials={'password':'test-admin','snmp_write_community':'test-rw-long'})
    h.credentials=h.DEFAULT_CREDENTIALS.copy()
    assert h.pending_secrets()['management_password']=='test-admin'
    assert h.pending_secrets()['snmp_write_community']=='test-rw-long'


@pytest.mark.asyncio
@pytest.mark.parametrize('accepted,authenticated',[(True,True),(False,True),(True,False)])
async def test_account_endpoint_requires_response_and_fresh_login(handler,monkeypatch,accepted,authenticated):
    from types import SimpleNamespace
    handler._stok='test-session';handler._cookie_file='/test/cookies'
    seen=[]
    async def request(args,url,form_data=None):
        import json,urllib.parse
        assert 'test-session' not in ' '.join(args)
        assert 'test-admin' not in ' '.join(args)
        assert url.endswith('/admin/set_account_params')
        body=json.loads(urllib.parse.parse_qs(form_data)['changed_elements'][0])
        assert body=={'device_props':{'admin_password':'test-admin'}}
        return SimpleNamespace(returncode=0),json.dumps({'success':int(accepted),'err':''}).encode(),b''
    monkeypatch.setattr(handler,'_run_curl_with_stdin_config',request)
    verify=AsyncMock(return_value=authenticated)
    monkeypatch.setattr(handler,'_verify_management_password',verify)
    assert await handler._apply_management_password('test-admin') is (accepted and authenticated)
    if not accepted:verify.assert_not_awaited()
