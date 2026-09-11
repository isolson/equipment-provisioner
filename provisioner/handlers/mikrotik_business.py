"""E60iUGS business profiles, owned by the MikroTik handler.

These bench profiles implement business network policy while Ops' renderer
contract is developed. They do not implement fleet reset/enrollment or KDF.
"""
import asyncio
import hashlib
import json
import os
import secrets
import re
from pathlib import Path

PROFILE_MARKER = "treehouse-business-v1:"
PROFILE_ROOT = Path(__file__).resolve().parents[2] / "configs/templates/mikrotik/modes"
MANAGEMENT_IPS = {"router": "192.168.10.1", "switch": "192.168.10.2"}

# Full import replaces only the preflight-approved bench layout. Users and
# certificates survive. No reset or factory-default claim is made by this flow.
CLEANUP = """
/ip dhcp-server remove [find]
/ip dhcp-server network remove [find]
/ip dhcp-client remove [find]
/ip pool remove [find]
/ip dhcp-server option sets remove [find]
/ip dhcp-server option remove [find]
/ip firewall filter remove [find where dynamic=no]
/ip firewall nat remove [find]
/ipv6 firewall filter remove [find where dynamic=no]
/ip route remove [find where dynamic=no]
/ip dns static remove [find]
/ip address remove [find]
/interface list member remove [find]
/interface bridge port remove [find]
/interface bridge vlan remove [find where dynamic=no]
/interface vlan remove [find]
/interface bridge remove [find]
/interface list remove [find where name="LAN" or name="WAN" or name="MGMT"]
/system logging remove [find where action=remote]
"""


def profile_text(mode):
    if mode not in MANAGEMENT_IPS:
        raise ValueError("Unknown business role")
    return CLEANUP + (PROFILE_ROOT / ("business-%s.rsc" % mode)).read_text()


async def ensure_source(handler):
    """Use an interface-only /32; never install a route to the host's LAN."""
    if not handler.interface:
        raise ValueError("A dedicated bench interface is required")
    proc = await asyncio.create_subprocess_exec(
        "ip", "address", "replace", "192.168.10.254/32", "dev", handler.interface,
        "noprefixroute", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    await proc.communicate()
    if proc.returncode:
        raise ValueError("Could not prepare the isolated management source")


async def connect(handler):
    await ensure_source(handler)
    for ip in dict.fromkeys([handler.ip] + list(MANAGEMENT_IPS.values())):
        handler.ip = ip
        handler._bind_ip_cache = None
        if await handler.connect():
            return True
    return False


def check_expressions(mode):
    """Independent live contract checks, not an import exit-code proxy."""
    router = mode == "router"
    checks = {}
    def count(name, path, where, n):
        checks[name] = '[:len [%s find%s]] = %d' % (path, ' where '+where if where else '', n)
    count('physical_ports', '/interface ethernet', '', 6)
    count('bridge', '/interface bridge', 'name="bridge" and vlan-filtering=yes and dhcp-snooping=yes', 1)
    count('bridge_ports', '/interface bridge port', 'bridge="bridge" and pvid=10 and ingress-filtering=yes', 5 if router else 6)
    for port in ['ether2', 'ether4', 'ether5'] + ([] if router else ['ether1']):
        count('trunk_'+port, '/interface bridge port', 'interface="%s" and frame-types=admit-all' % port, 1)
    for port in ['ether3', 'sfp1']:
        count('access_'+port, '/interface bridge port', 'interface="%s" and frame-types=admit-only-untagged-and-priority-tagged' % port, 1)
    count('wan_bridge', '/interface bridge port', 'interface="ether1"', 0 if router else 1)
    for vlan in [10,20,40,70]:
        tagged = 'bridge' if vlan == 10 else ('bridge,ether2,ether4,ether5' if router else 'ether1,ether2,ether4,ether5')
        checks['vlan_%s_tagged'%vlan] = '[:tostr [/interface bridge vlan get [find where dynamic=no and vlan-ids=%d] tagged]] = "%s"' % (vlan,tagged.replace(',', ';'))
    count('vlan_interfaces', '/interface vlan', '', 4 if router else 1)
    count('management_address','/ip address','address="%s/24" and interface="vlan10-internal" and disabled!=yes'%MANAGEMENT_IPS[mode],1)
    count('address_count','/ip address','dynamic=no',4 if router else 1)
    count('nat_count','/ip firewall nat','disabled!=yes',2 if router else 0)
    count('dhcp_servers','/ip dhcp-server','disabled!=yes',4 if router else 0)
    count('dhcp_networks','/ip dhcp-server network','',4 if router else 0)
    count('dhcp_clients','/ip dhcp-client','disabled!=yes and interface="ether1"',1 if router else 0)
    if router:
        for name,vlan,prefix,lease in [('internal',10,24,'12h'),('iot',20,24,'12h'),('guest',40,22,'2h'),('openroam',70,23,'2h')]:
            count('scope_'+name,'/ip dhcp-server network','address="192.168.%d.0/%d" and gateway="192.168.%d.1"'%(vlan,prefix,vlan),1)
            count('server_'+name,'/ip dhcp-server','name="dhcp-%s" and interface="vlan%d-%s" and lease-time=%s and disabled!=yes'%(name,vlan,name,lease),1)
        count('unifi_option','/ip dhcp-server option','name="unifi" and code=43 and value="0x0104ACE9D0AE"',1)
        count('unifi_inform','/ip firewall nat','chain=dstnat and action=dst-nat and comment="UniFi controller inform 8080->8089"',1)
        for field,value in [('dst-address','172.233.208.174'),('dst-port','8080'),('to-ports','8089'),('protocol','tcp')]:
            checks['unifi_'+field] = '[:tostr [/ip firewall nat get [find where comment="UniFi controller inform 8080->8089"] %s]] = "%s"' % (field,value)
        count('masquerade','/ip firewall nat','chain=srcnat and action=masquerade and out-interface-list="WAN"',1)
        for name in ['Guest: internet only','OpenRoam: internet only','IoT !-> Internal','IoT !-> Guest','IoT !-> OpenRoam','drop unsolicited WAN']:
            count('isolation_'+name,'/ip firewall filter','comment="%s" and chain=forward and action=drop and disabled!=yes'%name,1)
    else:
        count('management_route','/ip route','dst-address="0.0.0.0/0" and gateway="192.168.10.1" and disabled!=yes',1)
        count('trusted_uplink','/interface bridge port','interface="ether1" and trusted=yes',1)
    for service in ['ssh','www-ssl','winbox']:
        count('service_'+service,'/ip service','name="%s" and disabled!=yes and address="192.168.10.0/24"'%service,1)
    for service in ['telnet','ftp','www','api','api-ssl']:
        count('disabled_'+service,'/ip service','name="%s" and disabled=yes'%service,1)
    count('https_certificate','/certificate','name="webfig-local" and private-key=yes',1)
    count('input_drop','/ip firewall filter','chain=input and action=drop and disabled!=yes',2)
    count('ipv6_input_drop','/ipv6 firewall filter','chain=input and action=drop',1)
    count('ipv6_forward_drop','/ipv6 firewall filter','chain=forward and action=drop',1)
    checks['forwarding'] = '[/ip settings get ip-forward] = %s' % ('true' if router else 'false')
    checks['ipv6_forwarding'] = '[/ipv6 settings get forward] = false'
    checks['dns'] = '[:tostr [/ip dns get servers]] = "100.126.15.20;9.9.9.9"'
    checks['dns_service'] = '[/ip dns get allow-remote-requests] = %s' % ('true' if router else 'false')
    checks['ntp_enabled'] = '[/system ntp client get enabled] = true'
    count('ntp_server','/system ntp client servers','address="100.126.15.28"',1)
    checks['syslog_target'] = '[/system logging action get [find where name="remote"] remote] = 100.126.15.28'
    checks['syslog_format'] = '[/system logging action get [find where name="remote"] remote-log-format] = "syslog"'
    count('syslog_rules','/system logging','action="remote" and disabled!=yes',4)
    checks['timezone'] = '[/system clock get time-zone-name] = "America/Chicago"'
    checks['romon_containment'] = '([/tool romon get enabled] = false) or (([:len [/tool romon port find where interface=all and forbid=yes]] = 1) and ([:len [/tool romon port find where interface=ether3 and forbid=no and disabled!=yes]] = 1) and ([:len [/tool romon port find where interface!=all and interface!=ether3 and forbid=no and disabled!=yes]] = 0) and ([:len [/tool romon get secrets]] > 0))'
    prefix='subscriber-unassigned-' if router else 'switch-unassigned-'
    checks['identity_sentinel'] = '[/system identity get name] = ("%s" . [/system routerboard get serial-number])'%prefix
    checks['profile_marker'] = '[/system note get note] = "%s%s"'%(PROFILE_MARKER,mode)
    return checks


async def read_state(handler, mode):
    expressions=check_expressions(mode)
    command='; '.join(':put ("%s=" . (%s))'%(key,expression) for key,expression in expressions.items())
    output=await handler._run_command(command)
    values=dict(line.strip().split('=',1) for line in output.splitlines() if '=' in line)
    checks={key: values.get(key) == 'true' for key in expressions}
    return {'mode':mode,'profile':'business-v1','checks':checks,
            'management_ip':MANAGEMENT_IPS[mode]}


async def apply(handler, mode):
    text=profile_text(mode)
    await ensure_source(handler)
    info=await handler.get_info()
    serial=info.serial_number
    if not serial or info.model!='hEX S' or info.hardware_version!='arm' or info.firmware_version!='7.23.5':
        raise ValueError('Unqualified business hardware or firmware')
    remote='business-profile.rsc'
    async with handler._ssh.start_sftp_client() as sftp:
        async with sftp.open(remote,'w') as f:
            await f.write(text)
    # Syntax preflight executes no writes. Full import is launched on-device so
    # replacing its bridge cannot truncate the job with the old SSH connection.
    result=await handler._ssh.run('/import file-name=%s verbose=yes dry-run'%remote,check=False)
    if result.exit_status or 'No syntax errors found' not in result.stdout:
        async with handler._ssh.start_sftp_client() as sftp:
            await sftp.remove(remote)
        raise RuntimeError('Business profile import preflight failed')
    await handler._run_command('/execute {/import file-name=business-profile.rsc}')
    await handler.disconnect()
    handler.ip=MANAGEMENT_IPS[mode]
    handler._bind_ip_cache=None
    state=None
    try:
        for attempt in range(30):
            await asyncio.sleep(3)
            try:
                if not await handler.connect():
                    continue
                fresh=await handler.get_info()
                if fresh.serial_number != serial:
                    raise ValueError('Device identity changed after import')
                state=await read_state(handler,mode)
                if all(state['checks'].values()):
                    state.update(model=fresh.model,firmware=fresh.firmware_version,architecture=fresh.hardware_version)
                    state['render_sha256']=hashlib.sha256(text.encode()).hexdigest()
                    break
            except ValueError:
                raise
            except Exception:
                pass
        else:
            raise RuntimeError('Business profile did not pass readback')
    finally:
        if handler._ssh:
            async with handler._ssh.start_sftp_client() as sftp:
                await sftp.remove(remote)
                if await sftp.exists(remote):
                    raise RuntimeError('Uploaded profile removal failed')
    return state


SECRET_ROOT = Path("/var/lib/provisioner/device-secrets/mikrotik")


def _secret_file(serial):
    # Hash the filename as well: directory listings need no device identity.
    SECRET_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    return SECRET_ROOT / (hashlib.sha256(serial.encode()).hexdigest() + ".json")


def _save_secrets(path, data):
    temp = path.with_suffix(".tmp")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(data, stream)
        os.replace(str(temp), str(path))
    finally:
        if temp.exists():
            temp.unlink()


async def advanced_state(handler):
    enabled = (await handler._run_command(":put [/tool romon get enabled]")).strip() == "true"
    count = (await handler._run_command(':put [:len [/interface wireguard find where name="wg-management"]]')).strip()
    public = None
    if count == "1":
        public = (await handler._run_command(':put [/interface wireguard get [find where name="wg-management"] public-key]')).strip()
    return {"romon_enabled":enabled, "romon_port":"ether3", "wireguard_public_key":public,
            "wireguard_status":"key prepared; peer not configured" if public else "not prepared"}


async def apply_advanced(handler, romon_enabled=None, prepare_wireguard=False):
    state = await handler.network_mode_state()
    if state.get("profile") != "business-v1" or not all(state["checks"].values()):
        raise ValueError("Apply and verify a business profile before advanced options")
    info = await handler.get_info()
    path = _secret_file(info.serial_number)
    data = json.loads(path.read_text()) if path.exists() else {}
    if romon_enabled is not None:
        if romon_enabled:
            data.setdefault("romon_secret", secrets.token_hex(32))
            _save_secrets(path, data)  # Fail before writing device if storage is unavailable.
            secret = data["romon_secret"]
            if not re.fullmatch(r"[0-9a-f]{64}", secret):
                raise ValueError("Stored RoMON secret is invalid")
            await handler._run_command('/tool romon set enabled=no')
            await handler._run_command('/tool romon port set [find where interface=all] forbid=yes')
            await handler._run_command('/tool romon port remove [find where interface!=all]')
            await handler._run_command('/tool romon port add interface=ether3 forbid=no comment="business local management"')
            # Never log this command or expose the private readback.
            await handler._run_command('/tool romon set secrets="%s" enabled=yes' % secret)
        else:
            await handler._run_command('/tool romon set enabled=no')
    if prepare_wireguard:
        count = (await handler._run_command(':put [:len [/interface wireguard find where name="wg-management"]]')).strip()
        if count == '0':
            await handler._run_command('/interface wireguard add name=wg-management disabled=yes comment="Pending management concentrator"')
        private = (await handler._run_command(':put [/interface wireguard get [find where name="wg-management"] private-key]')).strip()
        public = (await handler._run_command(':put [/interface wireguard get [find where name="wg-management"] public-key]')).strip()
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", private) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public):
            raise RuntimeError("WireGuard key generation was not verified")
        data.update(wireguard_private_key=private, wireguard_public_key=public)
        _save_secrets(path, data)
    result = await advanced_state(handler)
    verified = await read_state(handler,state["mode"])
    if not all(verified["checks"].values()) or (romon_enabled is not None and result['romon_enabled'] != romon_enabled):
        raise RuntimeError("Advanced management did not pass readback")
    return result
