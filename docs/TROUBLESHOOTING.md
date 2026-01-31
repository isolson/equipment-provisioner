# Troubleshooting

Common issues and how to debug them.

## Device Not Detected

**Symptom:** Port stays on "NO LINK" or "DETECTING" and never identifies a device.

**Check the physical connection:**
```bash
# Verify VLAN interfaces exist
ip link show | grep eth0.

# Check link state on each VLAN
ip link show eth0.1991
```

If no `eth0.199x` interfaces exist, run:
```bash
sudo /opt/provisioner/scripts/setup_network.sh setup
```

**Check the switch trunk:**
```bash
# Verify trunk port carries all VLANs
# On MikroTik: /interface bridge vlan print
# Or check from Pi:
sudo tcpdump -i eth0 -e vlan -c 20
```

**Check device boot state:**

Devices need time to boot before they respond to HTTP probes. Default wait is 90 seconds. If a device takes longer, check `config.yaml`:
```yaml
detection:
  boot_wait_seconds: 90  # Increase if needed
```

**Check fingerprinting:**
```bash
# Manual probe from the VLAN interface
curl --interface eth0.1991 -sk https://169.254.1.1/ -m 5
curl --interface eth0.1991 -s http://169.254.1.1/ -m 5
```

If curl returns nothing, the device may use a non-standard IP. Check `config.yaml` device IP settings.

## Login Fails / "NEEDS CREDENTIALS"

**Symptom:** Device detected but provisioning stops at login.

The provisioner tries credentials in this order:
1. Factory defaults (e.g., `admin/admin` for Cambium)
2. Custom credentials set via the UI settings page
3. Falls back to prompting the user via the UI

**Fix:**
- Tap the port card and enter the correct credentials
- Or set credentials in the UI settings page (gear icon) to apply fleet-wide
- For devices with changed passwords, add a custom credential via `POST /api/v1/default-credentials/{device_type}`

**Check logs for the specific error:**
```bash
journalctl -u provisioner-web -f | grep -i "login\|auth\|credential"
```

## Provisioning Stuck / Never Completes

**Symptom:** Status shows a blue spinner indefinitely on one step.

**Firmware upload stuck:**
- Check if the device web UI is responsive: `curl --interface eth0.199X -sk https://169.254.1.1/`
- Large firmware files can take several minutes to upload over 100Mbps links
- The reboot timeout is 10 minutes; some devices need the full duration

**Config apply stuck:**
- Cambium `config_import` is asynchronous — the provisioner polls until `applyFinished` is true
- Check logs: `journalctl -u provisioner-web -f | grep -i "config\|apply"`

**Device rebooted unexpectedly:**
- Some devices (Tachyon) auto-reboot after firmware flash without explicit reboot command
- The provisioner handles this, but if the link drops for too long, it may time out
- Check `wait_for_reboot` timeout in `config.yaml`

## VLAN Interface Binding Errors

**Symptom:** `OSError: [Errno 99] Cannot assign requested address` or connections go to wrong device.

The provisioner uses `SO_BINDTODEVICE` to bind sockets to specific VLAN interfaces. This requires:
- Running as root or with `CAP_NET_RAW` capability
- The VLAN interface must exist and be up

**Check:**
```bash
# Verify the service has the right capabilities
systemctl cat provisioner-web | grep -i cap

# Verify interfaces are up
ip addr show eth0.1991
```

**If running manually (not via systemd):**
```bash
sudo provisioner-web -c /etc/provisioner/config.yaml
```

## Web UI Not Loading

**Check the service:**
```bash
sudo systemctl status provisioner-web
journalctl -u provisioner-web --no-pager -n 50
```

**Check the port:**
```bash
ss -tlnp | grep 8080
```

If another process is using port 8080, change the port in `config.yaml` or start with `--port 8081`.

**Kiosk mode not starting:**
```bash
# Check if X11 is running
systemctl status display-manager

# Check kiosk user auto-login
cat /etc/lightdm/lightdm.conf | grep autologin
```

## GPIO LEDs Not Working

**Symptom:** No LED or buzzer activity on provisioning events.

GPIO only works on OrangePi hardware. On other SBCs:
- Check that `OPi.GPIO` is installed: `pip show OPi.GPIO`
- Verify pin numbering in `config.yaml` matches your board's BOARD numbering scheme
- Check that the GPIO group permissions allow access

**Disable GPIO (if not using OrangePi):**
Set `gpio.enabled: false` in `config.yaml`.

## Database Errors

**Symptom:** Job history not saving or API returns empty jobs.

```bash
# Check database file
ls -la /var/lib/provisioner/history.db

# Check permissions
stat /var/lib/provisioner/history.db
```

The database is SQLite. If corrupted, you can safely delete it and it will be recreated:
```bash
sudo systemctl stop provisioner-web
sudo rm /var/lib/provisioner/history.db
sudo systemctl start provisioner-web
```

## Notifications Not Sending

**Check webhook URLs:**
```bash
# Test Slack webhook directly
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"test"}' \
  "$SLACK_WEBHOOK_URL"
```

**Check that the Pi has internet access** (notifications require outbound HTTPS). The provisioner itself doesn't need internet, but webhooks do.

Webhooks are configured in `/etc/provisioner/config.yaml` or via environment variables in `/etc/provisioner/provisioner.env`.

## Viewing Logs

```bash
# Live logs
journalctl -u provisioner-web -f

# Last 100 lines
journalctl -u provisioner-web --no-pager -n 100

# Filter by severity
journalctl -u provisioner-web -p err

# Log file (if configured)
tail -f /var/log/provisioner.log
```

Set log level in `config.yaml`:
```yaml
logging:
  level: DEBUG  # DEBUG, INFO, WARNING, ERROR
```
