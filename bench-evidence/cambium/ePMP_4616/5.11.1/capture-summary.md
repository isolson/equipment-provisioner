# Capture summary: ePMP 4616: upgrade 5.11.0 to 5.11.1, export, hand configuration in the UI, export (2026-09-02)

Source capture: `cambium4616.upgraderesetconfig.har` (247 entries, 2026-09-02T19:51:39 to 2026-09-02T20:15:14, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 14.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Unit: ePMP 4616 (SKU 53560) at 169.254.1.1, cabled to a laptop, running 5.11.0 with a non-default admin password already set.
- Firmware 5.11.1 uploaded with upload_sw_image_local, triggered with upgrade_sw_image_local (type=device), polled with get_upgrade_status, then reboot. Confirms the explicit endpoint on an AX radio running 5.11.0.
- config_export after the upgrade with the configuration still at factory values (management VLAN off, no cnMaestro URL, scan mask 3): this is the no-config backup. No reset_to_def appears in this capture.
- The technician then configured the unit by hand: set_account_params (installer user, admin password), set_param (management VLAN 12, cnMaestro URL and agent, SNMP communities, syslog server, device name, SNR threshold, WPA key), set_param (scan mask 3, 20/40 MHz, raised to 51, 20/40/80/160), set_param (agent enable), then reboot.
- config_export after the hand configuration: the hand-configured export. It is not a baseline witness: NTP mode and servers and the syslog mask stay at factory values, which the provisioner baseline sets. It shows why hand provisioning drifts.
- After the upgrade the banks read 5.11.1 and 5.11.0.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 19:51:49 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:51:49 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 19:51:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 19:51:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:51:55 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:51:55 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:51:59 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:52:06 | POST | `/cgi-bin/luci/;stok=***/admin/upload_sw_image_local` file field: (multipart) | 200 |
| 19:52:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:52:15 | POST | `/cgi-bin/luci/;stok=***/admin/upgrade_sw_image_local` type=device, debug=true | 200 |
| 19:52:16 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x4 more | |
| 19:52:19 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:19 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x7 more | |
| 19:52:24 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:24 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x7 more | |
| 19:52:29 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:30 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 19:52:34 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:34 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 19:52:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 19:52:44 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:44 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 19:52:49 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:49 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 19:52:54 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:52:54 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x5 more | |
| 19:52:59 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:53:05 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 20:07:31 | POST | `/cgi-bin/luci` username, password | 200 |
| 20:07:31 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 20:07:35 | POST | `/cgi-bin/luci` username, password | 401 |
| | repeated | `/cgi-bin/luci` x2 more | |
| 20:07:51 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 20:07:51 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 20:07:52 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 20:07:52 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` x1 more | |
| 20:07:56 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 20:08:04 | POST | `/cgi-bin/luci/;stok=***/admin/config_export` opts=json | 200 |
| 20:08:19 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 20:08:22 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:08:24 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x15 more | |
| 20:09:57 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 20:09:58 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 20:09:59 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:10:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 20:10:07 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 20:10:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 20:10:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:10:13 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 20:10:27 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 20:10:30 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:10:33 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 20:10:54 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:10:59 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 20:11:19 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 20:11:20 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` x1 more | |
| 20:11:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x4 more | |
| 20:12:03 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 20:12:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 20:12:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:12:13 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x3 more | |
| 20:12:29 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:12:33 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 20:12:41 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 20:15:01 | POST | `/cgi-bin/luci` username, password | 200 |
| 20:15:02 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 20:15:04 | POST | `/cgi-bin/luci` username, password | 200 |
| 20:15:04 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 20:15:04 | device reports | `cambiumCurrentuImageIVersion` = `5.11.0` | |
| 20:15:04 | device reports | `cambiumCurrentuImageVersion` = `5.11.1` | |
| 20:15:04 | device reports | `cambiumDAVersion` = `2.105.48` | |
| 20:15:04 | device reports | `version` = `5.11.1` | |
| 20:15:04 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 20:15:05 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 20:15:05 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 20:15:09 | POST | `/cgi-bin/luci/;stok=***/admin/config_export` opts=json | 200 |
| 20:15:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
