# Capture summary: Force 300-25: config export, factory reset, first-boot, config import, upgrade to 5.12.0 (2026-08-31)

Source capture: `cambiumf325-reset-config-upgrade.har` (245 entries, 2026-08-31T14:51:52 to 2026-08-31T17:17:26, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 11.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Unit: Force 300-25 (SKU 55) at 169.254.1.1 running 5.11.1.
- config_export before the reset, reset_to_def with mask=1, reboot, set_account_params, config_import, config_export after.
- Firmware uploaded with upload_sw_image_local, triggered with upgrade_sw_image_local (type=device), polled with get_upgrade_status, then reboot. This is the upgrade path on 5.11 and newer.
- After the upgrade the banks read 5.12.0 and 5.11.1.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 14:51:54 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 14:52:02 | POST | `/cgi-bin/luci/;stok=***/admin/logout` debug=true | 200 |
| 14:52:06 | POST | `/cgi-bin/luci` username, password | 200 |
| 14:52:06 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 14:52:06 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 14:52:13 | POST | `/cgi-bin/luci/;stok=***/admin/config_export` opts=json | 200 |
| 14:52:16 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 14:52:23 | POST | `/cgi-bin/luci/;stok=***/admin/reset_to_def` mask=1, debug=true | 200 |
| 14:52:26 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:03:58 | POST | `/cgi-bin/luci` username, password | 401 |
| | repeated | `/cgi-bin/luci` x2 more | |
| 17:04:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 17:04:07 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:04:07 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:04:07 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 17:04:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_freq` x1 more | |
| 17:04:12 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x3 more | |
| 17:04:27 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 17:06:43 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:06:44 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 17:06:45 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:06:45 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:06:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 17:06:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_freq` x1 more | |
| 17:06:51 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 17:07:03 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 17:07:04 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 17:07:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 0 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:07:31 | POST | `/cgi-bin/luci/;stok=***/admin/config_import` file field: (multipart) | 0 |
| 17:07:36 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 0 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x38 more | |
| 17:10:39 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 17:10:40 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 17:10:48 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 17:10:49 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x9 more | |
| 17:11:34 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 17:11:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 17:11:47 | POST | `/cgi-bin/luci/;stok=***/admin/config_export` opts=json | 200 |
| 17:11:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x9 more | |
| 17:13:40 | POST | `/cgi-bin/luci/;stok=***/admin/upload_sw_image_local` file field: (multipart) | 200 |
| 17:13:44 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:13:47 | POST | `/cgi-bin/luci/;stok=***/admin/upgrade_sw_image_local` type=device, debug=true | 200 |
| 17:13:47 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| 17:13:49 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:13:49 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x9 more | |
| 17:13:55 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:13:56 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x6 more | |
| 17:14:00 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:14:00 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x4 more | |
| 17:14:05 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:14:13 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 17:15:58 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:15:59 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 17:17:20 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:17:21 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:17:21 | device reports | `cambiumCurrentuImageIVersion` = `5.11.1` | |
| 17:17:21 | device reports | `cambiumCurrentuImageVersion` = `5.12.0` | |
| 17:17:21 | device reports | `cambiumMCUVersion` = `2.2.5-RC4` | |
| 17:17:21 | device reports | `cambiumDAVersion` = `2.105.48` | |
| 17:17:21 | device reports | `version` = `5.12.0` | |
| 17:17:21 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 17:17:22 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_freq` x1 more | |
| 17:17:26 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
