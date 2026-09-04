# Capture summary: Force 300-25: dual-bank upgrade to 5.11.1 (2026-08)

Source capture: `cambium_169.254.1.1_5.11.1dualbanktestsuccess.har` (195 entries, 2026-05-28T17:51:09 to 2026-05-28T17:57:28, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 5.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Unit: Force 300-25 (SKU 35) at 169.254.1.1.
- First pass used local_upload_image and get_upload_status, then reboot (the running firmware before this pass was older than 5.11).
- Second pass, now running 5.11.1, used upload_sw_image_local, upgrade_sw_image_local (type=device), get_upgrade_status, then reboot.
- Both banks read 5.11.1 at the end.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 17:51:09 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:51:09 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:51:10 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x4 more | |
| 17:51:30 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| 17:51:30 | POST | `/cgi-bin/luci/;stok=***/admin/local_upload_image` file field: (multipart) | 200 |
| 17:51:34 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:51:37 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x1 more | |
| 17:51:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:51:40 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 17:51:45 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:51:45 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 17:51:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:51:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x5 more | |
| 17:51:55 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x11 more | |
| 17:52:59 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 17:53:12 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 0 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:54:34 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:54:35 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 17:54:38 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:54:38 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:54:38 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 17:54:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_freq` x1 more | |
| 17:54:39 | POST | `/cgi-bin/luci/;stok=***/admin/spectral_status` stok, debug=true | 200 |
| 17:54:39 | POST | `/cgi-bin/luci/;stok=***/admin/socket_status` stok, debug=true | 200 |
| 17:54:43 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:54:53 | POST | `/cgi-bin/luci/;stok=***/admin/upload_sw_image_local` file field: (multipart) | 200 |
| 17:54:53 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:55:00 | POST | `/cgi-bin/luci/;stok=***/admin/upgrade_sw_image_local` type=device, debug=true | 200 |
| 17:55:01 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x1 more | |
| 17:55:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:55:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x8 more | |
| 17:55:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:55:09 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x7 more | |
| 17:55:13 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 17:55:14 | POST | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` type=device, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upgrade_status` x4 more | |
| 17:55:18 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 17:55:23 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 17:55:39 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 0 |
| 17:57:00 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:57:01 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 17:57:23 | POST | `/cgi-bin/luci` username, password | 200 |
| 17:57:23 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 17:57:23 | device reports | `cambiumCurrentuImageIVersion` = `5.11.1` | |
| 17:57:23 | device reports | `cambiumCurrentuImageVersion` = `5.11.1` | |
| 17:57:23 | device reports | `cambiumDAVersion` = `2.105.48` | |
| 17:57:23 | device reports | `cambiumMCUVersion` = `2.2.5-RC4` | |
| 17:57:23 | device reports | `version` = `5.11.1` | |
| 17:57:23 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 17:57:24 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_freq` x1 more | |
| 17:57:24 | POST | `/cgi-bin/luci/;stok=***/admin/spectral_status` stok, debug=true | 200 |
| 17:57:24 | POST | `/cgi-bin/luci/;stok=***/admin/socket_status` stok, debug=true | 200 |
| 17:57:28 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
