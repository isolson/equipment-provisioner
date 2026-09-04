# Capture summary: ePMP 4518: upgrade at 5.10.4, factory reset, first-boot setup, config import (2026-09-02)

Source capture: `cambium4518.upgraderesetconfig.har` (375 entries, 2026-09-02T19:05:54 to 2026-09-02T19:23:06, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 8.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Unit: ePMP 4518 (SKU 53544) at 169.254.1.1, cabled to a laptop, starting on firmware 5.10.4.
- Login with the factory password, then the first-boot set_param wrote admin_password, wirelessInterfaceEncryptionKey, and crashReporterEnable.
- Firmware 5.11.1 uploaded with local_upload_image and polled with get_upload_status, then reboot. This is the upgrade path for firmware older than 5.11; upload_sw_image_local answered 404 on this firmware the same day.
- reset_to_def with mask=1 then reboot returned the unit to factory state (login with the factory password worked again).
- After the reset the UI ran set_param (wirelessInterfaceEncryptionKey, crashReporterEnable) and set_account_params (admin_password): the first-boot setup is two calls.
- config_import (multipart) applied the known-good SM export, then reboot. The UI reboots after import; the provisioner polls applyFinished instead.
- After one upgrade pass the banks read 5.11.1 and 5.10.4. A second pass fills the other bank.
- No config export was taken on the factory unit, so the 4518 no-config backup is still missing.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 19:06:05 | POST | `/cgi-bin/luci` username, password | 401 |
| | repeated | `/cgi-bin/luci` x1 more | |
| 19:06:10 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 19:06:10 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 19:06:11 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 19:06:11 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:06:15 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 19:06:28 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 19:06:34 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x9 more | |
| 19:07:16 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:07:20 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x11 more | |
| 19:08:15 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| 19:08:16 | POST | `/cgi-bin/luci/;stok=***/admin/local_upload_image` file field: (multipart) | 200 |
| 19:08:17 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:08:25 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x3 more | |
| 19:08:27 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:28 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:08:33 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:33 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:08:38 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:38 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:08:42 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:43 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:08:48 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:48 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x6 more | |
| 19:08:52 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:53 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x6 more | |
| 19:08:57 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:08:58 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:09:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:09:03 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x7 more | |
| 19:09:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:09:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_upload_status` debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_upload_status` x2 more | |
| 19:09:13 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x5 more | |
| 19:09:40 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 19:12:08 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:12:08 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 19:12:11 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:12:11 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 19:12:11 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 19:12:12 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 19:12:12 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:12:16 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x3 more | |
| 19:12:32 | POST | `/cgi-bin/luci/;stok=***/admin/reset_to_def` mask=1, debug=true | 200 |
| 19:12:35 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x18 more | |
| 19:14:10 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 19:16:26 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:16:27 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 19:16:33 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:16:33 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 19:16:37 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 19:16:37 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 19:16:37 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:16:42 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x4 more | |
| 19:17:01 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 19:17:02 | POST | `/cgi-bin/luci/;stok=***/admin/set_account_params` changed_elements, debug=true | 200 |
| 19:19:44 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:19:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:19:50 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:19:52 | POST | `/cgi-bin/luci/;stok=***/admin/config_import` file field: (multipart) | 200 |
| 19:19:54 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x2 more | |
| 19:20:01 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:20:05 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| 19:20:08 | POST | `/cgi-bin/luci/;stok=***/admin/reboot` debug=true | 200 |
| 19:22:30 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:22:31 | POST | `/cgi-bin/luci/;stok=***/admin/get_param_prior` debug=true | 200 |
| 19:22:45 | POST | `/cgi-bin/luci` username, password | 200 |
| 19:22:46 | POST | `/cgi-bin/luci/;stok=***/admin/test_connect` debug=true | 200 |
| 19:22:46 | device reports | `cambiumCurrentuImageIVersion` = `5.10.4` | |
| 19:22:46 | device reports | `cambiumCurrentuImageVersion` = `5.11.1` | |
| 19:22:46 | device reports | `cambiumDAVersion` = `2.105.48` | |
| 19:22:46 | device reports | `version` = `5.11.1` | |
| 19:22:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=config_regular, debug=true | 200 |
| 19:22:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_freq` cc, devmode, drivermode, debug=true | 200 |
| 19:22:46 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
| 19:22:51 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:23:00 | POST | `/cgi-bin/luci/;stok=***/admin/set_param` changed_elements, debug=true | 200 |
| 19:23:05 | POST | `/cgi-bin/luci/;stok=***/admin/get_param` act=status, applyStatusNeeded=true, debug=true | 200 |
| | repeated | `/cgi-bin/luci/;stok=***/admin/get_param` x1 more | |
| 19:23:06 | POST | `/cgi-bin/luci/;stok=***/admin/get_single_radio_spectrum_result` debug=true | 200 |
