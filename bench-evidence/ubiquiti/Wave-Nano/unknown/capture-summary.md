# Capture summary: Wave Nano: login, setup, upgrade, management VLAN (2026-08-31)

Source capture: `ubiquti-login-setup-upgrade-mgmtvlan.har` (392 entries, 2026-08-31T16:42:28 to 2026-08-31T16:49:49, WebInspector). Raw file stays in the secure bench directory.

Device host: `192.168.1.20`. Requests to other hosts (browser telemetry, extensions) omitted: 33.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Process evidence for the Wave setup, configuration, upgrade, and reboot requests. The capture leaves the management VLAN unset, so the VLAN 12 transition is not proven.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 16:42:28 | GET | `/api/v1.0/public/device`  | 200 |
| | repeated | `/api/v1.0/public/device` x16 more | |
| 16:42:45 | GET | `/api/v1.0/system/airos/configuration`  | 200 |
| 16:42:45 | GET | `/api/v1.0/system/airmax/regdomain/US`  | 200 |
| 16:42:45 | GET | `/api/v1.0/device`  | 200 |
| 16:42:45 | POST | `/api/v1.0/tools/compose` json:addressType,analyticsEnabled,antenna,apMode,auto,body,cableLoss,channelWidth,cidr,clientIsolation,country,data | 200 |
| 16:42:45 | GET | `/api/v1.0/public/device`  | 200 |
| 16:42:59 | GET | `/api/v1.0/tools/compose`  | 200 |
| 16:42:59 | POST | `/api/v1.0/tools/compose` json:method,requests,rollback,route | 200 |
| 16:42:59 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:42:59 | GET | `/api/v1.0/statistics`  | 200 |
| 16:42:59 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:42:59 | POST | `/api/v1.0/tools/proxy/https` json:method,url | 500 |
| 16:42:59 | POST | `/api/v1.0/tools/discovery/neighbors`  | 200 |
| 16:42:59 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:00 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:43:04 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:04 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:09 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:09 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:10 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:14 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:15 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:19 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:19 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:20 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:24 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:25 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:29 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:29 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:30 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:34 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:35 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:39 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:39 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:40 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:43:44 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:45 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:49 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:50 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:43:50 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:43:55 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:43:55 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:00 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:00 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:00 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:05 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:05 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:10 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:10 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:10 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:15 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:15 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:20 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:20 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:20 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:25 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:25 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:30 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:30 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:31 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:44:35 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:35 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:44:40 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:40 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:40 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x2 more | |
| 16:44:43 | POST | `/api/v1.0/tools/compose` json:address,addressType,analyticsEnabled,antenna,apMode,auto,bluetoothManagement,body,cableLoss,carrierDrop,channelWidth,cidr | 200 |
| 16:44:43 | GET | `/api/v1.0/system`  | 200 |
| 16:44:58 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:44:58 | GET | `/api/v1.0/statistics`  | 200 |
| 16:44:58 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:44:59 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x1 more | |
| 16:45:01 | GET | `/api/v1.0/user/password-requirements`  | 200 |
| 16:45:01 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x1 more | |
| 16:45:03 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:03 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:08 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:08 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:08 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:13 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:14 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:45:17 | POST | `/api/v1.0/tools/compose` json:body,method,newPassword,oldPassword,onError,onUnreachable,requests,rollback,route,username,verifyPassword | 200 |
| 16:45:18 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:18 | GET | `/api/v1.0/statistics`  | 200 |
| 16:45:18 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:18 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:19 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:45:23 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:23 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:28 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:28 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:28 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:33 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:33 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:33 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:38 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:38 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:38 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:43 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:44 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x4 more | |
| 16:45:48 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:45:48 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:45:49 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:45:53 | POST | `/api/v1.0/system/upgrade/direct` file field: (multipart) | 200 |
| 16:46:00 | GET | `/api/v1.0/system/upgrade`  | 200 |
| | repeated | `/api/v1.0/system/upgrade` x1 more | |
| 16:46:01 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:46:01 | GET | `/api/v1.0/statistics`  | 200 |
| 16:46:01 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:46:01 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:46:02 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:46:06 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:46:06 | GET | `/api/v1.0/statistics`  | 200 |
| 16:46:07 | POST | `/api/v1.0/system/upgrade/direct` file field: (multipart) | 200 |
| 16:46:09 | GET | `/api/v1.0/system/upgrade`  | 200 |
| | repeated | `/api/v1.0/system/upgrade` x1 more | |
| 16:46:10 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:46:10 | GET | `/api/v1.0/statistics`  | 200 |
| 16:46:10 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:46:10 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:46:11 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x1 more | |
| 16:46:12 | POST | `/api/v1.0/system/upgrade/direct` file field: (multipart) | 200 |
| 16:46:18 | GET | `/api/v1.0/system/upgrade`  | 200 |
| | repeated | `/api/v1.0/system/upgrade` x11 more | |
| 16:46:30 | GET | `/api/v1.0/system/alerts`  | 200 |
| | repeated | `/api/v1.0/system/alerts` x1 more | |
| 16:46:30 | GET | `/api/v1.0/statistics`  | 200 |
| 16:46:30 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:46:30 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:46:30 | GET | `/api/v1.0/system/upgrade`  | 200 |
| 16:46:31 | GET | `/api/v1.0/statistics`  | 200 |
| 16:46:31 | POST | `/api/v1.0/system/reboot` json:timeout | 200 |
| 16:46:31 | GET | `/api/v1.0/system/alerts`  | 200 |
| | repeated | `/api/v1.0/system/alerts` x2 more | |
| 16:46:58 | GET | `/api/v1.0/statistics`  | 0 |
| 16:46:58 | GET | `/api/v1.0/tools/unms`  | 0 |
| 16:46:58 | GET | `/api/v1.0/tools/compose`  | 0 |
| 16:46:58 | GET | `/api/v1.0/statistics/historical/minute`  | 0 |
| 16:47:06 | GET | `/api/v1.0/statistics`  | 0 |
| 16:47:06 | GET | `/api/v1.0/tools/unms`  | 0 |
| 16:47:11 | GET | `/api/v1.0/statistics`  | 0 |
| 16:47:15 | GET | `/api/v1.0/tools/unms`  | 0 |
| 16:47:17 | GET | `/api/v1.0/statistics`  | 0 |
| 16:47:21 | GET | `/api/v1.0/tools/unms`  | 0 |
| 16:47:28 | GET | `/api/v1.0/statistics`  | 0 |
| 16:47:31 | GET | `/api/v1.0/public/ping`  | 0 |
| 16:47:32 | GET | `/api/v1.0/tools/unms`  | 0 |
| 16:47:36 | GET | `/api/v1.0/public/ping`  | 0 |
| | repeated | `/api/v1.0/public/ping` x4 more | |
| 16:47:51 | GET | `/api/v1.0/statistics`  | 0 |
| 16:47:52 | GET | `/api/v1.0/system/alerts`  | 0 |
| 16:47:52 | GET | `/api/v1.0/tools/compose`  | 0 |
| 16:47:52 | GET | `/api/v1.0/statistics/historical/minute`  | 0 |
| 16:47:54 | GET | `/api/v1.0/public/ping`  | 0 |
| | repeated | `/api/v1.0/public/ping` x2 more | |
| 16:48:29 | GET | `/api/v1.0/system/alerts`  | 401 |
| 16:48:43 | GET | `/settings/system`  | 200 |
| 16:48:44 | GET | `/api/v1.0/tools/compose`  | 401 |
| 16:48:44 | GET | `/api/v1.0/public/device`  | 200 |
| | repeated | `/api/v1.0/public/device` x11 more | |
| 16:48:54 | POST | `/api/v1.0/user/login` json:password,username | 200 |
| 16:48:54 | GET | `/api/v1.0/tools/compose`  | 404 |
| 16:48:54 | POST | `/api/v1.0/tools/compose` json:method,requests,rollback,route | 200 |
| 16:48:55 | GET | `/api/v1.0/tools/compose`  | 200 |
| 16:48:55 | POST | `/api/v1.0/tools/compose` json:method,requests,rollback,route | 200 |
| 16:48:56 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:48:56 | GET | `/api/v1.0/statistics`  | 200 |
| 16:48:56 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:48:56 | POST | `/api/v1.0/tools/proxy/https` json:method,url | 500 |
| 16:48:56 | POST | `/api/v1.0/tools/discovery/neighbors`  | 200 |
| 16:48:56 | GET | `/api/v1.0/system/alerts`  | 200 |
| 16:48:57 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:49:01 | GET | `/api/v1.0/tools/unms`  | 200 |
| 16:49:01 | GET | `/api/v1.0/statistics`  | 200 |
| | repeated | `/api/v1.0/statistics` x3 more | |
| 16:49:40 | GET | `/settings/network`  | 0 |
| | repeated | `/settings/network` x1 more | |
