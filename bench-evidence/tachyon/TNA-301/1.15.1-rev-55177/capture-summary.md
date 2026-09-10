# Capture summary: TNA-301: downgrade, upgrade to 1.15.1 rev 55177, config apply (2026-08-31)

Source capture: `tachyon-301l-downgrade-upgrade-config.har` (262 entries, 1969-12-31T23:59:59 to 2026-08-31T15:51:51, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 41.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- AP-configured, tower/customer-specific unit. Process evidence for the Tachyon upgrade and config-apply requests; not a template.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 15:41:26 | GET | `/cgi.lua/status`  | 200 |
| 15:41:26 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:41:26 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:41:28 | PUT | `/cgi.lua/update` file field: (multipart) | 200 |
| 15:41:35 | POST | `/cgi.lua/update` json:force,reset | 200 |
| 15:41:45 | GET | `/cgi.lua/login`  | 0 |
| 15:41:46 | GET | `/cgi.lua/status`  | 0 |
| 15:41:53 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:41:53 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:42:06 | GET | `/cgi.lua/status`  | 0 |
| 15:42:13 | GET | `/cgi.lua/login`  | 0 |
| 15:42:26 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:42:26 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:42:26 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:42:26 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:42:46 | GET | `/cgi.lua/status`  | 0 |
| 15:42:51 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:42:51 | GET | `/cgi.lua/firmwares`  | 401 |
| 15:42:53 | GET | `/cgi.lua/login`  | 200 |
| 15:42:53 | GET | `/index.html`  | 304 |
| 15:42:53 | GET | `/app.jsx`  | 200 |
| 15:42:53 | GET | `/cgi.lua/login`  | 200 |
| 15:43:19 | POST | `/cgi.lua/login` json:password,username | 200 |
| 15:43:19 | GET | `/cgi.lua/status`  | 200 |
| 15:43:19 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x2 more | |
| 15:43:19 | GET | `/cgi.lua/capabilities`  | 200 |
| 15:43:19 | GET | `/cgi.lua/config`  | 200 |
| 15:43:19 | GET | `/ws.lua/notify`  | 101 |
| 15:43:19 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:43:19 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 15:43:19 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:43:19 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:43:19 | GET | `/cgi.lua/lapse`  | 200 |
| | repeated | `/cgi.lua/lapse` x1 more | |
| 15:43:19 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:43:19 | GET | `/cgi.lua/events`  | 200 |
| 15:43:34 | POST | `/cgi.lua/reset`  | 200 |
| 15:43:39 | GET | `/cgi.lua/status`  | 0 |
| 15:44:13 | GET | `/cgi.lua/bootbank`  | 401 |
| 15:44:13 | GET | `/cgi.lua/firmwares`  | 401 |
| 15:44:13 | GET | `/cgi.lua/bootbank`  | 401 |
| 15:44:13 | GET | `/cgi.lua/firmwares`  | 401 |
| 15:44:32 | POST | `/cgi.lua/login` json:password,username | 200 |
| 15:44:32 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x1 more | |
| 15:44:34 | GET | `/cgi.lua/login`  | 200 |
| 15:44:34 | GET | `/index.html`  | 304 |
| 15:44:34 | GET | `/app.jsx`  | 304 |
| 15:44:34 | GET | `/cgi.lua/login`  | 200 |
| 15:44:34 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x2 more | |
| 15:44:44 | POST | `/cgi.lua/config` json:address,addresses,adv_tz,ageing_time,alias,allowed_ip,alt_local_ip,antenna,auto,autoneg,autoupdate,block_rogue_servers_enabled | 200 |
| 15:44:47 | GET | `/cgi.lua/login`  | 200 |
| 15:44:49 | DELETE | `/cgi.lua/login`  | 200 |
| 15:45:27 | POST | `/cgi.lua/login` json:password,username | 200 |
| 15:45:27 | GET | `/cgi.lua/status`  | 200 |
| 15:45:27 | GET | `/cgi.lua/config`  | 200 |
| 15:45:27 | GET | `/cgi.lua/capabilities`  | 200 |
| 15:45:27 | GET | `/cgi.lua/config`  | 200 |
| 15:45:27 | GET | `/ws.lua/notify`  | 101 |
| 15:45:27 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:45:27 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 15:45:27 | GET | `/cgi.lua/lapse`  | 200 |
| | repeated | `/cgi.lua/lapse` x1 more | |
| 15:45:27 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:45:27 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:45:27 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:45:27 | GET | `/cgi.lua/events`  | 200 |
| 15:45:47 | GET | `/cgi.lua/status`  | 200 |
| 15:45:47 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:45:47 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:45:51 | PUT | `/cgi.lua/update` fw, force file field: (multipart) | 200 |
| 15:46:07 | GET | `/cgi.lua/status`  | 200 |
| 15:46:07 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:46:07 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:46:19 | POST | `/cgi.lua/update` json:force,reset | 200 |
| 15:46:28 | GET | `/cgi.lua/status`  | 0 |
| 15:46:29 | GET | `/cgi.lua/login`  | 0 |
| 15:46:36 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:46:36 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:46:48 | GET | `/cgi.lua/status`  | 0 |
| 15:46:48 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:46:48 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:46:57 | GET | `/cgi.lua/login`  | 0 |
| 15:47:08 | GET | `/cgi.lua/status`  | 0 |
| 15:47:08 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:47:08 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:47:28 | GET | `/cgi.lua/status`  | 0 |
| 15:47:36 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:47:36 | GET | `/cgi.lua/firmwares`  | 0 |
| 15:47:38 | GET | `/cgi.lua/login`  | 0 |
| 15:47:45 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:47:45 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:47:47 | GET | `/ws.lua/heartbeat`  | 101 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 15:47:49 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:47:51 | GET | `/cgi.lua/status`  | 401 |
| 15:47:51 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:47:51 | GET | `/cgi.lua/bootbank`  | 401 |
| 15:47:51 | GET | `/cgi.lua/firmwares`  | 401 |
| 15:48:04 | POST | `/cgi.lua/login` json:password,username | 401 |
| | repeated | `/cgi.lua/login` x1 more | |
| 15:48:10 | GET | `/cgi.lua/status`  | 200 |
| 15:48:10 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x1 more | |
| 15:48:10 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 15:48:10 | GET | `/cgi.lua/lapse`  | 200 |
| | repeated | `/cgi.lua/lapse` x1 more | |
| 15:48:10 | GET | `/ws.lua/notify`  | 101 |
| 15:48:10 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:48:10 | GET | `/cgi.lua/events`  | 200 |
| 15:48:10 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:48:10 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:48:10 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:48:11 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:48:11 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:48:17 | POST | `/cgi.lua/snapshot` cfg file field: (multipart) | 200 |
| 15:48:17 | GET | `/cgi.lua/status`  | 200 |
| 15:48:17 | GET | `/cgi.lua/events`  | 200 |
| 15:48:19 | POST | `/cgi.lua/config` json:address,addresses,ageing_time,alias,allowed_ip,alt_local_ip,auto,autoneg,autoupdate,block_rogue_servers_enabled,broadcast,bssid | 200 |
| 15:48:21 | GET | `/cgi.lua/login`  | 0 |
| 15:48:30 | GET | `/cgi.lua/status`  | 0 |
| 15:48:59 | GET | `/cgi.lua/login`  | 0 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 0 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:36 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:49:36 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:49:40 | GET | `/cgi.lua/login`  | 200 |
| 15:49:50 | GET | `/cgi.lua/status`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:37 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:37 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:43 | GET | `/ws.lua/heartbeat`  | 101 |
| 15:50:43 | GET | `/ws.lua/periodic_stats`  | 101 |
| 15:50:43 | GET | `/ws.lua/notify`  | 101 |
| 15:50:50 | GET | `/cgi.lua/status`  | 200 |
| 15:50:50 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:50 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:50:51 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:50:51 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:10 | GET | `/cgi.lua/status`  | 200 |
| 15:51:10 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:10 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:11 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:11 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:30 | GET | `/cgi.lua/status`  | 200 |
| 15:51:30 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:30 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:31 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:31 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:50 | GET | `/cgi.lua/status`  | 200 |
| 15:51:50 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:50 | GET | `/cgi.lua/firmwares`  | 200 |
| 15:51:51 | GET | `/cgi.lua/bootbank`  | 200 |
| 15:51:51 | GET | `/cgi.lua/firmwares`  | 200 |
