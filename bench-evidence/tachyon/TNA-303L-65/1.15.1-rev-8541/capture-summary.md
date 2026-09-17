# Capture summary: TNA-303L-65: downgrade, upgrade to 1.15.1 rev 8541, config apply (2026-08-31)

Source capture: `tachyon-303l-downgrade-upgrade-config.har` (213 entries, 1969-12-31T23:59:59 to 2026-08-31T14:46:49, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 55.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- SM unit. Process evidence for the Tachyon firmware transition and config apply; the known-good post-apply backup is the SM fixture source.

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| | repeated | `/ws.lua/periodic_stats` x1 more | |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 14:37:35 | POST | `/cgi.lua/login` json:password,username | 200 |
| 14:37:35 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x3 more | |
| 14:37:47 | POST | `/cgi.lua/config` json:address,ageing_time,alias,alias6,alt_local_ip,antenna,auto,autoneg,block_mgmt_access,block_rogue_servers_enabled,boresight_lock,broadcast | 200 |
| 14:37:49 | DELETE | `/cgi.lua/login`  | 200 |
| 14:37:53 | POST | `/cgi.lua/login` json:password,username | 200 |
| 14:37:53 | GET | `/cgi.lua/status`  | 200 |
| 14:37:53 | GET | `/cgi.lua/config`  | 200 |
| 14:37:53 | GET | `/cgi.lua/capabilities`  | 200 |
| 14:37:53 | GET | `/cgi.lua/config`  | 200 |
| 14:37:53 | GET | `/ws.lua/notify`  | 101 |
| 14:37:53 | GET | `/ws.lua/periodic_stats`  | 101 |
| 14:37:53 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 14:37:53 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:37:53 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:37:53 | GET | `/ws.lua/heartbeat`  | 101 |
| 14:37:53 | GET | `/cgi.lua/events`  | 200 |
| 14:37:53 | GET | `/cgi.lua/lapse`  | 200 |
| 14:38:09 | PUT | `/cgi.lua/update` file field: (multipart) | 200 |
| 14:38:13 | GET | `/cgi.lua/status`  | 200 |
| 14:38:17 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:38:17 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:38:23 | POST | `/cgi.lua/update` json:force,reset | 200 |
| 14:38:33 | GET | `/cgi.lua/status`  | 0 |
| 14:38:34 | GET | `/cgi.lua/login`  | 0 |
| 14:38:41 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:38:41 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:38:53 | GET | `/cgi.lua/status`  | 0 |
| 14:38:53 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:38:53 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:39:01 | GET | `/cgi.lua/login`  | 0 |
| 14:39:13 | GET | `/cgi.lua/status`  | 0 |
| 14:39:22 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:39:22 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:39:35 | GET | `/cgi.lua/status`  | 0 |
| 14:39:35 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:39:35 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:39:42 | GET | `/cgi.lua/login`  | 0 |
| 14:39:54 | GET | `/cgi.lua/status`  | 0 |
| 14:39:54 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:39:54 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:40:05 | GET | `/ws.lua/heartbeat`  | 101 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 14:40:10 | GET | `/ws.lua/periodic_stats`  | 101 |
| 14:40:10 | GET | `/ws.lua/heartbeat`  | 101 |
| | repeated | `/ws.lua/heartbeat` x1 more | |
| 14:40:14 | GET | `/cgi.lua/status`  | 401 |
| 14:40:14 | GET | `/ws.lua/heartbeat`  | 101 |
| 14:40:14 | GET | `/cgi.lua/bootbank`  | 401 |
| 14:40:14 | GET | `/cgi.lua/firmwares`  | 401 |
| 14:40:35 | GET | `/cgi.lua/status`  | 401 |
| 14:40:35 | GET | `/cgi.lua/bootbank`  | 401 |
| 14:40:35 | GET | `/cgi.lua/firmwares`  | 401 |
| 14:40:55 | GET | `/cgi.lua/status`  | 401 |
| 14:40:55 | GET | `/cgi.lua/bootbank`  | 401 |
| 14:40:55 | GET | `/cgi.lua/firmwares`  | 401 |
| 14:41:03 | GET | `/cgi.lua/login`  | 200 |
| 14:41:03 | GET | `/index.html`  | 200 |
| 14:41:03 | GET | `/app.jsx`  | 200 |
| 14:41:03 | GET | `/cgi.lua/login`  | 200 |
| 14:43:49 | POST | `/cgi.lua/login` json:password,username | 401 |
| | repeated | `/cgi.lua/login` x1 more | |
| 14:43:52 | GET | `/cgi.lua/status`  | 200 |
| 14:43:52 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x2 more | |
| 14:43:52 | GET | `/cgi.lua/capabilities`  | 200 |
| 14:43:52 | GET | `/cgi.lua/config`  | 200 |
| 14:43:52 | GET | `/ws.lua/notify`  | 101 |
| 14:43:52 | GET | `/ws.lua/periodic_stats`  | 101 |
| 14:43:53 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 14:43:53 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:43:53 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:43:53 | GET | `/ws.lua/heartbeat`  | 101 |
| 14:43:53 | GET | `/cgi.lua/events`  | 200 |
| 14:43:53 | GET | `/cgi.lua/lapse`  | 200 |
| 14:44:13 | GET | `/cgi.lua/status`  | 200 |
| 14:44:13 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:44:13 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:44:15 | PUT | `/cgi.lua/update` file field: (multipart) | 200 |
| 14:44:22 | POST | `/cgi.lua/update` json:force,reset | 200 |
| 14:44:32 | GET | `/cgi.lua/login`  | 0 |
| 14:44:33 | GET | `/cgi.lua/status`  | 0 |
| 14:44:41 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:44:41 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:44:53 | GET | `/cgi.lua/status`  | 0 |
| 14:44:53 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:44:53 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:45:01 | GET | `/cgi.lua/login`  | 0 |
| 14:45:13 | GET | `/cgi.lua/status`  | 0 |
| 14:45:20 | GET | `/cgi.lua/bootbank`  | 0 |
| 14:45:20 | GET | `/cgi.lua/firmwares`  | 0 |
| 14:45:40 | GET | `/cgi.lua/status`  | 401 |
| 14:45:42 | GET | `/cgi.lua/login`  | 0 |
| 14:46:01 | GET | `/cgi.lua/bootbank`  | 401 |
| 14:46:01 | GET | `/cgi.lua/firmwares`  | 401 |
| 14:46:01 | GET | `/cgi.lua/bootbank`  | 401 |
| 14:46:01 | GET | `/cgi.lua/firmwares`  | 401 |
| 14:46:09 | POST | `/cgi.lua/login` json:password,username | 200 |
| 14:46:09 | GET | `/cgi.lua/status`  | 200 |
| 14:46:09 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x1 more | |
| 14:46:09 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 14:46:09 | GET | `/ws.lua/notify`  | 101 |
| 14:46:09 | GET | `/ws.lua/periodic_stats`  | 101 |
| 14:46:09 | GET | `/cgi.lua/lapse`  | 200 |
| 14:46:09 | GET | `/cgi.lua/events`  | 200 |
| 14:46:09 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:46:09 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:46:09 | GET | `/ws.lua/heartbeat`  | 101 |
| 14:46:18 | POST | `/cgi.lua/snapshot` file field: (multipart) | 200 |
| 14:46:20 | POST | `/cgi.lua/config` json:address,ageing_time,alias,alias6,alt_local_ip,antenna,auto,autoneg,block_mgmt_access,block_rogue_servers_enabled,boresight_lock,broadcast | 200 |
| 14:46:21 | GET | `/cgi.lua/status`  | 200 |
| 14:46:21 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:46:21 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:46:21 | GET | `/cgi.lua/status`  | 200 |
| 14:46:21 | GET | `/cgi.lua/events`  | 200 |
| 14:46:23 | GET | `/cgi.lua/login`  | 0 |
| 14:46:29 | GET | `/cgi.lua/status`  | 200 |
| 14:46:29 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:46:29 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:46:29 | GET | `/ws.lua/periodic_stats`  | 101 |
| 14:46:29 | GET | `/ws.lua/heartbeat`  | 101 |
| 14:46:29 | GET | `/ws.lua/notify`  | 101 |
| 14:46:30 | GET | `/cgi.lua/login`  | 200 |
| 14:46:41 | GET | `/cgi.lua/status`  | 200 |
| 14:46:41 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:46:41 | GET | `/cgi.lua/firmwares`  | 200 |
| 14:46:49 | GET | `/cgi.lua/status`  | 200 |
| 14:46:49 | GET | `/cgi.lua/bootbank`  | 200 |
| 14:46:49 | GET | `/cgi.lua/firmwares`  | 200 |
