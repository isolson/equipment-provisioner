# Capture summary: TNA-303L-65: config restore, factory reset, first-boot, export, config restore on 1.15.1 (2026-09-02)

Source capture: `303L-resetconfigprovision1.15.har` (134 entries, 1969-12-31T23:59:59 to 2026-09-02T20:44:58, WebInspector). Raw file stays in the secure bench directory.

Device host: `169.254.1.1`. Requests to other hosts (browser telemetry, extensions) omitted: 27.

This summary lists device operations only. It carries no credentials, tokens, keys, or bodies.

## What the capture did

- Unit: the bench TNA-303L-65 at 169.254.1.1 on 1.15.1 rev 8541, cabled to a laptop. Times in the table are UTC; local is UTC minus five.
- 15:26 local: export of the populated post-migration configuration (4 SM profiles, 3 users, remote syslog target, SNMPv3 encryption mode). Filed as before-reset.device-backup.tar.
- 15:41 local: POST /cgi.lua/config with loginUpdate (password change), POST /cgi.lua/snapshot, then POST /cgi.lua/config with the full populated configuration (4 profiles, 3 users, syslog target present in the request).
- 15:42 local: POST /cgi.lua/reset is the factory reset. The device dropped the session, answered 401 until the first-boot login page returned.
- 15:44 local: first-boot POST /cgi.lua/config with loginUpdate (admin password), login, POST /cgi.lua/snapshot with a cfg form (the export), then POST /cgi.lua/config with the full populated configuration again. The 15:44:32 export was taken seven seconds before that restore, so it is the exact post-reset no-config backup on 1.15.1: 0 profiles, 1 user, no syslog target. Filed as after-reset-restore.device-backup.tar and reduced to the no-config fixture.
- No export exists after the 15:44:39 restore. Whether the restore keeps the 4 profiles on 1.15.1 is still unproven; one more export from the unit settles it.
- Endpoint facts: POST /cgi.lua/reset (factory reset), POST /cgi.lua/config with loginUpdate (first-boot password), POST /cgi.lua/snapshot (export), POST /cgi.lua/config with data (full apply), GET /cgi.lua/bootbank and /cgi.lua/firmwares (bank state).

## Request sequence

| Time | Method | Path and form field names | Status |
| --- | --- | --- | --- |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 23:59:59 |  | `/ws.lua/heartbeat`  | 0 |
| 23:59:59 |  | `/ws.lua/notify`  | 0 |
| 23:59:59 |  | `/ws.lua/periodic_stats`  | 0 |
| 20:41:09 | POST | `/cgi.lua/config` json:address,ageing_time,alias,alias6,alt_local_ip,antenna,auto,autoneg,block_mgmt_access,block_rogue_servers_enabled,boresight_lock,broadcast | 200 |
| 20:41:12 | DELETE | `/cgi.lua/login`  | 200 |
| 20:41:18 | POST | `/cgi.lua/login` json:password,username | 200 |
| 20:41:18 | GET | `/cgi.lua/status`  | 200 |
| 20:41:18 | GET | `/cgi.lua/config`  | 200 |
| 20:41:18 | GET | `/cgi.lua/capabilities`  | 200 |
| 20:41:18 | GET | `/cgi.lua/config`  | 200 |
| 20:41:18 | GET | `/ws.lua/notify`  | 101 |
| 20:41:18 | GET | `/ws.lua/periodic_stats`  | 101 |
| 20:41:18 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 20:41:18 | GET | `/cgi.lua/bootbank`  | 200 |
| 20:41:18 | GET | `/cgi.lua/firmwares`  | 200 |
| 20:41:18 | GET | `/ws.lua/heartbeat`  | 101 |
| 20:41:18 | GET | `/cgi.lua/events`  | 200 |
| 20:41:18 | GET | `/cgi.lua/lapse`  | 200 |
| 20:41:32 | POST | `/cgi.lua/snapshot` file field: (multipart) | 200 |
| 20:41:34 | POST | `/cgi.lua/config` json:address,addresses,ageing_time,alias,alias6,alt_local_ip,autoneg,autoupdate,block_mgmt_access,block_rogue_servers_enabled,broadcast,carrier_drop | 200 |
| 20:41:35 | GET | `/cgi.lua/status`  | 200 |
| 20:41:35 | GET | `/cgi.lua/events`  | 200 |
| 20:41:37 | GET | `/cgi.lua/login`  | 0 |
| 20:41:38 | GET | `/cgi.lua/bootbank`  | 0 |
| 20:41:38 | GET | `/cgi.lua/firmwares`  | 0 |
| 20:41:42 | GET | `/ws.lua/heartbeat`  | 101 |
| 20:41:43 | GET | `/ws.lua/notify`  | 101 |
| 20:41:44 | GET | `/cgi.lua/login`  | 200 |
| 20:41:45 | GET | `/ws.lua/periodic_stats`  | 101 |
| 20:41:51 | DELETE | `/cgi.lua/login`  | 200 |
| 20:41:55 | POST | `/cgi.lua/login` json:password,username | 200 |
| 20:41:55 | GET | `/cgi.lua/status`  | 200 |
| 20:41:55 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x1 more | |
| 20:41:55 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 20:41:55 | GET | `/ws.lua/notify`  | 101 |
| 20:41:55 | GET | `/ws.lua/periodic_stats`  | 101 |
| 20:41:56 | GET | `/cgi.lua/events`  | 200 |
| 20:41:56 | GET | `/cgi.lua/bootbank`  | 200 |
| 20:41:56 | GET | `/cgi.lua/firmwares`  | 200 |
| 20:41:56 | GET | `/cgi.lua/lapse`  | 200 |
| 20:41:56 | GET | `/ws.lua/heartbeat`  | 101 |
| 20:42:01 | POST | `/cgi.lua/reset`  | 200 |
| 20:42:16 | GET | `/cgi.lua/status`  | 0 |
| 20:42:16 | GET | `/cgi.lua/bootbank`  | 0 |
| 20:42:16 | GET | `/cgi.lua/firmwares`  | 0 |
| 20:42:36 | GET | `/cgi.lua/status`  | 0 |
| 20:42:36 | GET | `/cgi.lua/bootbank`  | 0 |
| 20:42:36 | GET | `/cgi.lua/firmwares`  | 0 |
| 20:42:56 | GET | `/cgi.lua/status`  | 401 |
| 20:42:56 | GET | `/cgi.lua/bootbank`  | 401 |
| 20:42:56 | GET | `/cgi.lua/firmwares`  | 401 |
| 20:43:01 | GET | `/cgi.lua/login`  | 200 |
| 20:43:01 | GET | `/index.html`  | 304 |
| 20:43:01 | GET | `/app.jsx`  | 304 |
| 20:43:01 | GET | `/cgi.lua/login`  | 200 |
| 20:44:07 | POST | `/cgi.lua/login` json:password,username | 200 |
| 20:44:07 | GET | `/cgi.lua/config`  | 200 |
| | repeated | `/cgi.lua/config` x3 more | |
| 20:44:17 | POST | `/cgi.lua/config` json:address,ageing_time,alias,alias6,alt_local_ip,antenna,auto,autoneg,block_mgmt_access,block_rogue_servers_enabled,boresight_lock,broadcast | 200 |
| 20:44:19 | DELETE | `/cgi.lua/login`  | 200 |
| 20:44:21 | POST | `/cgi.lua/login` json:password,username | 200 |
| 20:44:21 | GET | `/cgi.lua/status`  | 200 |
| 20:44:21 | GET | `/cgi.lua/config`  | 200 |
| 20:44:21 | GET | `/cgi.lua/capabilities`  | 200 |
| 20:44:21 | GET | `/cgi.lua/config`  | 200 |
| 20:44:21 | GET | `/ws.lua/notify`  | 101 |
| 20:44:21 | GET | `/ws.lua/periodic_stats`  | 101 |
| 20:44:22 | GET | `/cgi.lua/status`  | 200 |
| | repeated | `/cgi.lua/status` x2 more | |
| 20:44:22 | GET | `/cgi.lua/bootbank`  | 200 |
| 20:44:22 | GET | `/cgi.lua/firmwares`  | 200 |
| 20:44:22 | GET | `/ws.lua/heartbeat`  | 101 |
| 20:44:22 | GET | `/cgi.lua/events`  | 200 |
| 20:44:22 | GET | `/cgi.lua/lapse`  | 200 |
| 20:44:37 | POST | `/cgi.lua/snapshot` cfg file field: (multipart) | 200 |
| 20:44:39 | POST | `/cgi.lua/config` json:address,addresses,ageing_time,alias,alias6,alt_local_ip,autoneg,autoupdate,block_mgmt_access,block_rogue_servers_enabled,broadcast,carrier_drop | 200 |
| 20:44:40 | GET | `/cgi.lua/status`  | 200 |
| 20:44:40 | GET | `/cgi.lua/events`  | 200 |
| 20:44:41 | GET | `/cgi.lua/login`  | 0 |
| 20:44:42 | GET | `/cgi.lua/bootbank`  | 0 |
| 20:44:42 | GET | `/cgi.lua/firmwares`  | 0 |
| 20:44:47 | GET | `/ws.lua/heartbeat`  | 101 |
| 20:44:47 | GET | `/ws.lua/notify`  | 101 |
| 20:44:48 | GET | `/cgi.lua/login`  | 200 |
| 20:44:49 | GET | `/ws.lua/periodic_stats`  | 101 |
| 20:44:58 | DELETE | `/cgi.lua/login`  | 200 |
