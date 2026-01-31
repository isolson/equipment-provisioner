# Tarana G1 gRPC-Web / gNOI Protocol Reference

> **Source**: HAR captures from the Tarana G1 web UI during a firmware update
> session on 2026-01-30. Device IP `169.254.100.1`, firmware upgraded from
> `SYS.A3.R10.XXX.3.611.002.00` to `SYS.A3.R10.XXX.3.622.005.00`.

---

## Transport Overview

| Transport          | Used For                              | Endpoint Pattern                          |
|--------------------|---------------------------------------|-------------------------------------------|
| HTTP POST (gRPC-web) | gNMI Get/Set, Reboot (unary RPCs)   | `http://<ip>/gnmi.gNMI/Get`, `.../Reboot` |
| WebSocket          | File/Put, SetPackage (streaming RPCs) | `ws://<ip>/gnoi.file.File/Put`, etc.      |

- **WebSocket sub-protocol**: `grpc-websockets`
- **WebSocket frame prefix**: Each client→server gRPC message is prefixed with a
  single byte before the standard gRPC 5-byte header:
  - `0x00` = data frame (followed by `[flag:1][length:4 BE][protobuf]`)
  - `0x01` = end-of-stream / half-close (standalone 1-byte message)
- **Server→client responses** use standard gRPC framing split across pairs of
  WebSocket binary messages: first the 5-byte header (`[flag:1][length:4 BE]`),
  then the payload in a separate WS message.
  - `flag 0x00` = data frame
  - `flag 0x80` = trailer frame (text: `grpc-status: N\r\n`)
- **All WebSocket messages are binary** (opcode 2), not text

---

## Authentication

Every request carries credentials as **custom HTTP headers** (no cookies, no bearer tokens):

```
user: admin
password: admin123
source: device-ui
content-type: application/grpc-web+proto
x-grpc-web: 1
```

- **HTTP requests**: headers go directly on the POST request.
- **WebSocket**: the upgrade can't carry custom headers, so credentials are sent
  as the **first binary WebSocket message** in `key: value\r\n` format (same
  header block above, encoded as UTF-8 bytes).

### Factory default credentials

| Username | Password   |
|----------|------------|
| `admin`  | `admin123` |

### Auth failure detection

Tarana returns **HTTP 200 even on auth failure**. The error is signalled via:

1. `Grpc-Status` / `Grpc-Message` **HTTP response headers** (check first)
2. gRPC **body trailers** (flag `0x80` frame with `grpc-status: N`)

A `Grpc-Status` of `0` = success. Any non-zero value is an error.

---

## Firmware Update Flow (4 Phases)

Observed timing from HAR: ~5.5 minutes total (upload ~28s, install ~2s,
user confirm gap ~2min, reboot + recovery ~2min).

### Phase 1: File Upload — `gnoi.file.File/Put` (WebSocket)

**URL**: `ws://<ip>/gnoi.file.File/Put`

| Msg # | Direction | Content |
|-------|-----------|---------|
| 0     | send      | Auth metadata (binary, 109 bytes, NO `0x00` prefix — raw header text ending with `\r\n`) |
| 1     | send      | `0x00` + gRPC frame: **PutRequest.open** (filename only, no permissions) — 41 bytes |
| 2…N   | send      | `0x00` + gRPC frames: **PutRequest.contents** (64 KB chunks) — 65546 bytes each |
| N+1   | send      | `0x00` + gRPC frame: **PutRequest.hash** (MD5, hash_type=3) — 28 bytes |
| N+2   | send      | EOS `0x01` (standalone byte, no gRPC header) |
| —     | recv      | 3 binary WS message pairs: response headers, PutResponse (filename echo), trailers `grpc-status: 0` |

#### PutRequest.open protobuf (msg 1)

```
field 1 (Details) {        // PutRequest.open
  field 1 (string): "<bare-filename>.tbn"   // remote_file — NO /tmp/ prefix
  // NO permissions field — browser omits it
}
```

Raw hex example (41 bytes total = 5 gRPC header + 36 protobuf):
```
00 00000023              # gRPC: uncompressed, 35 bytes
0a 21                    # field 1, len 33 (Details)
  0a 1f                  # field 1, len 31 (remote_file)
    5359532e41332e...    # "SYS.A3.R10.XXX.3.622.005.00.tbn"
```

#### PutRequest.contents protobuf (msgs 2…N)

```
field 2 (bytes): <65536 bytes of firmware data>   // PutRequest.contents
```

Each gRPC frame is ~65,546 bytes (5 header + 6 protobuf overhead + 65,536 data).
Chunk size is exactly **64 KB (65,536 bytes)**. Last chunk may be smaller.

#### PutRequest.hash protobuf (msg N+1)

```
field 3 (HashType) {       // PutRequest.hash
  field 1 (uint64): 3     // method = MD5 (⚠ Tarana maps 3 = MD5, not SHA512)
  field 2 (bytes): <16 bytes MD5 digest>
}
```

Raw hex example (28 bytes total = 5 gRPC header + 1 padding? + 22 protobuf):
```
00 00000016              # gRPC: uncompressed, 22 bytes
1a 14                    # field 3, len 20 (hash)
  08 03                  # field 1 = 3 (MD5)
  12 10                  # field 2, len 16
    ac22de59108d367f2f356517ec9090e1   # MD5 digest
```

---

### Phase 2: Package Install — `gnoi.system.System/SetPackage` (WebSocket)

**URL**: `ws://<ip>/gnoi.system.System/SetPackage`

| Msg # | Direction | Content |
|-------|-----------|---------|
| 0     | send      | Auth metadata (binary, 109 bytes) |
| 1     | send      | gRPC frame: **SetPackageRequest.package** |
| 2     | send      | gRPC frame: **SetPackageRequest.hash** (same MD5 from upload) |
| 3     | send      | EOS `0x01` |
| —     | recv      | Response headers, empty body, trailers `grpc-status: 0` |

Duration: ~2 seconds.

#### SetPackageRequest.package protobuf (msg 1)

**⚠ Tarana uses a NON-STANDARD Package proto.** The field numbers differ
from the OpenConfig gNOI spec.

Standard gNOI:
```
message Package { string filename = 1; string version = 2; bool activate = 3; }
```

Tarana G1 actual (from HAR):
```
message Package {                // field 1 of SetPackageRequest
  string filename = 1;
  // fields 2–4: unknown / unused
  bool activate = 5;             // ⚠ NOT field 3
  VersionInfo version_info = 6;  // ⚠ extra field, not in standard gNOI
}

message VersionInfo {
  string version = 1;            // same filename string
  int32 method = 2;              // observed value: 10
}
```

Raw hex (80 bytes total = 5 gRPC header + 75 protobuf):
```
00 0000004a              # gRPC: uncompressed, 74 bytes
0a 48                    # field 1, len 72 (SetPackageRequest.package)
  0a 23                  # field 1, len 35 (Package)
    0a 1f                #   field 1, len 31 (filename)
      5359532e...        #     "SYS.A3.R10.XXX.3.622.005.00.tbn"
    28 01                #   field 5, varint 1 (activate = true)
  32 21                  # field 6, len 33 (VersionInfo)
    0a 1f                #   field 1, len 31 (version string)
      5359532e...        #     "SYS.A3.R10.XXX.3.622.005.00.tbn"
    10 0a                #   field 2, varint 10 (method?)
```

#### SetPackageRequest.hash protobuf (msg 2)

**Identical** to the PutRequest.hash sent during File/Put:
```
field 3 (HashType) {
  field 1: 3             // MD5
  field 2: <16 bytes>    // same digest
}
```

---

### Phase 3: Reboot — `gnoi.system.System/Reboot` (HTTP POST)

**URL**: `POST http://<ip>/gnoi.system.System/Reboot`
**Transport**: Standard gRPC-web HTTP POST (NOT WebSocket)

Request body: 5 bytes — empty RebootRequest:
```
00 00000000              # gRPC: uncompressed, 0 bytes (empty proto)
```

Response: `grpc-status: 0` then device reboots.
The HTTP response arrives before the device actually reboots (~267ms round-trip).

---

### Phase 4: Post-Reboot Recovery

| Event | Time After Reboot |
|-------|-------------------|
| Device still responds | 0–13 seconds |
| First failed request (status=0) | ~13 seconds |
| Device offline | ~13s – ~2 minutes |
| First successful response | ~2 minutes |
| Normal operation resumes | ~2 min 15s |

The browser polls continuously through the reboot; it handles connection
failures gracefully and detects recovery by a successful `gnmi.gNMI/Get`.

---

## gNMI Polling Patterns (Background)

The web UI runs these queries concurrently at different intervals:

| Interval | Request Size | gNMI Paths | Response Size |
|----------|-------------|------------|---------------|
| ~2s      | 93 B        | `/connections/connection[id=0]/state`, `/radios/radio[id=0]/state`, `/radios/radio[id=1]/state` | ~5.3 KB |
| ~5s      | 199 B       | `/radios/global/state`, `/radios/regulatory/state`, `/radios/radio[id=*]/state/change-reason-message` | ~1.2 KB |
| ~15s     | 63 B        | `/system/alarms/alarm[id=*][status=raised]` | ~1.3 KB |
| ~15s     | 158 B       | `/platform/components/component[name=sys]`, `component[name=digboard]`, `/system`, `/platform/components` | ~20 KB |
| On-demand| 17 B        | `/system` (full tree) | ~13.6 KB |

---

## Firmware Bank Layout (A/B scheme)

| Field | gNMI Path | Example Value |
|-------|-----------|---------------|
| Bank 1 version | `/system/software/banks/state/system1` | `SYS.A3.R10.XXX.3.611.002.00` |
| Bank 2 version | `/system/software/banks/state/system2` | `SYS.A3.R10.XXX.3.622.005.00` |
| Active bank | `/system/software/state/active-bank` | `system2` |
| Current bank | `/system/software/state/current-bank` | `system2` |
| Next install | `/system/software/state/next-install-bank` | `system1` |
| Factory version | `/system/software/banks/state/factory` | `SYS.A3.R10.XXX.3.611.002.00` |

After upgrade: device runs from the newly written bank. Next install
target flips to the other bank (A/B alternation).

### Post-reboot state fields

| gNMI Path | Value |
|-----------|-------|
| `software/state/reboot/reason` | `USER_REBOOT` |
| `software/state/reboot/secondary-reason` | `USER_SW_UPGRADE` |
| `software/state/boot-status` | `success` |
| `software/state/boot-reason` | `warm boot` |
| `software/state/upgrade-status` | (empty = idle) |

---

## Device Identity

| gNMI Path | Example |
|-----------|---------|
| `/system/state/hostname` | `S197A1252300723` (= serial number) |
| `/system/state/role` | `rn` (Remote Node) or `bn` (Base Node) |
| `/platform/components/component[name=sys]/state/serial-no` | `S197A1252300723` |
| `/platform/components/component[name=sys]/state/software-version` | `SYS.A3.R10.XXX.3.622.005.00` |
| `/platform/components/component[name=sys]/state/firmware-version` | `CBL.A3.R10.XXX.3.901.000.00` |
| `/platform/components/component[name=digboard]/state/serial-no` | `M228A1252300215` |

---

## Known Issues / Gotchas

1. **HTTP 200 on auth failure** — always check `Grpc-Status` header before body.
2. **Hash type 3 = MD5** — contradicts standard gNOI enum (3 = SHA512).
   Always send 16-byte MD5 digest with type 3 for Tarana.
3. **Non-standard SetPackage proto** — `activate` is at field 5, not field 3.
   Extra `VersionInfo` block at field 6 is required.
4. **Version strings are exact** — `SYS.A3.R10.XXX.3.622.005.00` must match
   verbatim between firmware filename (minus `.tbn`) and bank query result.
5. **Filename is bare** — `SYS.A3...tbn`, not `/tmp/SYS.A3...tbn`.
6. **WebSocket auth is binary** — first WS message must be binary (opcode 2),
   not text (opcode 1), containing the credential headers.
7. **WebSocket gRPC data frames need `0x00` prefix** — unlike gRPC-web over
   HTTP POST (5-byte header), the `grpc-websockets` protocol prepends `0x00`
   before each gRPC frame. Missing this byte causes "Cannot write to closing
   transport" as the server rejects the malformed frames.
8. **Auth metadata needs trailing `\r\n`** — the metadata string must end with
   `\r\n` after the last header line (109 bytes total for default creds).
9. **Server responses are binary pairs** — the server sends each gRPC frame
   split across two WebSocket binary messages (5-byte header, then payload).
   There are no TEXT WebSocket frames in the response.
