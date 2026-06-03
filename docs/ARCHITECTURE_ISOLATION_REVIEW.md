# Architecture & Vendor-Isolation Review

> Audit of how modular the provisioner is: can one vendor be removed cleanly, and could the system be reduced to a single-vendor build? Tachyon is used as the worked example. Companion to `docs/epic-vendor-isolation-refactor.md` (the remediation plan).

## Headline verdict

- **Handler/behavior layer: excellent isolation (A-grade).** Each vendor's provisioning logic lives entirely in `handlers/{vendor}.py` (+ `firmware_sources/{vendor}.py` + `configs/templates/{vendor}/`). No handler imports another. Touching Tachyon cannot break Cambium. The property-driven `provision()` flow is honored almost everywhere.
- **Registration/enumeration layer: leaky (C-grade).** The claim *"only the `DeviceType` enum and `HANDLER_MAP`"* is **false**. The vendor list is duplicated across **6–8 independent sources of truth**, with **no single add/remove point**. The system is *subtractively modular* (you can carve a vendor out) but **not** *additively pluggable* (a vendor cannot self-register).
- **Can Tachyon come out and the rest still work?** → **Yes.** Nothing depends on Tachyon behaviorally. But it's a **~12–14 file edit**, not the "3 files" the docs imply, and a few sites crash-on-omission rather than failing silently.
- **Could it reduce to one vendor?** → **Yes, and the result is *cleaner*** — the core engine is vendor-neutral; `fingerprint.py`'s entire detection cascade (~80% of it) collapses to nothing.

---

## 1. System hierarchy (the map)

**Entry points**
- `systemd/provisioner-web.service` → `python -m provisioner.web_server` → provisioning loop **+** FastAPI UI on `:8080`.
- `systemd/provisioner.service` → `python -m provisioner.main` → headless loop only.

**Layered structure**

| Layer | Modules | Role | Vendor-aware? |
|---|---|---|---|
| **Orchestration** | `main.py` (`Provisioner`), `web_server.py` | Port-event loop, dispatch, credential assembly | **Yes (leaks)** |
| **Detection** | `fingerprint.py` (`DeviceFingerprinter`, `DeviceType`) | "What is this device?" via port-scan → per-vendor probes → HTTP/SSH/SNMP signatures | **Yes (by necessity)** |
| **Routing** | `handler_manager.py` (`HANDLER_MAP`) | Map `DeviceType` → handler instance | **Yes (the blessed registry)** |
| **Provisioning engine** | `handlers/base.py` (`BaseHandler.provision()`) | Property-driven flow: Login→Info→FW1→Reboot→Verify→Config→FW2 | **Mostly no** (1 leak) |
| **Vendor handlers** | `handlers/{mikrotik,cambium,tachyon,tarana,ubiquiti,evolution_digital}.py` | All vendor behavior | **Self-contained ✅** |
| **Supporting registries** | `firmware.py`, `config_store.py`, `port_manager.py`, `config.py` | FW patterns, config aliases, link-local IPs, typed config schema | **Yes (leaks)** |
| **Presentation** | `web/api.py`, `web/templates/index.html`, `web/static/vendor-icons/` | REST + touchscreen UI | **Yes (leaks)** |

**Data flow (device plugged in → provisioned):**
`port_manager` detects link on VLAN iface → boot-pings vendor link-local IPs (`DeviceLinkLocalIP.ALL`) → `fingerprint.identify_device()` classifies → `handler_manager.get_handler()` reads `HANDLER_MAP` → `base.provision()` runs the property-driven flow → progress streamed to UI via websocket. Verified dispatch points: `handler_manager.py:69`, `fingerprint.py:416-471`, `base.py:308`, `main.py:438` (Evolution Digital side-door).

**The flow-control contract (works as documented):** `provision()` reads handler **properties** — `supports_dual_bank`, `config_after_all_firmware`, `update_triggers_reboot`, `verify_active_bank`, `fw2_skips_reboot`, `supports_password_change` — to decide order, never `if vendor ==`. Properties may be conditional on `self._device_info.model` (e.g. Tachyon's `config_after_all_firmware` is True only for `tns-` models). This is the strong part of the design and it holds.

---

## 2. The core finding: the vendor list has 6–8 sources of truth

To **add or remove one vendor**, you must edit *every* one of these. There is no single registry. (CLAUDE.md claims only the first two.)

| # | Source of truth | Location | In the "blessed" contract? |
|---|---|---|---|
| 1 | `DeviceType` enum | `fingerprint.py:36` | ✅ yes |
| 2 | `HANDLER_MAP` (+ import) | `handler_manager.py:10,24` | ✅ yes |
| 3 | `handlers/__init__.py` import + `__all__` | `handlers/__init__.py` | ❌ undocumented |
| 4 | CLI handler dict + `choices=[...]` | `cli.py:383,522,568` | ❌ **duplicate of #2** |
| 5 | `VALID_DEVICE_TYPES` set | `web/api.py:1156` (used 2159/2193/2235/2270) | ❌ **duplicate** |
| 6 | UI vendor metadata map | `index.html:347` | ❌ **duplicate (frontend)** |
| 7 | Per-vendor pydantic classes + fields | `config.py:47-53` (`DeviceIPsConfig`), `97-120` (`*Credentials`/`CredentialsConfig`), firmware sources, feature flags | ❌ undocumented |
| 8 | `DeviceLinkLocalIP` consts + `.ALL` + inline copy | `port_manager.py:112` **and** `:982` | ⚠️ partly blessed, **self-duplicated** |

Credentials specifically have **four** copies: `CredentialsConfig` (`config.py:114`), the `main.py:109` dict, handler `DEFAULT_CREDENTIALS`, and `BUILTIN_CREDENTIALS` (`api.py:2086`).

**Implication:** the registry is not DRY. Forgetting any one site is the dominant failure mode of both extraction directions — and the failure mode varies (see §4).

---

## 3. Audit-grade leak table (every vendor-name reference outside the handlers)

Severity key — **S1/High**: explicit rule violation, or crash/silent-wrong if mishandled. **S2/Med**: real isolation leak (table-shaped, contained). **S3/Low**: cosmetic / by-design / docs.

| Sev | Leak | Location | Notes |
|---|---|---|---|
| **S1** | `if self.device_type == "mikrotik"` in the engine | `base.py:395-403` (`firmware_lookup_key`) | **The one true rule violation.** Should be a handler property override. Contained to 1 spot. |
| **S1** | Credentials dict ↔ config schema coupling | `main.py:109-129` ⟷ `config.py:97-120` | `self.config.credentials.tachyon` hardcoded. Remove from one but not the other → **AttributeError at startup**. Must move together. |
| **S1** | Handler imports | `handler_manager.py:10`, `handlers/__init__.py` | Delete a handler file but leave the import → **ImportError at startup** (hard crash). |
| **S2** | `HTTP_SIGNATURES` per-vendor regex blocks | `fingerprint.py:139-186` | Stale entries = harmless dead code; *missing* = device undetected. |
| **S2** | Dedicated probe methods + call sites | `fingerprint.py:426` (MikroTik :8728), `:434/589` (`_probe_tachyon_api`), `:441/694` (`_probe_wave_api`), `:991` (SSH banner), `:1030` (SNMP), `:1075` (`_get_mikrotik_info`) | The detection cascade is hand-wired per vendor — the biggest concentration of vendor knowledge outside handlers. |
| **S2** | `_extract_device_details` per-vendor `elif` chain | `fingerprint.py:~854-912` | Model/version regex branch per `DeviceType`. |
| **S2** | `MODEL_FIRMWARE_PATTERNS` | `firmware.py:165-218` | Vendor model→filename-pattern table. Dead rows harmless. |
| **S2** | Typed per-vendor config classes + IP defaults + feature flags | `config.py:47-53,97-120`, `apply_config_ubiquiti`/`apply_config_tarana`, `device_settings.tarana/.mikrotik` | Schema-level coupling. `apply_config_<vendor>` flags should be generic/table-driven. |
| **S2** | CLI handler dict + choices | `cli.py:383,522,568` | **Second copy** of the handler registry. |
| **S2** | `VALID_DEVICE_TYPES` + filename→type inference + UI lists + `BUILTIN_CREDENTIALS` | `web/api.py:1156,1208-1217,2068,2086` | **Third + fourth copies** of the vendor list. Plus MikroTik netinstall/ZTP and Tarana-settings blocks. |
| **S2** | UI vendor map + behavioral branches | `index.html:347` (map), `:966` (`canApplyMode`), `:1307` (Tachyon SSID uppercase) | **Frontend copy** + 2 vendor-specific UI behaviors. |
| **S2** | `DeviceLinkLocalIP` self-duplication | `port_manager.py:112` vs inline `:982-986` | Same IP→vendor data twice in one file. |
| **S2** | Tarana settings injection in main loop | `main.py:568-578` | Vendor `if device_type == "tarana"` in orchestrator. |
| **S3** | `CONFIG_MODEL_ALIASES` | `config_store.py:35-43` | Optional; dead entries harmless. |
| **S3** | Evolution Digital side-door dispatch | `main.py:438,757` | **By design & documented** (`handler_manager.py:21-23`): ED runs a passive cross-port flow, intentionally not in `HANDLER_MAP`. |
| **S3** | MikroTik/ED OUI tables, netinstall/BOOTP gating | `fingerprint.py:50-120`, `web/api.py` netinstall blocks | Vendor-specific but justified (destructive-op gating). |
| **S3** | Per-vendor firmware scrapers | `firmware_sources/{vendor}.py` | Self-contained like handlers — good isolation, just enumerated. |
| **S3** | Docs / labels / README / vendor icons / `config.yaml` | `README.md`, `docs/*`, `label-*.html`, `web/static/vendor-icons/*.png`, `config.yaml` | Cosmetic + runtime data (not code). |

---

## 4. Direction A — Pull Tachyon out (the worked example)

**Answer: Yes, cleanly — nothing behaviorally depends on Tachyon.** Cost ≈ 12–14 files.

**Delete outright (self-contained):** `handlers/tachyon.py`, `firmware_sources/tachyon.py`, `configs/templates/tachyon/`, `web/static/vendor-icons/tachyon.png`, Tachyon test cases.

**Must edit or it crashes (S1):** `handler_manager.py` (import + map), `handlers/__init__.py` (import + `__all__`), `config.py` (`TachyonCredentials`, `CredentialsConfig.tachyon`, `DeviceIPsConfig.tachyon`, firmware-source entry), `main.py` (credentials-dict key `:118`), `cli.py` (handler dict + choices).

**Must edit or you get dead code / an undetectable device (S2):** `fingerprint.py` (enum `:40`, `HTTP_SIGNATURES` `:156`, `_probe_tachyon_api` + its call at `:434`, `_extract_device_details` branch), `firmware.py` (3 rows `:186-193`), `config_store.py` (alias block), `port_manager.py` (`DeviceLinkLocalIP` Tachyon consts + `.ALL` + inline list), `web/api.py` (`VALID_DEVICE_TYPES` + `BUILTIN_CREDENTIALS` + filename inference + UI lists), `index.html` (vendor map + `canApplyMode` + SSID-uppercase branch).

**Risk profile:** the danger is *omission*, not breakage. Forgetting an S1 site stops the service at boot; forgetting an S2 site leaves dead code or a silently-undetectable device. `grep -ri tachyon provisioner/ configs/` is the safety net.

## 5. Direction B — Strip down to a single vendor (the opposite)

**Answer: Very achievable, and the result is *cleaner* than the multi-vendor system** — because the entire detection cascade collapses.

**Vendor-agnostic CORE — survives unchanged for 1 vendor:** `base.py` provisioning engine, `port_manager` VLAN/port lifecycle + link detection + 3-min grace, `firmware.py` version-compare + convention scan, `config_store` deep-merge, web UI/websocket/port-cards, credential plumbing, the one handler + its firmware source + templates.

**Multi-vendor SCAFFOLDING — deletable/collapsible:**
- **`fingerprint.py` is ~80% dead weight with one vendor.** Any device on the port *is* that vendor — delete the probe cascade (MikroTik :8728 special-case, `_probe_tachyon_api`, `_probe_wave_api`, SSH-banner, SNMP) and all other `HTTP_SIGNATURES`. `DeviceType` collapses to `{THE_VENDOR, UNKNOWN}`. **Biggest single simplification.**
- `handler_manager`/`HANDLER_MAP` → "always return TheHandler."
- `DeviceLinkLocalIP.ALL`, `cli` choices, `VALID_DEVICE_TYPES`, `index.html` vendor map → one entry each.
- Evolution Digital passive path, and (unless the chosen vendor *is* MikroTik) netinstall/ZTP/BOOTP/OUI machinery → deletable.

**Caveat:** because there's no plugin registry, "reduce to one" is the same manual carving across the same 6–8 enumeration sites. The core engine is genuinely vendor-neutral; the cost is concentrated in `fingerprint.py` and the duplicated enumerations.

---

## 6. Overall verdict

| Dimension | Grade | Why |
|---|---|---|
| **Behavioral isolation** (logic) | **A** | Handlers fully self-contained; property-driven flow; no inter-handler deps. |
| **Registration isolation** (enumeration) | **C** | Vendor list duplicated 6–8×; no single source of truth. |
| **Pluggability** | **D** | No self-registration; add and remove are manual multi-file edits. |
| **Can Tachyon come out cleanly?** | **Yes** | ~12–14 files, mechanical; no behavioral coupling; grep is the safety net. |
| **Can it reduce to one vendor?** | **Yes, and cleaner** | Core is vendor-neutral; the `fingerprint.py` cascade collapses. |

**Remediation:** see `docs/epic-vendor-isolation-refactor.md`. Phase 1 (consolidate the enumeration registries, fix the `base.py` leak) eliminates both S1 crash-couplings and ~90% of the modularity gap with no behavioral risk.

---

## 7. Verification (confirm these claims yourself)

```bash
# Every vendor-name reference outside handlers/ (the leak surface):
grep -rniE 'tachyon|cambium|mikrotik|tarana|ubiquiti|evolution' provisioner \
  --include='*.py' | grep -v 'provisioner/handlers/' | grep -v 'firmware_sources/'

# Confirm the duplicated vendor registries:
grep -rn 'HANDLER_MAP\|VALID_DEVICE_TYPES\|BUILTIN_CREDENTIALS\|DeviceType\.' provisioner | head -40

# Confirm no handler imports another handler (behavioral isolation):
grep -rn 'from .handlers' provisioner/handlers/*.py    # expect only base/__init__

# Tests still green:
python -m pytest tests/ -q
```
