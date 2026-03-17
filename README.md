# GreatMigration

GreatMigration is a network automation toolkit designed to accelerate migrations to Juniper Mist.
It started as a switch conversion utility and now provides a full web application for:

- Discovering legacy Cisco hardware and recommending replacements.
- Converting Cisco switch configurations into Mist-compatible payloads.
- Applying standardized port profile rules at scale.
- Auditing Mist sites for compliance drift.
- Performing controlled, role-gated remediation actions.

If you are a network engineer using this for the first time, the most important thing to know is:
**GreatMigration is built around staged validation first, and automated changes second.**
Most workflows support non-destructive review before any push action is available.

---

## Table of contents
- [Feature overview](#feature-overview)
  - [Hardware conversion](#hardware-conversion)
  - [Port profile rules](#port-profile-rules)
  - [Config conversion](#config-conversion)
  - [Compliance audit & 1 Click Fix](#compliance-audit--1-click-fix)
- [Hamburger menu guide](#hamburger-menu-guide)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quick start scripts](#quick-start-scripts)
  - [Manual setup](#manual-setup)
- [Extras: LDAP, syslog, and logging](#extras-ldap-syslog-and-logging)
- [Backend Python components](#backend-python-components-eli15)
- [Configuration reference](#configuration-reference)
- [Firewall requirements](#firewall-requirements)
- [Operational tips](#operational-tips)

---

## Feature overview

GreatMigration runs as a FastAPI web app with HTMX/Tailwind UI pages. Every operation is permission-aware:

- **Read-only users** can inspect data, run audits, and export results.
- **Push-enabled users** can execute change actions (Mist updates, 1 Click Fix, and push workflows).

Push rights are controlled through `PUSH_GROUP_DN` (LDAP mode) or `LOCAL_PUSH_USERS` (local auth mode).

### Hardware conversion

The Hardware Conversion workflow helps you answer: **“What Juniper hardware should replace this Cisco estate?”**

**What it does**

- Accepts Cisco `show tech-support` uploads.
- Or collects data over SSH directly from devices.
- Parses chassis, module, optics, and interface detail.
- Applies replacement mapping rules to suggest target Juniper models.
- Exports results as PDF/CSV for procurement and change documentation.

**How to use**

1. Open **Hardware Conversion**.
2. Choose input method:
   - **Upload bundle** for existing `show tech-support` files.
   - **SSH collect** to fetch inventory directly from switches.
3. Review parsed inventory and replacement suggestions.
4. Adjust mappings if needed (or update them in **Hardware Replacement Rules**).
5. Export reports for CAB/procurement review.

**How it works**

- Parsing and normalization are handled by `translate_showtech.parse_showtech`.
- Mapping is loaded through `translate_showtech.load_mapping` from `device_map.json` (or sample defaults).
- SSH collection is orchestrated by `backend/ssh_collect.py`, which runs command collection jobs and stores raw outputs for traceability.
- The same parser is used for upload and SSH sources, keeping results consistent regardless of intake method.

**Safety notes**

- Hardware conversion is an **analysis workflow** and does not push configuration to Mist.
- You can run this safely before any migration window.

### Port profile rules

Port Profile Rules provide deterministic logic for assigning Mist port usages from Cisco interface characteristics.

**What it does**

- Lets you define rule conditions such as mode, VLAN fields, PoE active status, and description regex.
- Uses ordered evaluation (first match wins).
- Stores rules in JSON for version control and reuse.
- Applies rules automatically during conversion and push preview.

**How to use**

1. Open **Rules → Port Profiles**.
2. Create or edit conditions (access/voice/native VLAN, trunk membership, description patterns).
3. Set the target Mist `usage` value.
4. Reorder rules to enforce priority.
5. Export/import JSON to standardize policy across teams.

**How it works**

- Rule files are validated via `push_mist_port_config.load_rules`.
- Interface matching uses `evaluate_rule` logic in conversion/push flows.
- The selected usage is injected into generated Mist `port_config` payloads.

**Safety notes**

- Rule updates do not change devices by themselves.
- You can validate rule effects through stage/test workflows before any live push.

### Config conversion

Config Conversion is the core migration path from Cisco CLI to Mist API payloads.

**What it does**

- Parses Cisco configs and builds Mist-ready `port_config` structures.
- Supports batch row-to-site/device mapping.
- Supports stack/chassis member remapping and uplink exclusion.
- Supports Stage/Test (preview) and Push (live Mist update).
- Includes lifecycle-oriented automation to move from temporary legacy layout toward final Juniper port state.

**How to use**

1. Open **Config Conversion**.
2. Upload one or more Cisco config files (or collect files over SSH).
3. Validate interface interpretation and member mapping.
4. Assign Mist org/site/device targets for each row.
5. Run **Stage/Test** first and review outputs.
6. Run **Push changes** only after review and approval.

**How it works**

- Parsing is performed by `convertciscotojson.convert_one_file` with CiscoConfParse.
- Payload construction merges conversion output, rule-driven usages, and selected Mist targets.
- Capacity/model guardrails are enforced via validation helpers in `push_mist_port_config.py`.
- Mist updates are executed through site/device API calls only when push workflows are explicitly triggered.

**Safety notes**

- Stage/Test is intended for pre-change validation and should be your default first step.
- Push controls are hidden/blocked for read-only users.
- Conversion output can be exported and peer-reviewed before any production change.

### Compliance audit & 1 Click Fix

Compliance Audit checks deployed Mist state against your operational standards.

**What it audits**

- Naming compliance (switches/APs).
- Required site variables.
- Template alignment and drift.
- Override cleanliness (including static DNS override cases).
- Device documentation/image coverage thresholds.

**Built-in 1 Click Fix actions**

- **AP naming remediation** based on LLDP neighbor context.
- **Switch static DNS cleanup** when template and variable prerequisites are met.

**How to use**

1. Open **Compliance Audit**.
2. Select org/site scope.
3. Run audit and inspect site cards/check summaries.
4. Export CSV summaries for records.
5. If authorized, run specific 1 Click Fix actions and monitor per-device status feedback.

**How it works**

- `compliance.py` builds site context from Mist API data and runs checks.
- `audit_history.py` stores run history for review/export.
- `audit_actions.py` defines available actions.
- `audit_fixes.py` executes each action with prerequisite checks and API operations.

**Safety notes**

- Audit runs are read-only.
- 1 Click Fix actions are explicit, per-action operations and remain permission-gated.
- Preconditions are checked before actions are enabled or executed.

---

## Hamburger menu guide

The hamburger menu (☰) is the main navigation pattern across pages (`/`, `/hardware`, `/replacements`, `/rules`, `/standards`, `/audit`).

### How the menu behaves

- Click ☰ to open/close.
- Click outside the drawer to close.
- Page content shifts when open so controls remain visible.
- Menu structure is consistent across feature pages.

### User/session behavior in the menu

- The UI calls `/me` and displays the current username.
- Read-only users are labeled as read-only where relevant.
- Log out is shown for active sessions and clears session state via `/logout`.
- Navigation visibility is broad, but mutating actions remain role-restricted.

### Menu items and what each one does

1. **Hardware Conversion** (`/hardware`)
   - Parse inventory and generate replacement recommendations.
2. **Hardware Replacement Rules** (`/replacements`)
   - Maintain Cisco→Juniper model mapping used by hardware conversion.
3. **Config Conversion** (`/`)
   - Convert configs and run stage/test/push workflows.
4. **Port Profile Rules** (`/rules`)
   - Define and prioritize interface-to-usage mapping logic.
5. **Standards** (`/standards`)
   - Review firmware standards by model/type and revision recency.
6. **Compliance Audit** (`/audit`)
   - Run compliance checks and optional 1 Click Fix remediations.
7. **Help** (`HELP_URL`)
   - Open your internal runbook/documentation target.

### Recommended operator workflow using the menu

1. **Standards**: verify software baseline expectations.
2. **Hardware Replacement Rules**: confirm model mapping policy.
3. **Hardware Conversion**: size migration hardware.
4. **Port Profile Rules**: validate interface policy translation.
5. **Config Conversion**: run stage/test and review payloads.
6. **Compliance Audit**: run post-stage checks, then apply fixes if needed.

This sequence minimizes risk by moving from policy/reference -> conversion planning -> controlled execution.

---

## Getting started

### Prerequisites

- Git
- Python 3.9+ (`python3-venv` on Linux/macOS)
- Mist API token (read for discovery; write for push/fix workflows)
- Optional: PowerShell 5.1+ / 7.x for Windows quickstart

### Quick start scripts

GreatMigration includes both Python and PowerShell bootstrap scripts.

#### Python (cross-platform)

```bash
git clone -b main https://github.com/ejstover/GreatMigration.git ./GreatMigration
cd ./GreatMigration
python3 quickstart.py
```

What it does:

- Clones/updates repo.
- Builds `.venv` and installs backend dependencies.
- Prompts for key settings and writes `backend/.env`.
- Ensures `backend/port_rules.json` exists.
- Starts `uvicorn` unless `--no-start` is set.

Useful options:

- `--repo`, `--dir`, `--branch`
- `--port`
- `--no-start`

#### PowerShell (Windows-friendly)

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
./quickstart.ps1 -RepoUrl https://github.com/ejstover/GreatMigration.git -TargetDir C:\GreatMigration
```

What it does:

- Mirrors Python quickstart behavior for Windows environments.
- Includes pip/bootstrap handling where needed.
- Supports `-Branch`, `-Port`, and `-NoStart` switches.

Both scripts reuse previously saved `.env` values so repeat runs are fast and predictable.

### Manual setup

1. **Clone + install dependencies**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   python3 -m venv .venv
   source .venv/bin/activate  # Windows: .\.venv\Scripts\activate
   pip install -r backend/requirements.txt
   ```

2. **Create `backend/.env`**
   Required core values:
   - `MIST_TOKEN`
   - `SESSION_SECRET`
   - `AUTH_METHOD=local` or `AUTH_METHOD=ldap`

   Common optional values:
   - `MIST_BASE_URL`, `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, `API_PORT`, `HELP_URL`
   - `SESSION_HTTPS_ONLY=true` (recommended for production)

   Local auth settings:
   - `LOCAL_USERS`
   - `LOCAL_PUSH_USERS` (optional)

   LDAP settings:
   - `LDAP_SERVER_URL`
   - `LDAP_SEARCH_BASE` or `LDAP_SEARCH_BASES`
   - `LDAP_BIND_TEMPLATE` or service bind settings
   - `PUSH_GROUP_DN`, optional `READONLY_GROUP_DN`

3. **Optional policy/config files**
   - Copy `backend/port_rules.sample.json` to `backend/port_rules.json`.
   - Copy `backend/device_map.sample.json` to `backend/device_map.json` for custom hardware mappings.
   - Copy `backend/replacement_rules.sample.json` to `backend/replacement_rules.json` if using customized replacement logic.

4. **Run the app**
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --app-dir backend --reload
   ```

### First-run checklist

1. Open `http://localhost:8000`.
2. Confirm authentication works with your chosen auth method.
3. Validate read-only user behavior first.
4. Run non-destructive workflows (hardware parse, stage/test, compliance audit).
5. Execute push/fix operations only after review and approval.

---

## Extras: LDAP, syslog, and logging

- **LDAP auth (optional)**
  - Set `AUTH_METHOD=ldap` and directory settings.
  - Group-based role control separates read-only and push users.

- **Syslog forwarding (optional)**
  - Set `SYSLOG_HOST` and `SYSLOG_PORT`.
  - If syslog is unavailable, local logging continues.

- **Local audit logging (default)**
  - Action logs are written under `backend/logs/` for operational traceability.

---

## Backend Python components

- `backend/app.py`: FastAPI server, endpoints, session/auth checks, and orchestration.
- `backend/convertciscotojson.py`: Cisco config parser and Mist payload builder.
- `backend/push_mist_port_config.py`: Rule evaluation, payload validation, and push helpers.
- `backend/translate_showtech.py`: Show-tech parsing and hardware mapping helpers.
- `backend/ssh_collect.py`: Multi-device SSH intake pipeline.
- `backend/compliance.py`: Compliance check framework and site-level runners.
- `backend/audit_actions.py`: Catalog of available remediation actions.
- `backend/audit_fixes.py`: Execution logic for remediation actions.
- `backend/audit_history.py`: Persistence and retrieval for audit history.
- `backend/auth_local.py`: Local auth logic.
- `backend/auth_ldap.py`: LDAP auth and group resolution.
- `backend/logging_utils.py`: File/syslog user action logging.

---

## Configuration reference

### Authentication and roles

- `AUTH_METHOD=local` uses `LOCAL_USERS` (`username:password` list).
- `AUTH_METHOD=ldap` uses LDAP bind/search plus group DNs.
- Push rights come from `PUSH_GROUP_DN` (LDAP) or `LOCAL_PUSH_USERS` (local).
- `SESSION_HTTPS_ONLY=true` is strongly recommended in production.

### Mist connectivity

- `MIST_BASE_URL` defaults to the AC2 Mist API domain.
- `MIST_TOKEN` is required for Mist API access.
- `MIST_ORG_ID` can be preset for faster operator workflows.

### Compliance policy tuning

- Naming patterns: `SWITCH_NAME_REGEX_PATTERN`, `AP_NAME_REGEX_PATTERN`.
- Required variables: `MIST_SITE_VARIABLES` (`key=value` entries).
- Documentation minimums: `SW_NUM_IMG`, `AP_NUM_IMG`.
- Standards cache/source behavior uses `backend/standard_fw_versions.json` with periodic refresh.

### VLAN/reserved behavior for conversion safety

- `LEGACY_VLANS` identifies VLANs preserved in legacy/staged workflows.
- `EXCLUDE_VLANS` omits specific VLANs from generated outputs.
- `RESERVED_VLANS` protects reserved IDs with explicit naming (format `id:name`).

### 1 Click Fix safeguards

- AP rename actions depend on LLDP-derived context and skip when required data is missing.
- DNS cleanup actions validate template and site-variable prerequisites before enabling execution.

---

## Firewall requirements

Allow these flows in controlled environments:

| Direction | Protocol/Port | Destination | Purpose |
|-----------|---------------|-------------|---------|
| Inbound   | TCP `API_PORT` (default 8000) | Admin/operator workstations | Access the web UI. |
| Outbound  | TCP 443 | Mist API endpoint (`api.ac2.mist.com` or regional host) | Read inventory, run audits/fixes, and perform pushes. |
| Outbound  | TCP 443 | `api.github.com` and optional `NETBOX_DT_URL` | Pull device type metadata used in conversion workflows. |
| Outbound  | TCP 22 | Managed switches | SSH collection and SSH-driven network workflows. |
| Outbound* | TCP 389/636 | LDAP/AD servers | Required only when using LDAP auth. |

*Use LDAPS (`636`) whenever possible.

---

## Operational tips

- **Start read-only**: validate inventory, rules, and audits before allowing push access.
- **Use stage/test first**: treat push as a final approved step, not the first step.
- **Keep policy files version-controlled**: `port_rules.json`, `device_map.json`, and related mappings.
- **Review logs after every change window**: local logs and Mist audit logs should agree.
- **Re-run quickstart periodically**: this updates dependencies and keeps local setup aligned.

GreatMigration is designed to reduce migration risk by making change intent visible, reviewable, and role-controlled.
