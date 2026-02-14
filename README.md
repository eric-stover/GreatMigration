# GreatMigration

GreatMigration is a network automation toolkit designed to accelerate moves to Juniper Mist. The project grew from the Mist Switch Configuration Converter but now delivers a cohesive web application that helps engineers normalize legacy device data, validate Mist deployments, and remediate issues with a single click.

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

GreatMigration ships with a responsive FastAPI + HTMX interface backed by a Mist-aware automation engine. All features honour Mist RBAC by granting “push” capabilities only to users in `PUSH_GROUP_DN` (or local users flagged via `LOCAL_PUSH_USERS`). Read-only users can still explore reports, download data, and stage conversion payloads.

### Hardware conversion

* Collect Cisco hardware details either by uploading `show tech-support` bundles **or** by letting the app log in over SSH.
* Receive Juniper (or custom) replacement suggestions based on curated mappings.
* Export a PDF summary for procurement or change records.

**How to use**

1. Navigate to **Hardware Conversion** in the web UI.
2. Choose one of the collection methods:
   * **Upload bundle** – drag-and-drop a `show tech-support` archive (or browse to select one).
   * **SSH collect** – provide the device IP/hostname plus credentials and start a job; the worker logs in and executes
     `show inventory`, `show interface status`, `show interfaces`, and `show running-config`, then persists the raw text for auditing.
3. Review the parsed chassis, line cards, and optics that appear in the results grid.
4. Adjust suggested replacements if needed, then download the PDF report or CSV export for planning.

**How it works**

* Uploads and SSH jobs both flow through `translate_showtech.parse_showtech`, which normalizes Cisco hardware tables and drives
  the recommendation engine (`translate_showtech.load_mapping`, `find_copper_10g_ports`).
* SSH collection is orchestrated by `backend/ssh_collect.py`: a thread pool launches Netmiko sessions per device, runs the
  command set above, captures stdout to disk, and synthesizes a `show tech` bundle so the same parser can be reused.
* Replacement suggestions are computed from `backend/device_map.sample.json` (or your customized `device_map.json`) and surfaced
  alongside interface counts so you can spot copper-to-fiber mismatches before ordering hardware.

### Port profile rules

* Maintain reusable mappings between detected Cisco interface traits and Mist port profiles.
* Build rules with multiple conditions (mode, description regex, VLANs, etc.) using a drag-and-drop priority list.
* Persist rule sets in `backend/port_rules.json` so they can be version-controlled or shared.

**How to use**

1. Open **Rules → Port Profiles** to see the existing rule stack.
2. Click **Add rule** to describe the Cisco traits (mode, access VLAN, voice VLAN, native VLAN, description regex, etc.).
3. Choose the Mist port usage that should be applied when a port matches the conditions.
4. Reorder rules to set priority—first match wins during conversions.
5. Use **Export JSON** to capture the current rule file or **Import JSON** to load a curated set into `backend/port_rules.json`.

**How it works**

* Rules are stored in JSON and validated/loaded through `push_mist_port_config.load_rules` so malformed entries are rejected early.
* During conversions the backend evaluates interfaces against each rule (`evaluate_rule`) using traits such as mode, access/voice
  VLANs, native VLAN, allowed VLAN membership, and description/name regex matches; the first rule that returns `True` supplies
  the target `usage`.
* The matched usage is injected into the generated Mist `port_config` payloads before staging or pushing so rule tweaks immediately
  impact both dry runs and live updates.

### Config conversion

* Translate legacy switch configs into Mist-ready JSON payloads.
* Batch map converted payloads to Mist sites and devices, tweak chassis member offsets, exclude uplinks, and override device models.
* Stage configurations or push live updates using the Site Deployment Automation controls; push options require push rights.

**How to use**

1. Visit **Config Conversion** and upload one or more Cisco configuration files (raw CLI or archive).
2. Inspect the parsed inventory and optionally adjust offsets/exclusions so the converted members align with target hardware.
3. Select the destination Mist org/site/device for each row. The UI displays the generated Mist payload preview.
4. Use the **Site Deployment Automation** section:
   * Choose **Stage/Test** to download the Mist payload or perform a dry run without changing devices.
   * Choose **Push changes** to send the converted configuration to Mist (requires push permissions).
5. Download the JSON or CSV exports for documentation or manual review at any stage.

**How it works**

* File uploads flow through `convertciscotojson.convert_one_file`, which relies on `CiscoConfParse` to model every interface, infer
  EX4100 member types, and translate Cisco naming into Mist FPC/port identifiers while preserving VLAN, PoE, QoS, and description
  details.
* Batch pushes reuse `_build_payload_for_row` inside `backend/app.py` to merge the converted `port_config` with Mist site/device
  selections, apply rule-driven port usages, enforce capacity checks (`validate_port_config_against_model`), and PUT the results to
  `/sites/{site_id}/devices/{device_id}`.
* Lifecycle Management (LCM) automation lets Step 3 target a site and device list to remove the temporary Cisco layout, preserving
  legacy VLANs while regenerating port assignments from live switch data for the final Juniper configuration.

### Compliance audit & 1 Click Fix

* Audit one or more Mist sites for required variables, device naming conventions, template adherence, documentation completeness, and configuration overrides.
* Drill into site cards to see affected devices, override diffs, and remediation suggestions.
* Take advantage of the following built-in 1 Click Fix actions (visible to push-enabled users):
  * **Access point naming:** rename Mist APs to match the required pattern using LLDP neighbour data. Buttons appear per device so you can remediate selectively.
  * **Switch static DNS cleanup:** remove statically configured management DNS servers from `ip_config` while respecting lab vs. production template assignments. Pre-checks verify the expected template and DNS site variables; buttons stay disabled and display guidance until prerequisites are met.
* UI status badges show live Mist API feedback next to each button so operators immediately see success, skipped states, or pre-check failures.

**How to use**

1. Open **Compliance Audit** and pick the Mist org and sites you want to evaluate.
2. Click **Run audit** to fetch live Mist data and generate the compliance report.
3. Expand each site card to review checks, affected devices, and recommended fixes.
4. For push-enabled users, click the appropriate **1 Click Fix** buttons (e.g., AP rename, DNS cleanup). Each button re-validates prerequisites before issuing Mist API calls.
5. Download the audit summary or device-level CSV exports for change records or further analysis.

**How it works**

* The audit engine (`backend/compliance.py`) hydrates a `SiteContext` with data from Mist site, derived setting, template, and device
  APIs, then runs a library of `ComplianceCheck` subclasses to flag naming violations, missing variables, override drift, and
  documentation gaps.
* Devices are filtered to those seen online recently (default: last seen within 14 days) before checks run, so stale/offline
  devices do not clutter the audit results.
* Findings are serialized through `audit_history` so the UI can show site/device counts and let you export CSV snapshots for change
  control.
* 1 Click Fix actions map to helpers in `audit_fixes.py`/`audit_actions.py`; each button re-checks prerequisites, stages a dry run
  when requested, and otherwise issues Mist REST calls (e.g., rename APs, clear DNS overrides) while streaming per-device status
  back to the browser.

---

## Hamburger menu guide

The hamburger menu (☰) is the primary navigation control across the app. It appears in the top-left of every main page (`/`, `/hardware`, `/replacements`, `/rules`, `/standards`, `/audit`) and opens a slide-out panel with all workflow links plus Help and Log out.

### How the menu behaves

* **Open/close interaction**
  * Click the ☰ button to open the left drawer.
  * Click ☰ again to close it.
  * Click anywhere outside the drawer to close it.
* **Layout behavior**
  * When open, the page content shifts right (`ml-64`) so the drawer does not cover working controls.
  * The drawer is fixed-position and keeps the same width/site-wide styling across pages.
* **Cross-page consistency**
  * The same menu structure is rendered on login + all feature pages, so users can jump directly between workflows without “back” navigation.

### User/session behavior in the menu

* **Greeting + role hint**
  * After page load, the UI calls `/me` and shows `Hey <username>!` in the menu.
  * Read-only users are labeled `Hey <username>! (read-only)` on pages that enforce push restrictions.
* **Log out visibility**
  * The **Log out** button is hidden until a valid session is detected.
  * Clicking **Log out** sends the user to `/logout` and clears the session cookie.
* **Access model reminder**
  * Menu visibility is broad, but action rights are enforced inside each workflow:
    * Read-only users can navigate, inspect data, and run non-destructive operations.
    * Push/fix operations require `can_push` rights (`PUSH_GROUP_DN` or `LOCAL_PUSH_USERS`).

### Menu items and what each one does

1. **Hardware Conversion** (`/hardware`)
   * Purpose: identify Juniper replacement hardware for existing Cisco inventory.
   * Typical flow:
     1. Upload a `show tech-support` file or run SSH hardware collection.
     2. Review detected chassis/cards/optics and suggested replacements.
     3. Export results for planning/procurement.

2. **Hardware Replacement Rules** (`/replacements`)
   * Purpose: maintain the Cisco→Juniper replacement mapping table used by Hardware Conversion.
   * Typical flow:
     1. Review existing mappings.
     2. Add/edit/remove model mappings.
     3. Save and re-run Hardware Conversion to apply updated rules.

3. **Config Conversion** (`/`)
   * Purpose: convert Cisco running configs into Mist-ready payloads and run deployment automation.
   * Typical flow:
     1. Fetch configs via SSH or upload files.
     2. Validate parsed output, mappings, and device/site assignments.
     3. Run stage/test or push workflows depending on permissions.

4. **Port Profile Rules** (`/rules`)
   * Purpose: define conditional logic that maps Cisco interface traits to Mist port profiles/usages.
   * Typical flow:
     1. Create rule conditions (mode, VLANs, regex, etc.).
     2. Prioritize rules (first match wins).
     3. Save/export/import `port_rules.json` sets and reuse during conversions.

5. **Standards** (`/standards`)
   * Purpose: view the firmware standards matrix by model/device type and recent revisions.
   * Typical flow:
     1. Open Standards to load the live standards table.
     2. Filter by model, device type, or version.
     3. Use this reference while planning conversions and compliance remediation.

6. **Compliance Audit** (`/audit`)
   * Purpose: run site checks for naming, variable/template drift, and related policy issues.
   * Typical flow:
     1. Select target scope/site.
     2. Run the audit and review findings.
     3. Export reports and (if authorized) use 1 Click Fix actions.

7. **Help** (`HELP_URL`)
   * Purpose: open your internal runbook/documentation in a new browser tab.
   * Setup:
     * Set `HELP_URL` in `backend/.env`.
     * If unset, the app falls back to the project README link.

### Recommended operator workflow using the menu

1. Start in **Standards** to confirm target software baselines.
2. Use **Hardware Replacement Rules** to confirm device mappings.
3. Run **Hardware Conversion** and **Config Conversion** to stage outputs.
4. Apply/verify **Port Profile Rules** before final push operations.
5. Finish with **Compliance Audit** and only then apply fix/push actions.

This sequence keeps the migration path deterministic: standards first, mapping second, conversion third, compliance and enforcement last.

---

## Getting started

### Prerequisites

* Git
* Python 3.9+ with `python3-venv` (Linux/macOS) or the Windows Store/official installer
* Mist API token with read access (for lookups) and write access (optional, required for pushes and 1 Click Fix actions)
* Optional: PowerShell 5.1+ or PowerShell 7.x if you prefer the Windows script

### Quick start scripts

Two scripts provide identical setup behaviour so teams can use whichever platform is most convenient.

#### Python (cross-platform)

```bash
git clone -b main https://github.com/ejstover/GreatMigration.git ./GreatMigration
cd ./GreatMigration
python3 quickstart.py
```

* Updates or clones the repository, builds `.venv`, installs backend dependencies, prompts for Mist credentials, creates `backend/.env`, ensures `backend/port_rules.json`, and starts `uvicorn`.
* Re-run later with `python3 quickstart.py` to reuse cached settings.
* Supply `--repo`, `--dir`, and `--branch` to bootstrap alternative locations; `--port` overrides the API port; `--no-start` performs setup without launching the API.

#### PowerShell (Windows-friendly)

```powershell
# From a PowerShell prompt
Set-ExecutionPolicy -Scope Process RemoteSigned
./quickstart.ps1 -RepoUrl https://github.com/ejstover/GreatMigration.git -TargetDir C:\GreatMigration
```

* Mirrors the Python script: syncs the git repo, provisions `.venv`, installs requirements (bootstrapping `pip` if necessary), builds `backend/.env`, ensures `backend/port_rules.json`, and starts the API.
* Supports `-Branch`, `-Port`, and `-NoStart` switches for parity with `quickstart.py`.

Both scripts read and reuse values in `backend/.env`, so follow-up runs only prompt when settings are missing.

### Manual setup

1. **Clone and prepare the project**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   python3 -m venv .venv
   source .venv/bin/activate  # .\.venv\Scripts\activate on Windows
   pip install -r backend/requirements.txt
   ```
2. **Configure the backend**
   * Copy `.env.sample` to `backend/.env` and populate:
     * `MIST_TOKEN`
     * `SESSION_SECRET`
     * `SESSION_HTTPS_ONLY` (recommended `true`; set to `false` only for local HTTP testing)
     * `AUTH_METHOD` (`local` or `ldap`)
     * For local auth: `LOCAL_USERS` and optional `LOCAL_PUSH_USERS`
     * For LDAP auth: `LDAP_SERVER_URL`, `LDAP_SEARCH_BASE`/`LDAP_SEARCH_BASES`, `LDAP_BIND_TEMPLATE`, `LDAP_SERVICE_DN`, `LDAP_SERVICE_PASSWORD`, plus `PUSH_GROUP_DN` and optional `READONLY_GROUP_DN`
     * Optional defaults: `MIST_BASE_URL`, `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, `API_PORT`, `HELP_URL`
     * Compliance tuning: `SWITCH_NAME_REGEX_PATTERN`, `AP_NAME_REGEX_PATTERN`, `MIST_SITE_VARIABLES`, `SW_NUM_IMG`, `AP_NUM_IMG`
     * Device catalog sources: `NETBOX_DT_URL`, `NETBOX_LOCAL_DT`
     * Logging: `SYSLOG_HOST`, `SYSLOG_PORT`
3. **Optional assets** – copy `backend/port_rules.sample.json` to `backend/port_rules.json` to maintain custom mappings outside version control.
4. **Launch the API**
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --app-dir backend --reload
   ```

---

### First-run checklist

1. Open a browser to `http://localhost:8000` (or the port you configured).
2. Log in with a local account (`AUTH_METHOD=local`) or your LDAP account (`AUTH_METHOD=ldap`).
3. Use the hamburger menu to pick your workflow (Hardware Conversion, Config Conversion, etc.).
4. Start with a non-destructive “Stage/Test” or “Run audit” step before enabling push actions.

---

## Extras: LDAP, syslog, and logging

* **LDAP integration (optional)** – set `AUTH_METHOD=ldap` and supply your server + group DNs in `backend/.env`. Users in `PUSH_GROUP_DN` can push changes; users in `READONLY_GROUP_DN` can still view reports without modifying Mist.
* **Syslog export (optional)** – set `SYSLOG_HOST` and `SYSLOG_PORT` to forward user action logs to your syslog collector. If syslog is unreachable, file logging still continues locally.
* **Local logging (default)** – user actions are written to daily log files in `backend/logs/` (one file per day) so you have an audit trail even without syslog.

---

## Backend Python components

Think of the backend as a set of small “helpers” that each do one job:

* `backend/app.py` – the FastAPI web server. It serves the UI, handles uploads, calls the conversion tools, and talks to Mist.
* `backend/convertciscotojson.py` – reads Cisco configs and turns them into Mist-friendly JSON.
* `backend/push_mist_port_config.py` – validates, builds, and pushes port configuration payloads to Mist.
* `backend/translate_showtech.py` – parses `show tech-support` files to extract hardware and interface details.
* `backend/ssh_collect.py` – logs into switches over SSH and collects the raw Cisco outputs the app needs.
* `backend/compliance.py` – runs the compliance checks for naming, templates, variables, and documentation.
* `backend/audit_actions.py` – defines which “1 Click Fix” buttons exist and how they are identified.
* `backend/audit_fixes.py` – performs the actual fix actions (like renaming APs or cleaning DNS overrides).
* `backend/audit_history.py` – saves and loads audit runs so the UI can show summaries and exports.
* `backend/auth_local.py` – handles username/password login when you use local accounts.
* `backend/auth_ldap.py` – handles LDAP login and group lookups.
* `backend/logging_utils.py` – writes user action logs to files and (optionally) syslog.

---

## Configuration reference

* **Authentication & authorization**
  * `AUTH_METHOD=local` uses users listed in `LOCAL_USERS` (`username:password`). Use strong, unique passwords and avoid defaults. Include comma-separated pairs and flag push-enabled accounts in `LOCAL_PUSH_USERS`.
  * `SESSION_HTTPS_ONLY` defaults to `true` and should stay enabled in production so session cookies are not sent over plain HTTP.
  * `AUTH_METHOD=ldap` supports read-only (`READONLY_GROUP_DN`) and push-enabled (`PUSH_GROUP_DN`) directory groups. Multiple values can be separated by semicolons or newlines.
* **Mist connectivity**
  * `MIST_BASE_URL` defaults to `https://api.ac2.mist.com`. Change it if your org lives in another Mist region.
  * `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, and `API_PORT` can be pre-filled to streamline onboarding.
* **Compliance checks**
  * Override naming patterns via `SWITCH_NAME_REGEX_PATTERN` / `AP_NAME_REGEX_PATTERN`.
  * Adjust required site variables with `MIST_SITE_VARIABLES`. Use `key=value` entries (for example, `hubDNSserver1=10.0.0.53`) to supply environment defaults that the 1 Click Fix action can apply automatically when a site is missing values.
  * Enforce device documentation photo counts with `SW_NUM_IMG` and `AP_NUM_IMG`.
  * Firmware standards for compliance are read from `backend/standard_fw_versions.json`. The app pulls suggested switch/AP versions from Mist on first run (or whenever the file has no stored versions), then refreshes every 90 days when `MIST_TOKEN` and `MIST_ORG_ID` are configured.
* **1 Click Fix safeguards**
  * AP rename actions derive new names from switch LLDP neighbours. Sites lacking neighbour data will surface actionable warnings but skip changes.
  * Switch DNS cleanup actions verify the applied template (`Prod - Standard Template` for production sites, `Lab` template for lab sites) and the presence of `siteDNSserver`, `hubDNSserver1`, and `hubDNSserver2`. Buttons remain disabled until both checks pass and are annotated with details describing any failures.

---

## Firewall requirements

Allow the following flows if your environment restricts outbound traffic:

| Direction | Protocol/Port | Destination | Purpose |
|-----------|---------------|-------------|---------|
| Inbound   | TCP `API_PORT` (8000 by default) | Admin workstations | Reach the GreatMigration web UI. Adjust if `API_PORT` is changed. |
| Outbound  | TCP 443 | `api.ac2.mist.com` (or your regional Mist API host) | Fetch inventory, perform 1 Click Fix actions, push configurations. |
| Outbound  | TCP 443 | `api.github.com` (and any custom `NETBOX_DT_URL`) | Download device type metadata referenced during conversions. |
| Outbound  | TCP 22  | Managed switches | Allow the automation engine to initiate SSH sessions when executing configuration pushes or validation steps. |
| Outbound† | TCP 389 / 636 | LDAP / Active Directory servers | Needed only when `AUTH_METHOD=ldap`. |

†Use the secure port declared in `LDAP_SERVER_URL` (e.g., 636 for LDAPS).

---

## Operational tips

* **Role-based controls** – buttons that modify Mist (push, 1 Click Fix) only appear for users in the push group. Read-only users can still download reports and review findings.
* **Dry runs first** – compliance actions report their intended changes before applying them, and the Site Deployment automation flow offers a dedicated Stage/Test option for safe validation.
* **Troubleshooting** – review `backend/logs/app.log` (when syslog forwarding is not configured) and inspect Mist audit logs for confirmation of pushed changes.
* **Staying current** – re-run either quick start script periodically; both update the git checkout, dependencies, and `.env` defaults while preserving custom settings.

Enjoy building faster Juniper Mist migrations!
