#!/usr/bin/env python3
"""
Quick start for the Switch Port Config tool.

Features
- Clone (or update) a git repo
- Create a Python virtual environment at ./.venv
- Install dependencies (from backend/requirements.txt if present, else sensible defaults)
- Ensure backend/.env (prompts on first run for Mist token, auth settings, and API port)
- Start FastAPI via uvicorn

Usage examples
-------------
# First time (clone & run)
python scripts/quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir "C:/work/GreatMigration" --branch main

# Subsequent runs (already cloned)
python scripts/quickstart.py --dir "C:/work/GreatMigration"

# Override port
python scripts/quickstart.py --dir . --port 9000

# Setup only (no server)
python scripts/quickstart.py --dir . --no-start
"""
from __future__ import annotations

import argparse
import os
import sys
import subprocess
import json
from pathlib import Path
import shutil
from typing import Dict
from getpass import getpass

# ---------- Utilities ----------

def run(cmd, cwd: Path | None = None, env: Dict[str, str] | None = None, check: bool = True):
    print(f"\n> {' '.join(cmd)}" + (f"   (cwd={cwd})" if cwd else ""))
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env)
    if check and proc.returncode != 0:
        raise SystemExit(f"Command failed with exit code {proc.returncode}: {' '.join(cmd)}")
    return proc.returncode

def which_or_die(name: str):
    if shutil.which(name) is None:
        raise SystemExit(f"Required tool '{name}' not found on PATH.")
    return name

def venv_python_path(venv_dir: Path) -> Path:
    # Windows: .venv/Scripts/python.exe ; POSIX: .venv/bin/python
    win = os.name == "nt"
    return venv_dir / ("Scripts/python.exe" if win else "bin/python")

def ensure_git_repo(repo_url: str | None, target_dir: Path, branch: str):
    if not target_dir.exists():
        target_dir.mkdir(parents=True, exist_ok=True)

    git_dir = target_dir / ".git"
    if git_dir.exists():
        # Check current branch
        try:
            current_branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], 
                cwd=str(target_dir), 
                text=True,
                stderr=subprocess.DEVNULL
            ).strip()
        except Exception:
            current_branch = ""

        # Check for local changes (tracked files only)
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(target_dir), text=True).strip()
        has_changes = any(line.strip() and not line.startswith("??") for line in status.splitlines())

        if current_branch != branch:
            if has_changes:
                print(f"\n! Warning: Local changes detected on branch '{current_branch}'.")
                print(f"! Skipping switch to '{branch}' to avoid stashing/committing.")
                print("! Please switch branches manually when ready.")
            else:
                print(f"Switching from '{current_branch}' to '{branch}' ...")
                run(["git", "checkout", branch], cwd=target_dir)

        # Only pull if clean and on the right branch
        if not has_changes and current_branch == branch:
            print(f"Updating branch '{branch}' in {target_dir} ...")
            run(["git", "fetch", "origin"], cwd=target_dir)
            run(["git", "pull", "--rebase", "origin", branch], cwd=target_dir)
        elif has_changes:
            print(f"\n! Skipping update of '{branch}' due to local changes.")
    else:
        if not repo_url:
            raise SystemExit("Repo not found locally and --repo URL not provided.")
        print(f"Cloning {repo_url} into {target_dir} ...")
        run(["git", "clone", "--branch", branch, repo_url, str(target_dir)])

def ensure_venv(project_dir: Path) -> Path:
    venv_dir = project_dir / ".venv"
    if not venv_dir.exists():
        print("Creating virtual environment (.venv) ...")
        # On some minimal Linux installs the ensurepip module is missing.
        # This results in a cryptic failure from `python -m venv`.  Check for
        # it up front so we can provide a helpful message.
        try:
            import ensurepip  # noqa: F401
        except ModuleNotFoundError:
            raise SystemExit(
                "Python's ensurepip module is required to create virtual environments.\n"
                "Install the 'python3-venv' package and retry.\n"
                "For example on Debian/Ubuntu: sudo apt install python3-venv"
            )

        # Prefer 'py -3' on Windows if available
        py = shutil.which("py")
        if py and os.name == "nt":
            run([py, "-3", "-m", "venv", str(venv_dir)])
        else:
            run([sys.executable, "-m", "venv", str(venv_dir)])
    return venv_dir

def pip(venv_python: Path, *args: str):
    cmd = [str(venv_python), "-m", "pip", *args]
    return run(cmd)

def ensure_requirements(project_dir: Path, venv_python: Path):
    # Some environments may have a venv without pip installed.  Attempt to
    # detect and bootstrap pip in that case so subsequent installs succeed.
    if run([str(venv_python), "-m", "pip", "--version"], check=False) != 0:
        print("pip not found; bootstrapping with ensurepip ...")
        run([str(venv_python), "-m", "ensurepip", "--upgrade"])

    print("Upgrading pip ...")
    pip(venv_python, "install", "--upgrade", "pip", "wheel", "setuptools")

    req = project_dir / "backend" / "requirements.txt"
    if req.exists():
        print(f"Installing dependencies from {req} ...")
        pip(venv_python, "install", "-r", str(req))
    else:
        print("requirements.txt not found; installing core deps ...")
        pip(
            venv_python,
            "install",
            "fastapi==0.115.0",
            "uvicorn==0.30.6",
            "python-multipart==0.0.9",
            "jinja2==3.1.4",
            "requests",
            "ciscoconfparse>=1.6.52",
            "python-dotenv",
        )


def ensure_env_file(project_dir: Path) -> int | None:
    env_file = project_dir / "backend" / ".env"
    if env_file.exists():
        print(f"Found {env_file}")
        env = load_env_from_file(env_file)
        port_val = env.get("API_PORT")
        return int(port_val) if port_val and port_val.isdigit() else None

    env_sample = project_dir / ".env.sample"
    print("\nCreating backend/.env (first run). Values are stored locally in this file.")
    token = getpass("MIST_TOKEN (input hidden): ").strip()
    base = input("MIST_BASE_URL [default https://api.ac2.mist.com]: ").strip() or "https://api.ac2.mist.com"
    org = input("MIST_ORG_ID (optional): ").strip()
    tmpl = input("SWITCH_TEMPLATE_ID (optional): ").strip()
    port = input("API_PORT [default 8000]: ").strip() or "8000"
    auth = input("AUTH_METHOD [default local]: ").strip().lower() or "local"
    syslog_host = input("SYSLOG_HOST (optional): ").strip()
    syslog_port = input("SYSLOG_PORT [default 514]: ").strip() or "514"

    lines = [
        f"AUTH_METHOD={auth}",
        "SESSION_SECRET=change_me",
        f"MIST_TOKEN={token}",
        f"MIST_BASE_URL={base}",
        f"MIST_ORG_ID={org}",
        f"SWITCH_TEMPLATE_ID={tmpl}",
        "HELP_URL=https://github.com/ejstover/GreatMigration/blob/main/README.md",
    ]

    if auth == "ldap":
        print("LDAP selected. Update backend/.env with correct LDAP settings.")
        if env_sample.exists():
            sample_lines = env_sample.read_text().splitlines()
            ldap_lines = [
                ln.lstrip("# ").rstrip()
                for ln in sample_lines
                if ln.startswith("# LDAP_") or ln.startswith("# PUSH_GROUP_DN")
            ]
            lines.extend(ldap_lines)
        else:
            lines.extend([
                "LDAP_SERVER_URL=",
                "LDAP_SEARCH_BASE=",
                "LDAP_BIND_TEMPLATE=",
                "PUSH_GROUP_DN=",
                "LDAP_SERVICE_DN=",
                "LDAP_SERVICE_PASSWORD=",
            ])
    else:
        user = input("Local username: ").strip()
        pwd = getpass("Local password (input hidden): ").strip()
        lines.append(f"LOCAL_USERS={user}:{pwd}")
        lines.append(f"LOCAL_PUSH_USERS={user}")

    lines.append(f"API_PORT={port}")
    if syslog_host:
        lines.append(f"SYSLOG_HOST={syslog_host}")
        if syslog_port:
            lines.append(f"SYSLOG_PORT={syslog_port}")

    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {env_file}")
    return int(port)

def ensure_standard_fw_versions_file(project_dir: Path):
    backend = project_dir / "backend"
    dest = backend / "standard_fw_versions.json"
    if not dest.exists():
        default_content = {
            "generated_at": None,
            "models": {
                "switch": {},
                "ap": {}
            }
        }
        dest.write_text(json.dumps(default_content, indent=2), encoding="utf-8")
        print(f"Created default {dest}")

def ensure_tmp_dirs(project_dir: Path):
    tmp_ssh_jobs = project_dir / "tmp_ssh_jobs"
    if not tmp_ssh_jobs.exists():
        tmp_ssh_jobs.mkdir(parents=True, exist_ok=True)
        print(f"Created {tmp_ssh_jobs}")
    
    logs_dir = project_dir / "backend" / "logs"
    if not logs_dir.exists():
        logs_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created {logs_dir}")

def ensure_port_rules_file(project_dir: Path):
    backend = project_dir / "backend"
    sample = backend / "port_rules.sample.json"
    dest = backend / "port_rules.json"
    if dest.exists():
        print(f"Found {dest}")
    elif sample.exists():
        shutil.copy(sample, dest)
        print(f"Copied {sample} to {dest}")
    else:
        # Create an empty one if no sample found
        dest.write_text("[]\n", encoding="utf-8")
        print(f"Created empty {dest}")

def load_env_from_file(env_path: Path) -> Dict[str, str]:
    """Very small .env loader to pass vars to uvicorn process in case app doesn't load automatically."""
    out: Dict[str, str] = {}
    if not env_path.exists():
        return out
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            out[key] = val
    return out

def start_api(project_dir: Path, venv_python: Path, port: int):
    backend = project_dir / "backend"
    env_file = backend / ".env"
    child_env = os.environ.copy()
    child_env.update(load_env_from_file(env_file))

    print(f"\nStarting API at http://0.0.0.0:{port} (Ctrl+C to stop)")
    cmd = [str(venv_python), "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", str(port), "--app-dir", str(backend)]
    try:
        run(cmd, env=child_env, check=True)
    except KeyboardInterrupt:
        print("\nStopped by user.")

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser(description="Quick start: clone/update repo, create venv, install, ensure .env, run API.")
    parser.add_argument("--repo", help="Git repo URL (for first-time clone).")
    parser.add_argument("--dir", dest="target_dir", default=".", help="Target project directory (default: current dir).")
    parser.add_argument("--branch", default="main", help="Git branch to use (default: main).")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="API port (default: value in backend/.env or 8000).",
    )
    parser.add_argument("--no-start", action="store_true", help="Setup only; do not start the API.")
    args = parser.parse_args()

    which_or_die("git")

    project_dir = Path(args.target_dir).expanduser().resolve()
    ensure_git_repo(args.repo, project_dir, args.branch)

    venv_dir = ensure_venv(project_dir)
    vpython = venv_python_path(venv_dir)

    ensure_requirements(project_dir, vpython)
    env_port = ensure_env_file(project_dir)
    ensure_port_rules_file(project_dir)
    ensure_standard_fw_versions_file(project_dir)
    ensure_tmp_dirs(project_dir)

    port = args.port if args.port is not None else env_port or 8000

    if not args.no_start:
        start_api(project_dir, vpython, port)
    else:
        print("\nSetup complete. To start later:")
        print(f'  "{vpython}" -m uvicorn app:app --host 0.0.0.0 --port {port} --app-dir "{project_dir / "backend"}"')

if __name__ == "__main__":
    main()
