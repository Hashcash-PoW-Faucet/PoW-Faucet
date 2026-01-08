#!/usr/bin/env python3
"""restore_from_github.py

Restores an encrypted+compressed SQLite database snapshot from a git repo.

Assumptions / format (matches our backup script convention):
- Snapshots are files within the repo (default: snapshots/) with one of these suffixes:
    *.db.gz.gpg, *.gz.gpg, *.gpg (GPG symmetric)
    *.db.gz.enc, *.sqlite.gz.enc, *.gz.enc, *.enc (OpenSSL enc)
- The plaintext is a gzip-compressed SQLite DB.
- Encryption uses OpenSSL 'enc' with AES-256-GCM, PBKDF2, SHA-256.

This script:
- Optionally git-pulls the repo
- Picks the latest snapshot (by filename mtime) unless --snapshot is given
- Decrypts -> gunzips -> writes DB to target path atomically
- Runs PRAGMA integrity_check on the restored DB

It auto-loads dotenv-style env files (default: ./backup.env).
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ------------------------- dotenv -------------------------

def _parse_dotenv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        # strip optional quotes
        if (len(v) >= 2) and ((v[0] == v[-1]) and v[0] in ("\"", "'")):
            v = v[1:-1]
        out[k] = v
    return out


def load_env_file(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    return _parse_dotenv(path.read_text("utf-8"))


def apply_env(env: Dict[str, str], override: bool = False) -> None:
    for k, v in env.items():
        if override or (k not in os.environ):
            os.environ[k] = v


def expanduser_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p))).resolve()


# ------------------------- helpers -------------------------

@dataclass
class RestoreConfig:
    repo: Path
    out_db: Path
    passphrase: str
    snapshots_dir: Path
    snapshot_globs: Tuple[str, ...]
    git_pull: bool


def run(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str]:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return p.returncode, p.stdout


def ensure_git_repo(repo: Path) -> None:
    if not repo.exists():
        raise SystemExit(f"Repo path does not exist: {repo}")
    if not (repo / ".git").exists():
        raise SystemExit(f"Not a git repo (missing .git): {repo}")


def git_pull(repo: Path) -> None:
    code, out = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo)
    if code != 0:
        raise SystemExit(f"git error: {out.strip()}")

    # Fetch + fast-forward only
    code, out = run(["git", "fetch", "--all", "--prune"], cwd=repo)
    if code != 0:
        raise SystemExit(f"git fetch failed: {out.strip()}")

    code, out = run(["git", "pull", "--ff-only"], cwd=repo)
    if code != 0:
        raise SystemExit(f"git pull failed: {out.strip()}")


def find_snapshots(snapshots_dir: Path, globs: Tuple[str, ...]) -> List[Path]:
    files: List[Path] = []
    if not snapshots_dir.exists():
        return []
    for g in globs:
        files.extend(sorted(snapshots_dir.glob(g)))
    # dedupe
    uniq = sorted({p.resolve() for p in files})
    return [Path(p) for p in uniq]


def pick_latest(files: List[Path]) -> Path:
    if not files:
        raise SystemExit("No snapshots found.")
    # pick by mtime (robust across varying filenames)
    files2 = sorted(files, key=lambda p: (p.stat().st_mtime, str(p)), reverse=True)
    return files2[0]


def require_openssl() -> str:
    code, out = run(["openssl", "version"])
    if code != 0:
        raise SystemExit("OpenSSL not found. Install openssl or ensure it is on PATH.")
    return out.strip()


def require_gpg() -> str:
    code, out = run(["gpg", "--version"])
    if code != 0:
        raise SystemExit("gpg not found. Install gpg or ensure it is on PATH.")
    # first line contains version
    return out.splitlines()[0].strip() if out else "gpg"


def openssl_decrypt_to_file(enc_path: Path, out_path: Path, passphrase: str) -> None:
    """Decrypts enc_path into out_path using OpenSSL enc AES-256-GCM PBKDF2 SHA-256."""
    # Note: using -pass pass:... (no env leakage via args is still visible in ps).
    # For a more private variant, use -pass env:...; we support that too.
    env = os.environ.copy()
    env["BACKUP_PASSPHRASE"] = passphrase

    cmd = [
        "openssl",
        "enc",
        "-d",
        "-aes-256-gcm",
        "-pbkdf2",
        "-iter",
        "200000",
        "-md",
        "sha256",
        "-salt",
        "-in",
        str(enc_path),
        "-out",
        str(out_path),
        "-pass",
        "env:BACKUP_PASSPHRASE",
    ]

    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    if p.returncode != 0:
        raise SystemExit(f"Decrypt failed: {p.stdout.strip()}")


def gpg_decrypt_to_file(enc_path: Path, out_path: Path, passphrase: str) -> None:
    """Decrypts enc_path into out_path using GPG symmetric decryption."""
    # Use loopback pinentry so this can run non-interactively.
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "-o",
        str(out_path),
        "-d",
        str(enc_path),
    ]

    p = subprocess.run(
        cmd,
        input=(passphrase + "\n"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if p.returncode != 0:
        raise SystemExit(f"GPG decrypt failed: {p.stdout.strip()}")


def decrypt_snapshot_to_gz(snapshot_path: Path, out_gz_path: Path, passphrase: str) -> None:
    """Decrypt snapshot (either .gpg or .enc) into a gzip file at out_gz_path."""
    name = snapshot_path.name.lower()
    if name.endswith(".gpg"):
        gpg_decrypt_to_file(snapshot_path, out_gz_path, passphrase)
        return
    if name.endswith(".enc"):
        openssl_decrypt_to_file(snapshot_path, out_gz_path, passphrase)
        return
    raise SystemExit(f"Unknown snapshot format (expected .gpg or .enc): {snapshot_path}")


def gunzip_to_file(gz_path: Path, out_path: Path) -> None:
    with gzip.open(gz_path, "rb") as fin:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as fout:
            shutil.copyfileobj(fin, fout)


def sqlite_integrity_check(db_path: Path, quick: bool = False) -> Tuple[bool, str]:
    q = "PRAGMA quick_check;" if quick else "PRAGMA integrity_check;"
    try:
        con = sqlite3.connect(str(db_path))
        try:
            cur = con.execute(q)
            rows = [r[0] for r in cur.fetchall()]
        finally:
            con.close()
    except Exception as e:
        return False, f"sqlite error: {e}"

    # SQLite returns a single row 'ok' when checks pass (or multiple issues).
    if rows == ["ok"]:
        return True, "ok"
    return False, "\n".join(str(x) for x in rows)


def atomic_replace(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    try:
        if tmp.exists():
            tmp.unlink()
    except Exception:
        pass
    shutil.move(str(src), str(tmp))
    os.replace(str(tmp), str(dst))


# ------------------------- main -------------------------


def build_restore_config(args: argparse.Namespace) -> RestoreConfig:
    repo = expanduser_path(args.repo)
    out_db = expanduser_path(args.out_db)

    passphrase = args.passphrase or os.environ.get("BACKUP_PASSPHRASE") or ""
    if not passphrase:
        raise SystemExit("Missing BACKUP_PASSPHRASE (set in env or backup.env or pass --passphrase).")

    snapshots_dir = expanduser_path(args.snapshots_dir) if args.snapshots_dir else (repo / "snapshots")

    globs = tuple(args.glob) if args.glob else (
        "*.db.gz.gpg",
        "*.sqlite.gz.gpg",
        "*.gz.gpg",
        "*.gpg",
        "*.db.gz.enc",
        "*.sqlite.gz.enc",
        "*.gz.enc",
        "*.enc",
    )

    return RestoreConfig(
        repo=repo,
        out_db=out_db,
        passphrase=passphrase,
        snapshots_dir=snapshots_dir,
        snapshot_globs=globs,
        git_pull=not args.no_pull,
    )


def list_snapshots(files: List[Path]) -> None:
    if not files:
        print("No snapshots found.")
        return
    print("Snapshots:")
    for p in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
        size = p.stat().st_size
        print(f"  {ts}  {size:>10}  {p.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Restore encrypted+gzipped SQLite DB snapshot (.gpg or .enc) from git repo")
    ap.add_argument("--env", default="backup.env", help="dotenv-style env file to load (default: ./backup.env)")

    ap.add_argument("--repo", default=os.environ.get("DB_BACKUP_REPO", "~/db-backup"), help="Local path to db-backup git repo")
    ap.add_argument("--out-db", default=os.environ.get("FAUCET_DB", "~/PoW-Faucet/backend/faucet.db"), help="Target DB path to write")

    ap.add_argument("--snapshots-dir", default=os.environ.get("SNAPSHOTS_DIR", ""), help="Snapshots directory (default: <repo>/snapshots)")
    ap.add_argument("--glob", action="append", help="Snapshot glob(s) within snapshots-dir (can repeat)")

    ap.add_argument("--snapshot", default="", help="Specific snapshot filename (within snapshots-dir) to restore")
    ap.add_argument("--no-pull", action="store_true", help="Do not git pull before restoring")

    ap.add_argument("--passphrase", default="", help="Backup passphrase (otherwise BACKUP_PASSPHRASE env)")

    ap.add_argument("--check-only", action="store_true", help="Only decrypt+check integrity; do not replace target DB")
    ap.add_argument("--quick", action="store_true", help="Use PRAGMA quick_check instead of integrity_check")
    ap.add_argument("--list", action="store_true", help="List available snapshots and exit")

    args = ap.parse_args()

    # Load env file (dotenv-style) without requiring `source`.
    env_path = expanduser_path(args.env)
    env = load_env_file(env_path)
    apply_env(env, override=False)

    cfg = build_restore_config(args)

    ensure_git_repo(cfg.repo)

    if cfg.git_pull:
        print(f"restore: git pull in {cfg.repo} ...")
        git_pull(cfg.repo)

    files = find_snapshots(cfg.snapshots_dir, cfg.snapshot_globs)

    if args.list:
        list_snapshots(files)
        return 0

    if args.snapshot:
        snap = (cfg.snapshots_dir / args.snapshot).resolve()
        if not snap.exists():
            raise SystemExit(f"Snapshot not found: {snap}")
    else:
        snap = pick_latest(files)

    # Ensure required crypto tool is available for the selected snapshot.
    if snap.name.lower().endswith(".gpg"):
        require_gpg()
    elif snap.name.lower().endswith(".enc"):
        require_openssl()
    else:
        raise SystemExit(f"Unsupported snapshot type: {snap.name}")

    print(f"restore: snapshot={snap}")
    print(f"restore: target_db={cfg.out_db}")

    with tempfile.TemporaryDirectory(prefix="db-restore-") as td:
        td_path = Path(td)
        dec_gz = td_path / "snapshot.db.gz"
        plain_db = td_path / "snapshot.db"

        print("restore: decrypting...")
        decrypt_snapshot_to_gz(snap, dec_gz, cfg.passphrase)

        print("restore: gunzipping...")
        gunzip_to_file(dec_gz, plain_db)

        print("restore: sqlite integrity check...")
        ok, msg = sqlite_integrity_check(plain_db, quick=args.quick)
        if not ok:
            raise SystemExit(f"Integrity check failed:\n{msg}")
        print("restore: integrity ok")

        if args.check_only:
            print("restore: check-only; not writing target db")
            return 0

        # Backup existing target if present
        if cfg.out_db.exists():
            bak = cfg.out_db.with_suffix(cfg.out_db.suffix + f".bak.{int(time.time())}")
            print(f"restore: backing up existing db -> {bak}")
            bak.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cfg.out_db, bak)

        print("restore: replacing target db atomically...")
        atomic_replace(plain_db, cfg.out_db)

    print("restore: DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
