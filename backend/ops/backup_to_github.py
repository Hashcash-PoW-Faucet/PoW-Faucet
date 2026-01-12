#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Tuple


def _strip_env_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and ((v[0] == v[-1]) and v[0] in ('"', "'")):
        return v[1:-1]
    return v


def load_env_file(path: Path, *, override: bool = False) -> bool:
    """Load KEY=VALUE lines from a .env-style file.

    - Lines starting with # are ignored.
    - Blank lines are ignored.
    - Values may be quoted with single or double quotes.
    - By default, existing os.environ keys are NOT overridden.

    Returns True if the file existed and was parsed, else False.
    """
    if not path.exists() or not path.is_file():
        return False

    for raw in path.read_text("utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = _strip_env_quotes(v)
        if not k:
            continue
        if (k in os.environ) and not override:
            continue
        os.environ[k] = v

    return True


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def cleanup_snapshot_artifacts(base_db: Path, gz_path: Path) -> None:
    """Remove plaintext snapshot artifacts (best effort)."""
    candidates = [
        base_db,
        Path(str(base_db) + "-wal"),
        Path(str(base_db) + "-shm"),
        Path(str(base_db) + "-journal"),
        gz_path,
    ]
    for p in candidates:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass


def run_sqlite_checks(db_path: Path) -> Dict[str, Any]:
    # read-only connect (best effort); still works on normal file too
    uri = f"file:{db_path.as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        con.row_factory = sqlite3.Row
        qc = con.execute("PRAGMA quick_check;").fetchall()
        ic = con.execute("PRAGMA integrity_check;").fetchall()

        quick_ok = all((r[0] == "ok") for r in qc)
        integ_ok = all((r[0] == "ok") for r in ic)

        jm = con.execute("PRAGMA journal_mode;").fetchone()[0]
        sm = con.execute("PRAGMA synchronous;").fetchone()[0]
        uv = con.execute("PRAGMA user_version;").fetchone()[0]

        return {
            "quick_check_ok": bool(quick_ok),
            "integrity_check_ok": bool(integ_ok),
            "quick_check": [r[0] for r in qc[:10]],
            "integrity_check": [r[0] for r in ic[:10]],
            "journal_mode": jm,
            "synchronous": sm,
            "user_version": uv,
        }
    finally:
        con.close()


def make_consistent_snapshot(src_db: Path, dst_db: Path) -> None:
    """
    Creates a consistent snapshot using sqlite backup API.
    This avoids copying a file mid-write.
    """
    dst_db.parent.mkdir(parents=True, exist_ok=True)

    # Open source normally (read-only backup can still require read access)
    src = sqlite3.connect(src_db.as_posix(), timeout=30)
    try:
        dst = sqlite3.connect(dst_db.as_posix(), timeout=30)
        try:
            # Pages per step: tune to reduce blocking time
            src.backup(dst, pages=2000)
            # Ensure the snapshot is self-contained and does not rely on WAL sidecars.
            try:
                dst.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except Exception:
                pass
            try:
                dst.execute("PRAGMA journal_mode=DELETE;")
            except Exception:
                pass
            dst.commit()
        finally:
            dst.close()
    finally:
        src.close()


def gzip_compress(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as f_in, gzip.open(dst, "wb", compresslevel=9) as f_out:
        shutil.copyfileobj(f_in, f_out)


def gpg_encrypt_sym(src: Path, dst: Path, passphrase: str) -> None:
    gpg = shutil.which("gpg")
    if not gpg:
        raise RuntimeError("gpg not found. Install with: brew install gnupg")

    # Symmetric encryption with AES256; loopback to allow --passphrase in batch mode.
    cmd = [
        gpg,
        "--batch",
        "--yes",
        "--pinentry-mode", "loopback",
        "--passphrase", passphrase,
        "--symmetric",
        "--cipher-algo", "AES256",
        "-o", str(dst),
        str(src),
    ]
    subprocess.run(cmd, check=True)


def git(cmd: list[str], repo_dir: Path) -> Tuple[int, str]:
    p = subprocess.run(["git", "-C", str(repo_dir), *cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


def main() -> int:
    # Phase 1: allow loading env vars from a local file (no need to `source backup.env`).
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument(
        "--env",
        default=None,
        help="Optional path to an env file (default: ./backup.env if present)",
    )
    pre_args, _ = pre.parse_known_args()

    env_loaded = False
    if pre_args.env:
        env_loaded = load_env_file(Path(os.path.expanduser(pre_args.env)).resolve())
    else:
        env_loaded = load_env_file(Path.cwd() / "backup.env")

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--env",
        default=pre_args.env,
        help="Optional path to an env file (default: ./backup.env if present)",
    )
    ap.add_argument(
        "--db",
        default=os.environ.get("FAUCET_DB"),
        help="Path to faucet_old.db (or set FAUCET_DB in backup.env)",
    )
    ap.add_argument(
        "--repo",
        default=os.environ.get("DB_BACKUP_REPO"),
        help="Local path to cloned db-backup repo (or set DB_BACKUP_REPO in backup.env)",
    )
    ap.add_argument(
        "--keep-snapshots",
        type=int,
        default=int(os.environ.get("KEEP_SNAPSHOTS", "200")),
        help="How many encrypted snapshots to keep in repo (or set KEEP_SNAPSHOTS)",
    )
    args = ap.parse_args()

    if not args.db or not args.repo:
        if not env_loaded:
            print("ERROR: missing --db/--repo and no backup.env loaded (expected ./backup.env)", file=sys.stderr)
        else:
            print("ERROR: missing --db/--repo (set FAUCET_DB and DB_BACKUP_REPO in backup.env)", file=sys.stderr)
        return 2

    db_path = Path(os.path.expanduser(args.db)).resolve()
    repo_dir = Path(os.path.expanduser(args.repo)).resolve()
    if not db_path.exists():
        print(f"ERROR: DB not found: {db_path}", file=sys.stderr)
        return 2
    if not (repo_dir / ".git").exists():
        print(f"ERROR: repo dir is not a git repo: {repo_dir}", file=sys.stderr)
        return 2

    if args.env:
        env_path = Path(os.path.expanduser(args.env)).resolve()
        if not env_path.exists():
            print(f"ERROR: env file not found: {env_path}", file=sys.stderr)
            return 2

    passphrase = os.environ.get("BACKUP_PASSPHRASE", "").strip()
    if not passphrase:
        print("ERROR: BACKUP_PASSPHRASE env var is missing", file=sys.stderr)
        return 2

    # 0) Sync repo first (before writing new snapshot files).
    # A brand-new empty GitHub repo has no remote branch yet; in that case, skip pull.
    rc, out = git(["pull", "--rebase"], repo_dir)
    print(out)
    if rc != 0:
        out_l = out.lower()
        if (
            "no such ref was fetched" in out_l
            or "couldn't find remote ref" in out_l
            or "could not find remote ref" in out_l
            or "remote ref does not exist" in out_l
            or "does not appear to be a git repository" in out_l
        ):
            print(
                "WARNING: git pull skipped (remote branch not found yet). "
                "If this is a new repo, create an initial commit on GitHub (e.g. add a README) "
                "or run `git push -u origin main` once in the repo.",
                file=sys.stderr,
            )
        else:
            print("ERROR: git pull failed", file=sys.stderr)
            return 4
    ts = int(time.time())
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(ts))

    out_dir = repo_dir / "snapshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    snap_db = out_dir / f"faucet_snapshot_{stamp}.db"
    snap_gz = out_dir / f"{snap_db.name}.gz"
    snap_gpg = out_dir / f"{snap_gz.name}.gpg"

    # 1) Check source DB integrity
    checks = run_sqlite_checks(db_path)
    if not checks["quick_check_ok"] or not checks["integrity_check_ok"]:
        print("ERROR: DB integrity checks failed. Will not back up.", file=sys.stderr)
        print(json.dumps(checks, indent=2), file=sys.stderr)
        return 3

    # 2) Create consistent snapshot
    make_consistent_snapshot(db_path, snap_db)

    # 3) Optional: check snapshot too (paranoid mode)
    snap_checks = run_sqlite_checks(snap_db)
    if not snap_checks["quick_check_ok"] or not snap_checks["integrity_check_ok"]:
        print("ERROR: SNAPSHOT integrity checks failed. Will not back up.", file=sys.stderr)
        print(json.dumps(snap_checks, indent=2), file=sys.stderr)
        try:
            snap_db.unlink()
        except Exception:
            pass
        return 3

    # 4) Compress
    gzip_compress(snap_db, snap_gz)

    # 5) Encrypt
    gpg_encrypt_sym(snap_gz, snap_gpg, passphrase)

    # cleanup plaintext artifacts (including possible WAL/SHM sidecars)
    cleanup_snapshot_artifacts(snap_db, snap_gz)

    # 6) Write manifest
    manifest = {
        "created_at_unix": ts,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "source_db_path": str(db_path),
        "snapshot_file": snap_gpg.name,
        "snapshot_size_bytes": snap_gpg.stat().st_size,
        "snapshot_sha256": sha256_file(snap_gpg),
        "source_checks": checks,
        "snapshot_checks": snap_checks,
        "note": "Encrypted snapshot: gzip + gpg symmetric AES256",
    }
    (repo_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (repo_dir / "LATEST").write_text(snap_gpg.name + "\n", encoding="utf-8")

    # 7) Prune old snapshots (keep newest N)
    snaps = sorted(out_dir.glob("faucet_snapshot_*.db.gz.gpg"), key=lambda p: p.name)
    if len(snaps) > int(args.keep_snapshots):
        for p in snaps[: len(snaps) - int(args.keep_snapshots)]:
            try:
                p.unlink()
            except Exception:
                pass

    # 8) Git commit + push

    rc, out = git(["add", "manifest.json", "LATEST", "snapshots/"], repo_dir)
    print(out)
    if rc != 0:
        print("ERROR: git add failed", file=sys.stderr)
        return 4

    rc, out = git(["status", "--porcelain"], repo_dir)
    if rc != 0:
        print("ERROR: git status failed", file=sys.stderr)
        return 4
    if not out.strip():
        print("No changes to commit.")
        return 0

    msg = f"backup: {snap_gpg.name}"
    rc, out = git(["commit", "-m", msg], repo_dir)
    print(out)
    if rc != 0:
        print("ERROR: git commit failed", file=sys.stderr)
        return 4

    rc, out = git(["push"], repo_dir)
    print(out)
    if rc != 0:
        print("ERROR: git push failed", file=sys.stderr)
        return 4

    print("Backup OK:", snap_gpg.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())