#!/usr/bin/env python3
"""Cache top 10 largest files and directories to a JSON file.
Run via cron every 30 minutes. Dashboard reads the cache for instant display."""
import json
import os
import subprocess
import pwd as _pwd

CACHE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "top-disk.json")
SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/snap")


def human_size(size_bytes):
    size_bytes = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024.0 or unit == "TB":
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def get_owner(path):
    try:
        st = os.stat(path)
        return _pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        return "?"


def scan_files():
    """Top 10 largest files via find."""
    files = []
    try:
        result = subprocess.run(
            ["find", "/", "-xdev", "-type", "f", "-printf", "%s %u %p\n"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=60,
        )
        parsed = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue
            try:
                size = int(parts[0])
            except ValueError:
                continue
            owner = parts[1]
            path = parts[2]
            if any(path.startswith(p) for p in SKIP_PREFIXES):
                continue
            parsed.append((size, owner, path))
        parsed.sort(key=lambda x: x[0], reverse=True)
        for size, owner, path in parsed[:10]:
            files.append({
                "path": path,
                "size_human": human_size(size),
                "size_bytes": size,
                "owner": owner,
            })
    except Exception as e:
        print(f"Error scanning files: {e}")
    return files


def scan_dirs():
    """Top 10 largest directories via du on first-level children."""
    dirs = []
    try:
        # Scan first-level children of /
        entries = []
        for d in os.listdir("/"):
            full = os.path.join("/", d)
            if not os.path.isdir(full):
                continue
            if any(full.startswith(p) for p in SKIP_PREFIXES):
                continue
            entries.append(full)
        if not entries:
            return dirs
        result = subprocess.run(
            ["du", "-xsb"] + entries,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=60,
        )
        parsed = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) < 2:
                continue
            try:
                size = int(parts[0])
            except ValueError:
                continue
            path = parts[1]
            owner = get_owner(path)
            parsed.append((size, owner, path))
        parsed.sort(key=lambda x: x[0], reverse=True)
        for size, owner, path in parsed[:10]:
            dirs.append({
                "path": path,
                "size_human": human_size(size),
                "size_bytes": size,
                "owner": owner,
            })
    except Exception as e:
        print(f"Error scanning dirs: {e}")
    return dirs


def main():
    print("Scanning top files...")
    files = scan_files()
    print(f"  Found {len(files)} files")

    print("Scanning top directories...")
    dirs = scan_dirs()
    print(f"  Found {len(dirs)} directories")

    # 2026-09-13: si le scan échoue (timeout find/du sous charge CPU élevée),
    # ne PAS écraser le cache avec des listes vides — garder l'ancienne valeur.
    if not files and not dirs:
        if os.path.exists(CACHE_FILE):
            print("Scan returned no data — keeping existing cache (not overwritten)")
            return
        print("Scan returned no data and no cache exists — writing empty cache")

    data = {"files": files, "dirs": dirs, "timestamp": __import__("time").time()}

    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Cache written to {CACHE_FILE}")


if __name__ == "__main__":
    main()
