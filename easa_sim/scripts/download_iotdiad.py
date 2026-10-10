#!/usr/bin/env python3
r"""Recursively download the CIC IoT-DIAD 2024 "Anomaly Detection - Flow Based features" tree.

The CIC portal is a browse.php?p=<folder path> listing with per-file "Download" links.
This crawler discovers sub-folders and file links generically, mirrors the folder
structure under --out, skips files that already exist with the right size, and
retries on transient errors.

Usage (PowerShell, from the easa_sim folder, with .venv active):
  python scripts\download_iotdiad.py --dry-run             # list what would be downloaded
  python scripts\download_iotdiad.py                       # download everything (Flow Based)
  python scripts\download_iotdiad.py --root "Anomaly Detection - Flow Based features/DDoS"   # one family only

If the server answers 403 even in a browser-like session, open the site in your browser,
press F12 -> Application/Storage -> Cookies, copy the cookie string and pass it:
  python scripts\download_iotdiad.py --cookie "PHPSESSID=....; other=..."
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests

BASE = "https://cicresearch.ca/IOTDataset/CIC-IoT-IDAD-Dataset-2024/"
DEFAULT_ROOT = "Anomaly Detection - Flow Based features"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0 Safari/537.36")
FILE_EXT = (".csv", ".txt", ".zip", ".gz", ".parquet", ".pdf")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []   # (href, text)
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def browse_url(path: str) -> str:
    return BASE + "browse.php?p=" + requests.utils.quote(path, safe="")


def listing(session: requests.Session, path: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Return (sub-folder paths, [(file_download_url, suggested_name)])."""
    r = session.get(browse_url(path), timeout=60)
    r.raise_for_status()
    p = LinkParser(); p.feed(r.text)
    folders, files = [], []
    for href, text in p.links:
        if not href or href.startswith("#"):
            continue
        full = urljoin(BASE, href)
        q = parse_qs(urlparse(full).query)
        if "browse.php" in full and "p" in q:
            sub = unquote(q["p"][0]).replace("+", " ")
            if sub.startswith(path) and sub != path and sub.rstrip("/") != path.rstrip("/"):
                folders.append(sub)
            continue
        low = full.lower()
        is_file = low.endswith(FILE_EXT) or "download" in low or text.lower() == "download" \
            or any(v and v[0].lower().endswith(FILE_EXT) for v in q.values())
        if is_file:
            # best-effort name: a query parameter that looks like a filename, else URL basename
            name = None
            for v in q.values():
                if v and v[0].lower().endswith(FILE_EXT):
                    name = os.path.basename(unquote(v[0])); break
            if name is None:
                name = os.path.basename(unquote(urlparse(full).path)) or "download.bin"
            files.append((full, name))
    # de-duplicate while preserving order
    seen = set(); files = [f for f in files if not (f[0] in seen or seen.add(f[0]))]
    return sorted(set(folders)), files


def download(session: requests.Session, url: str, dest: str, retries: int = 4) -> str:
    for attempt in range(1, retries + 1):
        try:
            with session.get(url, stream=True, timeout=120) as r:
                r.raise_for_status()
                # honour server-provided filename if present
                cd = r.headers.get("Content-Disposition", "")
                m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
                if m:
                    dest = os.path.join(os.path.dirname(dest), os.path.basename(unquote(m.group(1))))
                total = int(r.headers.get("Content-Length", 0) or 0)
                if os.path.exists(dest) and total and os.path.getsize(dest) == total:
                    return "skip"
                tmp = dest + ".part"
                done = 0; t0 = time.time()
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        if chunk:
                            f.write(chunk); done += len(chunk)
                            if total:
                                pct = 100 * done / total
                                print(f"\r    {os.path.basename(dest)}  {pct:5.1f}%  {done/1e6:8.1f} MB", end="")
                os.replace(tmp, dest)
                dt = time.time() - t0
                print(f"\r    {os.path.basename(dest)}  done  {done/1e6:8.1f} MB  ({done/1e6/max(dt,1e-6):.1f} MB/s)")
                return "ok"
        except Exception as e:  # noqa: BLE001
            print(f"\n    retry {attempt}/{retries} after error: {e}")
            time.sleep(3 * attempt)
    return "fail"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=DEFAULT_ROOT, help="portal folder path to mirror")
    ap.add_argument("--out", default=os.path.join("data", "IoT-DIAD-2024", "flow"))
    ap.add_argument("--cookie", default=None, help="raw Cookie header copied from the browser if 403")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Referer": BASE, "Accept": "text/html,*/*"})
    if a.cookie:
        s.headers["Cookie"] = a.cookie

    stack = [a.root]; n_files = n_ok = n_skip = n_fail = 0
    while stack:
        path = stack.pop(0)
        try:
            folders, files = listing(s, path)
        except requests.HTTPError as e:
            print(f"[{path}] HTTP {e.response.status_code} -- if 403, re-run with --cookie (see docstring)")
            sys.exit(1)
        rel = path[len(a.root):].strip("/")
        dest_dir = os.path.join(a.out, *[seg for seg in rel.split("/") if seg])
        print(f"[{path}]  folders={len(folders)}  files={len(files)}")
        stack = folders + stack           # depth-first so one family completes before the next
        if not files:
            continue
        if not a.dry_run:
            os.makedirs(dest_dir, exist_ok=True)
        for url, name in files:
            n_files += 1
            dest = os.path.join(dest_dir, name)
            if a.dry_run:
                print(f"    {name}  <-  {url}"); continue
            res = download(s, url, dest)
            n_ok += res == "ok"; n_skip += res == "skip"; n_fail += res == "fail"
    print(f"\nfiles seen={n_files}  downloaded={n_ok}  skipped={n_skip}  failed={n_fail}")
    if n_fail:
        print("re-run the same command to retry failed files (existing complete files are skipped)")


if __name__ == "__main__":
    main()
