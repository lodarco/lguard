"""`lguard` command line."""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

from . import config as config_mod
from . import quarantine, vault
from .clamd import Clamd
from .freeze import freeze, unfreeze
from .i18n import set_language
from .index import Index
from .scanner import Scanner
from .sweep import Sweep, walk


def _ts(x) -> str:
    return dt.datetime.fromtimestamp(float(x)).strftime("%Y-%m-%d %H:%M") if x else "-"


def _need_root():
    if os.geteuid() != 0:
        sys.exit("lguard: this needs root (sudo lguard ...)")


def index_path() -> str:
    return os.path.join(config_mod.STATE_DIR, "index.db")


def open_index(readonly=False) -> Index:
    _need_root()
    try:
        v = vault.Vault(vault.load_master_key())
    except vault.VaultError as e:
        sys.exit(f"lguard: {e}")
    if readonly and not os.path.exists(index_path()):
        sys.exit("lguard: no inventory yet (run `lguard init`, then a sweep)")
    return Index(index_path(), v, readonly=readonly)


def _line(r, path):
    return f"{r.verdict:10} {r.signature or '':40} {r.action or '':11} {path}" + ((" (known content)" if r.detail else " (index)") if r.cached else "")


def cmd_init(cfg, args):
    _need_root()
    how = vault.init_master_key()
    idx = open_index()
    idx.event("init", f"key storage: {how}")
    seq, head = idx.ledger_head()
    vault.write_anchor(seq, head)
    idx.close()
    print(f"master key created ({how}); inventory at {index_path()}")
    print("next: lguard sweep   (first full scan, reads every byte once)")


def cmd_scan(cfg, args):
    idx = open_index()
    sw = Sweep(cfg, Scanner(cfg, idx))
    bad = 0
    for p in map(os.path.abspath, args.paths):
        files = walk(p, cfg, same_dev=False) if os.path.isdir(p) else [p]
        for f in files:
            r = sw._scan(f, force=args.force)
            if r.verdict not in ("clean", "skipped") or args.verbose or not os.path.isdir(p):
                print(_line(r, f))
            bad += r.verdict in ("infected", "suspicious")
    idx.close()
    s = sw.stats
    print(f"\n{s['seen']} files, {s['scanned']} scanned, {s['cached']} from the index, "
          f"{s['findings']} findings, {s['errors']} errors")
    return 1 if bad else 0


def cmd_sweep(cfg, args):
    idx = open_index()

    def progress(**kw):
        if args.verbose:
            print(f"\r{kw['seen']:>10} seen {kw['scanned']:>9} scanned {kw['findings']} findings ",
                  end="", flush=True)
    sw = Sweep(cfg, Scanner(cfg, idx), progress=progress)
    sw.report = True
    stats = sw.full(only_priority=args.priority, deep=args.full)
    seq, head = idx.ledger_head()
    vault.write_anchor(seq, head)
    idx.close()
    print(f"\nsweep: {stats}")


def cmd_maintenance(cfg, args):
    idx = open_index()
    sw = Sweep(cfg, Scanner(cfg, idx))
    budget = int(args.verify_gb * 1024 ** 3) if args.verify_gb is not None else None
    sw.maintenance(verify_budget=budget)
    seq, head = idx.ledger_head()
    vault.write_anchor(seq, head)
    idx.close()
    n, used, mism = getattr(sw, "verified", (0, 0, 0))
    print(f"maintenance: {sw.stats}; verified {n} files / {used // 1024 ** 2} MiB, {mism} mismatches")


def cmd_status(cfg, args):
    idx = open_index(readonly=True)
    try:
        eng, db = Clamd(cfg.clamd_socket).version()
    except Exception as e:
        eng, db = f"clamd unreachable ({e})", 0
    c = idx.meta_get("counts") or {}
    print(f"engine:        {eng}, signatures {db}")
    print(f"key:           {vault.key_storage()}")
    print(f"inventory:     {idx.file_count()} files"
          + (f" (as of {_ts(c.get('at'))}: clean {c.get('clean', 0)}, infected {c.get('infected', 0)}, "
             f"suspicious {c.get('suspicious', 0)}, {c.get('bytes', 0) / 1024 ** 3:.1f} GiB)" if c else ""))
    print(f"last sweep:    {_ts(idx.meta_get('last_sweep'))}")
    print(f"frozen:        {idx.meta_get('frozen', 'no')}")
    seq, head = idx.ledger_head()
    print(f"history:       {seq} entries, head {head.hex()[:16]}")
    print(f"quarantine:    {len(quarantine.entries(cfg))} files")
    for d in idx.daily(7):
        print(f"  {d['day']}  scanned {d['scanned']:>8}  from index {d['cached']:>9}  findings {d['findings']}")


def cmd_findings(cfg, args):
    idx = open_index(readonly=True)
    for f in idx.findings(args.limit):
        print(f"{_ts(f['ts'])}  {f['level']:10} {f['action']:11} {f['signature']:38} {f['path']}")


def cmd_history(cfg, args):
    idx = open_index(readonly=True)
    for e in idx.ledger_entries(limit=args.limit):
        body = {k: v for k, v in e.items() if k not in ("seq", "ts", "kind")}
        print(f"{e['seq']:>7} {_ts(e['ts'])}  {e['kind']:15} {body}")


def cmd_verify(cfg, args):
    """Check that the inventory and its history are intact."""
    idx = open_index(readonly=True)
    problems = idx.verify_ledger()
    seq, head = idx.ledger_head()
    try:
        anchor = vault.read_anchor()
    except vault.VaultError as e:
        anchor = None
        problems.append(f"anchor unreadable: {e}")
    if anchor:
        aseq, ahead = anchor
        if seq < aseq:
            problems.append(f"ROLLBACK: history has {seq} entries, the sealed anchor says {aseq}")
        else:
            r = idx.db.execute("SELECT chain FROM ledger WHERE seq=?", (aseq,)).fetchone()
            if aseq and (not r or r[0] != ahead):
                problems.append(f"history entry {aseq} does not match the sealed anchor")
    n = 0
    for table in ("files", "hashes", "allow", "meta", "daily"):
        for _ in idx._iter(table):
            n += 1
    if idx.tamper_count:
        problems.append(f"{idx.tamper_count} stored records failed authentication")
    print(f"checked {seq} history entries and {n} records; anchor "
          + (f"at entry {anchor[0]}" if anchor else "none"))
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print("  - " + p)
        return 2
    print("inventory and history are intact")
    return 0


def cmd_quarantine(cfg, args):
    if args.action == "list":
        _need_root()
        for e in quarantine.entries(cfg):
            print(f"{e['id']}  {_ts(e['quarantined_at'])}  {e['signature']:38} {e['path']}")
        return 0
    if not args.id:
        sys.exit("quarantine restore|delete needs an id (see: lguard quarantine list)")
    idx = open_index()
    meta = next((e for e in quarantine.entries(cfg) if e["id"] == args.id), None)
    if not meta:
        sys.exit(f"no quarantine entry {args.id}")
    if args.action == "restore":
        if args.allow and meta.get("digest"):
            idx.allow(meta["digest"], meta.get("signature"), f"restored {meta['path']}")
        target = quarantine.restore(cfg, args.id)
        idx.finding_action(args.id, "restored+allowed" if args.allow else "restored")
        print(f"restored to {target}" + (" and allowed" if args.allow else ""))
    else:
        quarantine.delete(cfg, args.id)
        idx.finding_action(args.id, "deleted")
        print("deleted")
    idx.close()


def cmd_freeze(cfg, args):
    idx = open_index()
    if args.action == "freeze":
        ok = freeze(cfg, idx, "manual (lguard freeze)")
        print("frozen" if ok else "no freeze_commands configured")
    else:
        unfreeze(cfg, idx)
        print("unfrozen")
    idx.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lguard", description="Lguard - antivirus, torrent guard and ransomware alarm")
    ap.add_argument("-c", "--config", default=config_mod.CONFIG_PATH)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the sealed master key and the inventory").set_defaults(fn=cmd_init)

    p = sub.add_parser("scan", help="scan files or folders now")
    p.add_argument("paths", nargs="+")
    p.add_argument("-f", "--force", action="store_true", help="ignore the inventory, rescan")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--priority", action="store_true", help="(from qBittorrent) same as scan")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("sweep", help="walk all disks, scan what changed (first run: everything)")
    p.add_argument("--priority", action="store_true", help="only the priority (media/torrent) folders")
    p.add_argument("--full", action="store_true", help="full disk scan: read every file again now")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(fn=cmd_sweep)

    p = sub.add_parser("maintenance", help="prune, retro-hunt, deep byte verification")
    p.add_argument("--verify-gb", type=float, help="deep verification budget (default from config)")
    p.set_defaults(fn=cmd_maintenance)

    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("verify", help="check the inventory and history for tampering").set_defaults(fn=cmd_verify)

    p = sub.add_parser("findings")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(fn=cmd_findings)

    p = sub.add_parser("history")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(fn=cmd_history)

    p = sub.add_parser("quarantine")
    p.add_argument("action", choices=["list", "restore", "delete"])
    p.add_argument("id", nargs="?")
    p.add_argument("--allow", action="store_true", help="with restore: never flag this content again")
    p.set_defaults(fn=cmd_quarantine)

    for name in ("freeze", "unfreeze"):
        p = sub.add_parser(name, help=f"{name} backups/sync (freeze_commands)")
        p.set_defaults(fn=cmd_freeze, action=name)

    args = ap.parse_args(argv)
    cfg = config_mod.load(args.config)
    set_language(cfg.language)
    return args.fn(cfg, args) or 0


if __name__ == "__main__":
    sys.exit(main())
