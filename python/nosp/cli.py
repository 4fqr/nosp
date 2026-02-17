"""
NOSP command-line utility — succinct, human-friendly and robust.

Usage examples:
  python -m nosp.cli init-db --db ./nosp.db
  python -m nosp.cli scan --top 10
  python -m nosp.cli analyze --pid 1234
  python -m nosp.cli watch --duration 60

The CLI re-uses existing package components and deliberately avoids
starting the Streamlit UI when invoked.
"""
from __future__ import annotations
import argparse
import sys
import time
from typing import List, Dict, Optional

# local imports (use package internals for stable behavior)
from .risk_scorer import RiskScorer
from .database import NOSPDatabase
from .ai_engine import NOSPAIEngine

ANSI_BOLD = "\x1b[1m"
ANSI_RESET = "\x1b[0m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_RED = "\x1b[31m"


def _header(text: str) -> None:
    print(f"{ANSI_BOLD}{text}{ANSI_RESET}")


def init_db(db_path: str = "nosp.db") -> bool:
    """Create or verify the database and schema."""
    db = NOSPDatabase(db_path)
    # constructor initializes schema; return True to indicate success
    print(f"Initialized database: {db_path}")
    db.close()
    return True


def _format_table(rows: List[Dict[str, object]], columns: List[str]) -> str:
    widths = [max((len(str(r.get(c, ''))) for r in rows), default=len(c)) for c in columns]
    widths = [max(w, len(c)) for w, c in zip(widths, columns)]
    hdr = "  ".join(c.ljust(w) for c, w in zip(columns, widths))
    sep = "  ".join("-" * w for w in widths)
    lines = [hdr, sep]
    for r in rows:
        lines.append("  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(columns, widths)))
    return "\n".join(lines)


def scan(top: int = 10) -> List[Dict[str, object]]:
    """Scan running processes and return the top N suspicious by heuristic risk.

    This is intentionally safe: it uses psutil and the RiskScorer heuristics only.
    """
    try:
        import psutil
    except Exception as e:
        print("psutil is required for scan. Install with: pip install psutil")
        raise

    scorer = RiskScorer()
    rows: List[Dict[str, object]] = []
    for p in psutil.process_iter(["pid", "name", "username", "cmdline", "ppid"]):
        try:
            info = p.info
            event = {
                "image": info.get("name") or "",
                "command_line": " ".join(info.get("cmdline") or []),
                "pid": info.get("pid"),
                "user": info.get("username") or "",
                "parent_image": "",
            }
            # best-effort parent name
            try:
                parent = psutil.Process(info.get("ppid")) if info.get("ppid") else None
                event["parent_image"] = parent.name() if parent else ""
            except Exception:
                event["parent_image"] = ""

            score, factors = scorer.calculate_risk(event)
            rows.append({"pid": event["pid"], "name": event["image"], "risk": score, "cmdline": event["command_line"]})
        except Exception:
            continue

    rows = sorted(rows, key=lambda r: r["risk"], reverse=True)[:top]
    print(_format_table(rows, ["pid", "risk", "name", "cmdline"]))
    return rows


def analyze(pid: int) -> Dict[str, object]:
    """Run AI analysis for a process (best-effort; uses NOSPAIEngine.safe path)."""
    try:
        import psutil
    except Exception:
        return {"ok": False, "error": "psutil required"}

    try:
        proc = psutil.Process(pid)
    except Exception as e:
        return {"ok": False, "error": f"PID {pid} not found: {e}"}

    event = {
        "image": proc.name(),
        "command_line": " ".join(proc.cmdline() or []),
        "process_id": proc.pid,
        "user": proc.username() if hasattr(proc, "username") else "",
        "parent_image": "",
    }
    try:
        parent = proc.parent()
        event["parent_image"] = parent.name() if parent else ""
    except Exception:
        event["parent_image"] = ""

    engine = NOSPAIEngine()
    res = engine.analyze_process_safe(event)
    if hasattr(res, "success") and res.success:
        print("AI analysis:\n")
        print(res.value)
        return {"ok": True, "analysis": res.value}
    else:
        msg = res.message if hasattr(res, "message") else str(res)
        print(f"Analysis failed: {msg}")
        return {"ok": False, "error": msg}


def watch(duration: Optional[int] = 0) -> None:
    """Watch for new processes and print suspicious ones as they appear.

    duration of 0 means run until interrupted.
    """
    try:
        import psutil
    except Exception:
        print("psutil is required for watch. Install with: pip install psutil")
        raise

    seen = set()
    scorer = RiskScorer()
    start = time.time()
    print("Watching for new processes (press Ctrl-C to stop)")
    try:
        while True:
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                pid = p.info.get("pid")
                if pid in seen:
                    continue
                seen.add(pid)
                try:
                    event = {"image": p.info.get("name") or "", "command_line": " ".join(p.info.get("cmdline") or []), "pid": pid, "user": ""}
                    score, _ = scorer.calculate_risk(event)
                    if score >= 40:
                        print(f"[{time.strftime('%H:%M:%S')}] {ANSI_YELLOW}PID {pid:<6}{ANSI_RESET} {p.info.get('name'):<25} risk={score}")
                except Exception:
                    continue
            if duration and (time.time() - start) > duration:
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("Stopped by user")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nosp", description="NOSP command-line utility")
    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init-db", help="create/verify database schema")
    p_init.add_argument("--db", default="nosp.db", help="database file path")

    p_scan = sub.add_parser("scan", help="scan running processes using heuristics")
    p_scan.add_argument("--top", type=int, default=10, help="top N results to show")

    p_analyze = sub.add_parser("analyze", help="run AI analysis for a running PID (best-effort)")
    p_analyze.add_argument("--pid", type=int, required=True, help="process id to analyze")

    p_watch = sub.add_parser("watch", help="watch for new processes and report suspicious ones")
    p_watch.add_argument("--duration", type=int, default=0, help="seconds to run (0 = indefinite)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "init-db":
        init_db(args.db)
        return 0
    if args.command == "scan":
        scan(args.top)
        return 0
    if args.command == "analyze":
        analyze(args.pid)
        return 0
    if args.command == "watch":
        watch(args.duration)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
