"""Receive local handoff files, prepare/run a frozen review, or replay an export."""
import argparse
import sqlite3
import subprocess
import sys
from pathlib import Path
from bridge import Receiver, CONTRACT, MAX_BUNDLE, MAX_SELECTION, read_file, encode, replay_export


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--db", type=Path)
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("init")
    receive = subs.add_parser("receive")
    receive.add_argument("--event", required=True)
    receive.add_argument("--bundle", type=Path, required=True)
    receive.add_argument("--received-at", help="UTC time asserted by the receiver; omit if unknown")
    prepare = subs.add_parser("prepare")
    prepare.add_argument("--cutoff", required=True)
    prepare.add_argument("--assessed-at", required=True)
    for name in ("run", "status", "export"):
        sub = subs.add_parser(name)
        sub.add_argument("run_id")
        if name == "export":
            sub.add_argument("directory", type=Path)
    subs.add_parser("replay").add_argument("directory", type=Path)
    args = parser.parse_args()
    receiver = None
    try:
        selected = read_file(args.selection, MAX_SELECTION)
        if args.command == "replay":
            result = replay_export(selected, args.directory)
        else:
            if args.db is None:
                parser.error("--db is required except for replay")
            receiver = Receiver(args.db, selected, create=args.command == "init")
            if args.command == "init":
                result = {"contract": CONTRACT, "status": "initialized", "is_execution_ticket": False}
            elif args.command == "receive":
                result = receiver.receive(args.event, read_file(args.bundle, MAX_BUNDLE), args.received_at)
            elif args.command == "prepare":
                result = receiver.prepare(args.cutoff, args.assessed_at)
            elif args.command == "run":
                result = receiver.run(args.run_id)
            elif args.command == "status":
                result = receiver.report(receiver.box.status(args.run_id))
            else:
                result = receiver.export(args.run_id, args.directory)
        print(encode(result).decode())
        if args.command == "run" and result["inbox"]["status"] != "completed":
            return 3
        return 2 if result.get("status") == "unassessable" else 0
    except BlockingIOError:
        result = {"status": "retryable_busy", "reason": "RECEIVER_BUSY", "is_execution_ticket": False}
    except sqlite3.OperationalError as exc:
        result = {"status": "retryable_busy" if "locked" in str(exc).lower() else "storage_error",
                  "reason": "SQLITE_OPERATION_FAILED", "is_execution_ticket": False}
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        result = {"status": "operation_error", "reason": getattr(exc, "code", type(exc).__name__),
                  "is_execution_ticket": False}
    finally:
        if receiver is not None:
            receiver.close()
    print(encode(result).decode())
    return 3


if __name__ == "__main__":
    sys.exit(main())
