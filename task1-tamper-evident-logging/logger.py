"""
Task 1: Tamper-Evident Logging System
======================================
Each log entry contains a SHA-256 hash of the previous entry,
forming a cryptographic chain. Any modification, deletion, or
reordering of entries breaks the chain and is detected instantly.

Detection capabilities:
  - Entry content modified     -> hash mismatch
  - Entry deleted              -> ID gap in sequence
  - Entries reordered          -> ID sequence out of order
  - Chain linkage broken       -> prev_hash mismatch

The verification system also pinpoints the exact entry where
tampering first occurred and lists all clean entries before it.
"""

import hashlib
import json
import os
from datetime import datetime

LOG_FILE = "logs.json"

def compute_hash(entry: dict) -> str:
    entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
    raw = json.dumps(entry_copy, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def load_logs() -> list:
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_logs(logs: list):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def add_log(event_type: str, description: str, user: str = "system"):
    logs = load_logs()
    prev_hash = logs[-1]["entry_hash"] if logs else "0" * 64
    entry = {
        "id"          : len(logs) + 1,
        "timestamp"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type"  : event_type,
        "description" : description,
        "user"        : user,
        "prev_hash"   : prev_hash,
    }
    entry["entry_hash"] = compute_hash(entry)
    logs.append(entry)
    save_logs(logs)
    print(f"  + Log #{entry['id']} added  [{event_type}] -- {description}")
    return entry

def verify_logs() -> bool:
    logs = load_logs()

    if not logs:
        print("  No log entries found.")
        return True

    print(f"\n  Verifying {len(logs)} log entries...\n")

    all_ok        = True
    first_bad_id  = None
    clean_entries = []

    ids = [entry["id"] for entry in logs]

    # CHECK 1a: Reordering detection
    if ids != sorted(ids):
        print(f"  [FAIL] REORDER DETECTED -- Entry IDs are not in correct sequence!")
        print(f"         Found order : {ids}")
        print(f"         Expected    : {sorted(ids)}")
        all_ok = False
        for i in range(len(ids) - 1):
            if ids[i] > ids[i + 1]:
                first_bad_id = ids[i]
                break

    # CHECK 1b: Deletion detection
    if ids:
        expected_ids = list(range(1, max(ids) + 1))
        missing = sorted(set(expected_ids) - set(ids))
        extra   = sorted(set(ids) - set(expected_ids))
        if missing:
            print(f"  [FAIL] DELETION DETECTED -- Missing entry IDs: {missing}")
            print(f"         {len(missing)} log entr{'y was' if len(missing)==1 else 'ies were'} removed from the chain!")
            all_ok = False
            if first_bad_id is None:
                first_bad_id = missing[0]
        if extra:
            print(f"  [FAIL] INSERTION DETECTED -- Unexpected entry IDs: {extra}")
            all_ok = False

    # CHECK 2: Per-entry hash and chain verification
    for i, entry in enumerate(logs):

        expected_hash = compute_hash(entry)
        if entry["entry_hash"] != expected_hash:
            print(f"  [FAIL] MODIFICATION DETECTED at entry #{entry['id']} -- content was altered!")
            print(f"         Stored hash  : {entry['entry_hash'][:32]}...")
            print(f"         Expected hash: {expected_hash[:32]}...")
            all_ok = False
            if first_bad_id is None:
                first_bad_id = entry["id"]
            continue

        if i == 0:
            if entry["prev_hash"] != "0" * 64:
                print(f"  [FAIL] CHAIN TAMPERED -- Entry #1 has invalid genesis prev_hash!")
                all_ok = False
                if first_bad_id is None:
                    first_bad_id = entry["id"]
        else:
            expected_prev = logs[i - 1]["entry_hash"]
            if entry["prev_hash"] != expected_prev:
                prev_id = logs[i - 1]["id"]
                curr_id = entry["id"]
                if curr_id - prev_id > 1:
                    print(f"  [FAIL] DELETION DETECTED -- Gap in chain between entry #{prev_id} and #{curr_id}!")
                    print(f"         Entries {list(range(prev_id+1, curr_id))} appear to have been removed.")
                else:
                    print(f"  [FAIL] CHAIN BROKEN between entry #{prev_id} and #{curr_id}!")
                print(f"         Expected prev_hash: {expected_prev[:32]}...")
                print(f"         Found    prev_hash: {entry['prev_hash'][:32]}...")
                all_ok = False
                if first_bad_id is None:
                    first_bad_id = curr_id

        if first_bad_id is None:
            clean_entries.append(entry["id"])
            print(f"  [OK]   Entry #{entry['id']:>3}  [{entry['event_type']:<20}]  hash OK  |  chain OK")

    # TAMPER SUMMARY
    print()
    print("  " + "=" * 55)

    if all_ok:
        print("  INTEGRITY CHECK PASSED -- All entries are authentic.\n")
    else:
        print("  INTEGRITY CHECK FAILED -- Log tampering detected!")
        print("  " + "=" * 55)
        print()
        print("  TAMPER SUMMARY:")

        if first_bad_id is not None:
            print(f"     First anomaly detected at : Entry #{first_bad_id}")
            print(f"     All entries from #{first_bad_id} onwards are compromised")
        else:
            print(f"     Anomaly detected in ID sequence (deletion/reorder)")

        if clean_entries:
            if len(clean_entries) == 1:
                print(f"     Entries verified clean    : #{clean_entries[0]} only")
            else:
                print(f"     Entries verified clean    : #{clean_entries[0]} to #{clean_entries[-1]}")
        else:
            print(f"     Entries verified clean    : None -- entire chain is compromised")

        if first_bad_id and first_bad_id > 1:
            print(f"     Recommendation            : Restore from backup before Entry #{first_bad_id}")
        else:
            print(f"     Recommendation            : Restore entire log from a trusted backup")

        print()

    return all_ok

def display_logs():
    logs = load_logs()
    if not logs:
        print("  No logs to display.")
        return
    print(f"\n  {'='*70}")
    print(f"  LOG CHAIN -- {len(logs)} entries")
    print(f"  {'='*70}")
    for entry in logs:
        print(f"\n  Entry #{entry['id']}  |  {entry['timestamp']}")
        print(f"  Event      : {entry['event_type']}")
        print(f"  User       : {entry['user']}")
        print(f"  Description: {entry['description']}")
        print(f"  Prev Hash  : {entry['prev_hash'][:32]}...")
        print(f"  This Hash  : {entry['entry_hash'][:32]}...")
        print(f"  {'-'*66}")
    print()

def simulate_tamper(entry_id: int, new_description: str):
    logs = load_logs()
    for entry in logs:
        if entry["id"] == entry_id:
            entry["description"] = new_description
            save_logs(logs)
            print(f"  [DEMO] Entry #{entry_id} modified -- description changed to: '{new_description}'")
            return
    print(f"  Entry #{entry_id} not found.")

def simulate_delete(entry_id: int):
    logs = load_logs()
    original_count = len(logs)
    logs = [e for e in logs if e["id"] != entry_id]
    if len(logs) == original_count:
        print(f"  Entry #{entry_id} not found.")
        return
    save_logs(logs)
    print(f"  [DEMO] Entry #{entry_id} deleted from the chain!")

def simulate_reorder(id_a: int, id_b: int):
    logs = load_logs()
    idx_a = next((i for i, e in enumerate(logs) if e["id"] == id_a), None)
    idx_b = next((i for i, e in enumerate(logs) if e["id"] == id_b), None)
    if idx_a is None or idx_b is None:
        print(f"  One or both entry IDs not found.")
        return
    logs[idx_a], logs[idx_b] = logs[idx_b], logs[idx_a]
    save_logs(logs)
    print(f"  [DEMO] Entries #{id_a} and #{id_b} swapped in the chain!")

def menu():
    while True:
        print("\n  " + "="*50)
        print("    TAMPER-EVIDENT LOGGING SYSTEM")
        print("  " + "="*50)
        print("    1. Add a log entry")
        print("    2. View all logs")
        print("    3. Verify log integrity")
        print("    4. Simulate modification  (alter entry content)")
        print("    5. Simulate deletion      (remove an entry)")
        print("    6. Simulate reordering    (swap two entries)")
        print("    7. Exit")
        print("  " + "="*50)

        choice = input("    Choose an option: ").strip()

        if choice == "1":
            event = input("    Event type (e.g. LOGIN, TRANSACTION): ").strip()
            desc  = input("    Description: ").strip()
            user  = input("    User (default: system): ").strip() or "system"
            add_log(event, desc, user)

        elif choice == "2":
            display_logs()

        elif choice == "3":
            verify_logs()

        elif choice == "4":
            display_logs()
            try:
                eid   = int(input("    Entry ID to modify: ").strip())
                ndesc = input("    New (fake) description: ").strip()
                simulate_tamper(eid, ndesc)
                print("    Now run option 3 to see modification detected!")
            except ValueError:
                print("    Invalid ID.")

        elif choice == "5":
            display_logs()
            try:
                eid = int(input("    Entry ID to delete: ").strip())
                simulate_delete(eid)
                print("    Now run option 3 to see deletion detected!")
            except ValueError:
                print("    Invalid ID.")

        elif choice == "6":
            display_logs()
            try:
                id_a = int(input("    First entry ID to swap: ").strip())
                id_b = int(input("    Second entry ID to swap: ").strip())
                simulate_reorder(id_a, id_b)
                print("    Now run option 3 to see reordering detected!")
            except ValueError:
                print("    Invalid IDs.")

        elif choice == "7":
            print("    Exiting. Goodbye.")
            break
        else:
            print("    Invalid option. Try again.")

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        print("\n  Creating sample log entries...")
        add_log("SYSTEM_START", "System initialized successfully",        "system")
        add_log("LOGIN",        "User admin logged in from 192.168.1.10", "admin")
        add_log("FILE_ACCESS",  "Accessed /etc/config.json",              "admin")
        add_log("TRANSACTION",  "Transfer of $500 to account #4821",      "admin")
        add_log("LOGOUT",       "User admin logged out",                  "admin")
        print("  Sample logs created! Starting menu...\n")

    menu()
