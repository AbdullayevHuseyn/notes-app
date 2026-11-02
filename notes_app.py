#!/usr/bin/env python3
"""
Simple notes app demonstrating access control + STRIDE/DREAD logging.

- Two predefined users, each with their own notes.
- Login = choosing a username (simplified, NOT real authentication).
- A user may view/edit only their own notes.
- Attempts on someone else's note are DENIED and logged with a
  STRIDE threat type and a precomputed DREAD risk score.
"""

import sys
from datetime import datetime

LOG_FILE = "access.log"

# ---------------------------------------------------------------- data
# note id -> {"owner": ..., "text": ...}
NOTES = {
    1: {"owner": "Ali",   "text": "Ali's shopping list"},
    2: {"owner": "Vusal", "text": "Vusal's secret plan"},
    3: {"owner": "Ali",   "text": "Ali's homework reminders"},
    4: {"owner": "Vusal", "text": "Vusal's password hints"},
}
USERS = ["Ali", "Vusal"]

# ---------------------------------------------------------------- threat model
# DREAD factors (1-10): Damage, Reproducibility, Exploitability,
# Affected users, Discoverability.  Score = average, precomputed below.
DREAD_FACTORS = {
    "Tampering":              (5, 4, 4, 2, 4),   # sum 19 -> 3.8
    "Information Disclosure": (4, 4, 3, 2, 4),   # sum 17 -> 3.4
}
DREAD_SCORES = {t: round(sum(f) / len(f), 1) for t, f in DREAD_FACTORS.items()}

# action -> STRIDE threat when the action is attempted on a foreign note
THREAT_FOR_ACTION = {
    "view": "Information Disclosure",
    "edit": "Tampering",
}


# ---------------------------------------------------------------- logic
def is_owner(user, note_id):
    note = NOTES.get(note_id)
    return note is not None and note["owner"] == user


def write_log(user, action, note_id, result, threat=None):
    """Append an entry to the log file and print it."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line1 = f"user={user} | action={action} | note={note_id} | result={result}"
    lines = [f"[{ts}]", line1]
    if threat:
        lines.append(f"threat={threat} | DREAD={DREAD_SCORES[threat]}")
    entry = "\n".join(lines)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n\n")
    except OSError as e:
        print(f"(warning: could not write log: {e})")
    return entry


def view_note(user, note_id):
    """Returns (allowed, text_or_message)."""
    if note_id not in NOTES:
        return False, "Note does not exist."
    if not is_owner(user, note_id):
        write_log(user, "view", note_id, "DENIED", THREAT_FOR_ACTION["view"])
        return False, "Access denied: this note belongs to another user."
    write_log(user, "view", note_id, "ALLOWED")
    return True, NOTES[note_id]["text"]


def edit_note(user, note_id, new_text):
    """Returns (allowed, message)."""
    if note_id not in NOTES:
        return False, "Note does not exist."
    if not is_owner(user, note_id):
        write_log(user, "edit", note_id, "DENIED", THREAT_FOR_ACTION["edit"])
        return False, "Access denied: this note belongs to another user."
    NOTES[note_id]["text"] = new_text
    write_log(user, "edit", note_id, "ALLOWED")
    return True, "Note updated."


def my_notes(user):
    return sorted(i for i, n in NOTES.items() if n["owner"] == user)


# ---------------------------------------------------------------- UI
def ask_note_id(prompt="Note ID: "):
    raw = input(prompt).strip()
    try:
        return int(raw)
    except ValueError:
        print("Please enter a number.")
        return None


def login():
    print("Users:", ", ".join(USERS))
    while True:
        name = input("Choose username: ").strip()
        # case-insensitive match
        for u in USERS:
            if u.lower() == name.lower():
                return u
        print("Unknown user. Try again.")


def main():
    print("=== Notes App (access control demo) ===")
    user = login()
    print(f"Logged in as {user}. Your notes: {my_notes(user)}")

    while True:
        print("\n1) View note   2) Edit note   3) List my notes   4) Quit")
        choice = input("> ").strip()
        if choice == "1":
            nid = ask_note_id()
            if nid is None:
                continue
            ok, msg = view_note(user, nid)
            print(msg if ok else f"[!] {msg}")
        elif choice == "2":
            nid = ask_note_id()
            if nid is None:
                continue
            text = input("New text: ")
            ok, msg = edit_note(user, nid, text)
            print(msg if ok else f"[!] {msg}")
        elif choice == "3":
            print("Your notes:", my_notes(user))
        elif choice == "4":
            print("Bye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nBye.")
        sys.exit(0)
