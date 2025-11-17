import os
import json
from hashlib import sha256
from app.common.utils import now_ms

TRANSCRIPT_FILE = "transcript.log"


def compute_hash(prev_hash: bytes, entry_bytes: bytes) -> bytes:
    """
    Compute TranscriptHash = SHA256(prev_hash || entry_bytes).
    """
    return sha256(prev_hash + entry_bytes).digest()


class Transcript:
    def __init__(self, path: str = TRANSCRIPT_FILE):
        self.path = path

    def _load_entries(self):
        """
        Load all transcript entries.
        If any line is invalid JSON, mark entry as None (tampered).
        """
        entries = []
        if not os.path.exists(self.path):
            return entries

        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    # Mark invalid entry for tamper detection
                    entries.append(None)

        return entries

    def append(self, event_type: str, data=None) -> str:
        """
        Append a new transcript entry and compute hash chaining.
        Returns the new entry hash (hex string).
        """
        if data is None:
            data = {}

        entries = self._load_entries()

        # Determine previous hash
        if not entries:
            prev_hash = b"\x00" * 32
        else:
            last = entries[-1]
            if last is None:
                # Previous entry corrupted — treat chain as broken
                prev_hash = b"\x00" * 32
            else:
                prev_hash = bytes.fromhex(last["hash"])

        entry = {
            "timestamp": now_ms(),
            "type": event_type,
            "data": data,
        }

        # Entry bytes without hash
        entry_bytes = json.dumps(entry, sort_keys=True).encode("utf-8")

        # Compute chained hash
        h = compute_hash(prev_hash, entry_bytes)
        entry["hash"] = h.hex()

        # Append entry to file
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry["hash"]

    def verify_integrity(self) -> bool:
        """
        Verify transcript hash chain.
        Returns False if any line is invalid or hash mismatch occurs.
        """
        entries = self._load_entries()
        prev_hash = b"\x00" * 32

        for e in entries:
            if e is None:
                return False  # Invalid JSON = tampered

            # Copy entry except hash
            chk = {k: v for k, v in e.items() if k != "hash"}
            entry_bytes = json.dumps(chk, sort_keys=True).encode("utf-8")

            expected = compute_hash(prev_hash, entry_bytes)

            if expected.hex() != e["hash"]:
                return False  # Hash mismatch

            prev_hash = expected

        return True
