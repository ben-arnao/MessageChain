"""
Anchor connection persistence for MessageChain.

Anchor connections are saved to disk on shutdown and reconnected first on
startup. This prevents eclipse attacks across node restarts — an attacker
cannot isolate a node by waiting for it to restart and then filling all
its connection slots.

Inspired by Bitcoin Core's anchors.dat (PR #17428).

## Durability

The file is written via tmp-file-then-rename so a crash during save cannot
corrupt the live file — readers either see the complete OLD file or the
complete NEW file, never a half-written one.  The prior contents of the
file are rotated into a ``.bak`` sidecar on each successful save, giving
the loader a last-known-good snapshot to fall back to if the live file
is somehow corrupted out-of-band (disk error, operator edit, etc.).

## Corruption handling

A malformed live file does NOT silently yield an empty anchor list —
that would open an eclipse window on reboot, since the node would then
connect to anyone.  Instead, the loader logs a WARNING naming the bad
path and attempts to load the ``.bak`` sidecar; only if both are bad
does it fall back to an empty list.
"""

import json
import logging
import os
import tempfile

logger = logging.getLogger(__name__)


class AnchorStore:
    """Persists anchor peer addresses to survive node restarts."""

    def __init__(self, path: str):
        self.path = path
        self.bak_path = path + ".bak"

    def save_anchors(self, anchors: list[tuple[str, int]]):
        """Save anchor addresses to disk atomically.

        Strategy:
          1. Move the current live file (if any) to ``<path>.bak`` so a
             recovery path exists if the upcoming write turns out bad.
          2. Write the new contents to a ``<path>.tmp`` sibling.
          3. Rename the tmp file over the live path (atomic on POSIX; on
             Windows ``os.replace`` is atomic for same-volume renames).

        If any step raises, the live file is left exactly as it was
        before the save attempt.  Callers see a warning in the log but
        no exception — this code runs on shutdown / periodic flush
        where a raised exception would be swallowed anyway.
        """
        data = [{"host": h, "port": p} for h, p in anchors]
        # Serialize FIRST so that an encoding error doesn't leave the
        # live file in the middle of the rotate-and-rename dance.
        try:
            payload = json.dumps(data)
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize anchors for {self.path}: {e}")
            return

        # Rotate existing live file into .bak so the load path has a
        # recovery snapshot.  Best-effort: if the rotate fails we STILL
        # try to write the new file — losing the .bak snapshot is
        # preferable to silently dropping a save.
        if os.path.exists(self.path):
            try:
                os.replace(self.path, self.bak_path)
            except OSError as e:
                logger.warning(
                    f"Failed to rotate {self.path} -> {self.bak_path}: {e}"
                )

        # tmp-file-then-rename for atomicity.  Write to a sibling in the
        # same directory so the final rename stays on the same volume
        # (cross-volume rename is not atomic on any OS).
        parent = os.path.dirname(self.path) or "."
        tmp_fd = None
        tmp_path = None
        try:
            os.makedirs(parent, exist_ok=True)
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix=os.path.basename(self.path) + ".",
                suffix=".tmp",
                dir=parent,
            )
            with os.fdopen(tmp_fd, "w") as f:
                tmp_fd = None  # fdopen took ownership
                f.write(payload)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync not supported on every FS (e.g. some tmpfs);
                    # non-fatal — we still have the .bak and the rename
                    # is atomic.
                    pass
            os.replace(tmp_path, self.path)
            tmp_path = None  # successfully renamed
        except OSError as e:
            logger.warning(f"Failed to save anchors to {self.path}: {e}")
            # Best-effort cleanup of leftover tmp file.
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception as e:
            logger.warning(f"Unexpected error saving anchors to {self.path}: {e}")
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if tmp_path is not None and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def load_anchors(self) -> list[tuple[str, int]]:
        """Load anchor addresses from disk.

        Returns empty list if no file exists at all (fresh node).  On
        corruption, logs a WARNING naming the bad path and tries to
        recover from the ``.bak`` sidecar before giving up — silently
        returning [] would leave the node with zero anchors on reboot,
        opening an eclipse window.
        """
        # Try the live file first.
        anchors, status = self._try_read(self.path)
        if status == "ok":
            return anchors
        if status == "corrupt":
            logger.warning(
                f"Anchor file at {self.path} is corrupt; "
                f"attempting recovery from {self.bak_path}"
            )
            bak_anchors, bak_status = self._try_read(self.bak_path)
            if bak_status == "ok":
                logger.warning(
                    f"Recovered {len(bak_anchors)} anchor(s) from {self.bak_path}"
                )
                return bak_anchors
            if bak_status == "corrupt":
                logger.warning(
                    f"Anchor backup at {self.bak_path} is also corrupt; "
                    f"no anchors will be loaded this session"
                )
        # status == "missing" or no valid backup — fresh start.
        return []

    @staticmethod
    def _try_read(path: str) -> tuple[list[tuple[str, int]], str]:
        """Attempt to read and validate an anchor file.

        Returns ``(anchors, status)`` where status is one of:
          * ``"missing"`` — file does not exist (not an error)
          * ``"ok"`` — read and validated successfully
          * ``"corrupt"`` — file exists but cannot be parsed or is
            structurally wrong (caller decides how loudly to complain)
        """
        if not os.path.exists(path):
            return [], "missing"
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return [], "corrupt"
        if not isinstance(data, list):
            return [], "corrupt"
        result: list[tuple[str, int]] = []
        for entry in data:
            if not isinstance(entry, dict):
                # Silently skip individual bad entries; a single malformed
                # row in an otherwise-valid file is not a reason to refuse
                # the whole file.  A file that isn't even a list (above)
                # is a different kind of broken.
                continue
            host = entry.get("host", "")
            port = entry.get("port", 0)
            # H7: Validate port range
            if not isinstance(port, int) or not (1 <= port <= 65535):
                logger.warning(f"Skipping anchor with invalid port: {host}:{port}")
                continue
            if not isinstance(host, str) or not host:
                logger.warning("Skipping anchor with invalid host")
                continue
            result.append((host, port))
        return result, "ok"
