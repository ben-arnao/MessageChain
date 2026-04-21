"""Tests for TLS private key file permissions (R5-C TOCTOU fix).

Verifies that ``_generate_self_signed_cert`` never leaves the private
key file on disk in a world- or group-readable state, closing the race
window between ``open()`` and the (old) trailing ``os.chmod(..., 0o600)``.

On Windows, POSIX mode bits do not fully apply — the shared-host threat
model is POSIX only.  The mode-specific assertions are therefore gated
on ``sys.platform != "win32"``.  The code-path inspection tests (which
assert that the cryptography path uses ``O_CREAT | O_EXCL | O_WRONLY``
and mode 0o600) run on every platform: the correct flags matter even
where Python can't enforce the mode bits.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from messagechain.network import tls


def _cryptography_available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


class TestCryptographyPathKeyMode(unittest.TestCase):
    """Cryptography-path branch — primary path when the lib is installed."""

    @unittest.skipUnless(_cryptography_available(),
                         "cryptography library not installed")
    @unittest.skipIf(sys.platform == "win32",
                     "POSIX mode bits not enforced on Windows")
    def test_key_file_mode_is_0o600_after_generation(self):
        """After ``_generate_self_signed_cert`` returns, the key file
        MUST have mode 0o600 (owner rw only)."""
        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            tls._generate_self_signed_cert(cert, key)
            mode = stat.S_IMODE(os.stat(key).st_mode)
            self.assertEqual(
                mode, 0o600,
                f"Key file mode is {oct(mode)}, expected 0o600",
            )

    @unittest.skipUnless(_cryptography_available(),
                         "cryptography library not installed")
    def test_cryptography_path_uses_o_excl_and_mode_0o600(self):
        """The cryptography path MUST open the key file with
        ``O_CREAT | O_EXCL | O_WRONLY`` and mode 0o600 so the file is
        created with restrictive permissions atomically — never
        appearing on disk world-readable."""
        real_open = os.open
        captured = {}

        def spy_open(path, flags, mode=0o777, *args, **kwargs):
            # Capture only the call targeting the key file (path ending
            # in "key.pem").  Cert writes use the normal ``open()`` and
            # do not need TOCTOU protection.
            if isinstance(path, (str, bytes, os.PathLike)):
                p = os.fspath(path)
                if p.endswith("key.pem"):
                    captured["flags"] = flags
                    captured["mode"] = mode
            return real_open(path, flags, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            with patch("os.open", side_effect=spy_open):
                tls._generate_self_signed_cert(cert, key)

        self.assertIn(
            "flags", captured,
            "Expected os.open() to be called for the key file — "
            "the cryptography path still uses the vulnerable "
            "builtin open() + chmod pattern.",
        )
        self.assertTrue(
            captured["flags"] & os.O_CREAT,
            "Key file os.open must include O_CREAT",
        )
        self.assertTrue(
            captured["flags"] & os.O_EXCL,
            "Key file os.open must include O_EXCL so an attacker can't "
            "pre-create a world-readable file at that path.",
        )
        self.assertTrue(
            captured["flags"] & os.O_WRONLY,
            "Key file os.open must include O_WRONLY",
        )
        self.assertEqual(
            captured["mode"], 0o600,
            f"Key file os.open mode is {oct(captured['mode'])}, "
            f"expected 0o600",
        )

    @unittest.skipUnless(_cryptography_available(),
                         "cryptography library not installed")
    def test_overwrites_existing_key_file(self):
        """Re-generation when a key already exists at the path must
        succeed (preserves the prior overwrite-silently semantics of
        ``open(..., 'wb')``).  The O_EXCL flag requires handling this
        case explicitly — typically by unlinking first."""
        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            # Pre-create a stale key file that we expect to be replaced.
            with open(key, "wb") as f:
                f.write(b"stale-key-contents")
            tls._generate_self_signed_cert(cert, key)
            with open(key, "rb") as f:
                contents = f.read()
            self.assertNotEqual(contents, b"stale-key-contents")
            self.assertIn(b"PRIVATE KEY", contents)


class TestOpensslFallbackKeyMode(unittest.TestCase):
    """Openssl fallback — hit only when cryptography is not installed.

    We mock subprocess.run so these tests don't actually require an
    openssl binary on PATH.  The fix under test is that the fallback
    tightens umask around the subprocess call, so the key file is
    created with mode 0o600 even if openssl's own behaviour would
    otherwise have created it world-readable.
    """

    def _force_openssl_path(self):
        """Return a context manager that makes the cryptography import
        inside ``_generate_self_signed_cert`` raise ImportError."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ImportError(
                    "cryptography forced-off for fallback test",
                )
            return real_import(name, *args, **kwargs)

        return patch("builtins.__import__", side_effect=fake_import)

    @unittest.skipIf(sys.platform == "win32",
                     "umask semantics are POSIX-specific")
    def test_openssl_fallback_tightens_umask(self):
        """The openssl fallback MUST tighten the process umask to
        0o077 around the subprocess.run call so openssl creates the
        key file as 0o600 instead of 0o644-ish.  Verify that when the
        subprocess is invoked, the current umask is restrictive."""
        observed_umasks = []

        def fake_run(cmd, *args, **kwargs):
            # Capture the umask visible to the child at the moment
            # subprocess.run is called — a no-arg os.umask call sets
            # *and* returns the previous umask, so we round-trip.
            prior = os.umask(0o077)
            observed_umasks.append(prior)
            os.umask(prior)
            # Simulate openssl writing out minimal PEM files.
            keyfile = cmd[cmd.index("-keyout") + 1]
            certfile = cmd[cmd.index("-out") + 1]
            with open(keyfile, "wb") as f:
                f.write(b"-----BEGIN FAKE KEY-----\n")
            with open(certfile, "wb") as f:
                f.write(b"-----BEGIN FAKE CERT-----\n")

            class Result:
                returncode = 0
            return Result()

        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            prior = os.umask(0o022)
            try:
                with self._force_openssl_path(), \
                     patch("subprocess.run", side_effect=fake_run):
                    tls._generate_self_signed_cert(cert, key)
            finally:
                os.umask(prior)

        self.assertEqual(
            len(observed_umasks), 1,
            "Expected subprocess.run to be called exactly once",
        )
        # The umask visible while the subprocess runs must be 0o077
        # (i.e., openssl-created files become 0o600).
        self.assertEqual(
            observed_umasks[0], 0o077,
            f"umask during openssl invocation was {oct(observed_umasks[0])}, "
            f"expected 0o077 so openssl creates the key as 0o600",
        )

    @unittest.skipIf(sys.platform == "win32",
                     "umask restoration check is POSIX-specific")
    def test_openssl_fallback_restores_umask_on_error(self):
        """The fallback MUST restore the prior umask even when
        subprocess.run raises (otherwise the tightened umask would
        leak into the rest of the process)."""
        def boom(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "openssl")

        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "cert.pem")
            key = os.path.join(tmp, "key.pem")
            prior = os.umask(0o022)
            try:
                with self._force_openssl_path(), \
                     patch("subprocess.run", side_effect=boom):
                    with self.assertRaises(subprocess.CalledProcessError):
                        tls._generate_self_signed_cert(cert, key)
                # After the failed call, the umask must be back to
                # what it was beforehand.
                current = os.umask(0o022)
                self.assertEqual(
                    current, 0o022,
                    f"umask leaked — expected 0o022, got {oct(current)}",
                )
            finally:
                os.umask(prior)


if __name__ == "__main__":
    unittest.main()
