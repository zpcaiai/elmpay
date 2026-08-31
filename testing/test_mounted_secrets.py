from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/runtime"))

from elmpay_runtime.common import ValidationError  # noqa: E402
from elmpay_runtime.mounted_secrets import read_mounted_secret  # noqa: E402


class MountedSecretTest(unittest.TestCase):
    def test_accepts_kubernetes_rotation_symlink_inside_mount(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory) / "mount"
            revision = mount / "..2026_08_30"
            revision.mkdir(parents=True)
            target = revision / "key"
            target.write_bytes(b"s" * 32 + b"\n")
            target.chmod(0o400)
            (mount / "..data").symlink_to(revision.name)
            (mount / "key").symlink_to("..data/key")

            self.assertEqual(b"s" * 32,
                             read_mounted_secret(str(mount / "key"), "test key"))

    def test_rejects_escape_and_writable_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount = root / "mount"
            mount.mkdir()
            outside = root / "outside"
            outside.write_bytes(b"x" * 32)
            outside.chmod(0o400)
            (mount / "key").symlink_to(outside)
            with self.assertRaisesRegex(ValidationError, "escapes"):
                read_mounted_secret(str(mount / "key"), "test key")

            (mount / "key").unlink()
            writable = mount / "writable"
            writable.write_bytes(b"y" * 32)
            writable.chmod(0o600)
            with self.assertRaisesRegex(ValidationError, "read-only"):
                read_mounted_secret(str(writable), "test key")


if __name__ == "__main__":
    unittest.main()
