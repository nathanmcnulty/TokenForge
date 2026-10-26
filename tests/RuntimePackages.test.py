"""Offline standard-library checks for the bounded historical-archive repacker."""
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('repack', Path(__file__).resolve().parents[1] / 'scripts/New-TokenForgeRuntimePackages.py')
repack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(repack)


class PackageBoundary(unittest.TestCase):
    def read(self, names, zipped=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture'
            if zipped:
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, mode in names:
                        entry = zipfile.ZipInfo(name)
                        entry.external_attr = mode << 16
                        archive.writestr(entry, b'fixture')
            else:
                with tarfile.open(path, 'w:gz') as archive:
                    for name, mode in names:
                        entry = tarfile.TarInfo(name)
                        entry.type = mode
                        if mode == tarfile.REGTYPE:
                            entry.size = 7
                            archive.addfile(entry, io.BytesIO(b'fixture'))
                        else:
                            entry.linkname = 'outside'
                            archive.addfile(entry)
            return repack.read_archive(path, hashlib.sha256(path.read_bytes()).hexdigest(), zipped)

    def test_regular_archives(self):
        for zipped, mode in ((False, tarfile.REGTYPE), (True, stat.S_IFREG | 0o600)):
            self.assertEqual(self.read([('src/file', mode)], zipped), {'src/file': b'fixture'})

    def test_unsafe_names(self):
        for name in ('../outside', '/absolute', 'a/../b', 'a//b', 'a\\b', 'a\nb'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.read([(name, tarfile.REGTYPE)])

    def test_duplicate_and_case_collisions(self):
        for names in (('a', 'a'), ('A', 'a')):
            for zipped, mode in ((False, tarfile.REGTYPE), (True, stat.S_IFREG | 0o600)):
                with self.subTest(names=names, zipped=zipped), self.assertRaises(ValueError):
                    self.read([(n, mode) for n in names], zipped)

    def test_links_and_special_files(self):
        for mode in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.read([('a', mode)])
        with self.assertRaises(ValueError):
            self.read([('a', stat.S_IFLNK | 0o600)], True)

    def test_file_parent_conflict(self):
        with self.assertRaises(ValueError):
            self.read([('A', tarfile.REGTYPE), ('a/b', tarfile.REGTYPE)])

    def test_modified_archive_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture'
            path.write_bytes(b'not the pinned archive')
            with self.assertRaisesRegex(ValueError, 'independently pinned'):
                repack.read_archive(path, '0' * 64)

    def test_incomplete_compilation_set_rejected(self):
        with patch.object(repack, 'tree', return_value={'one': 'blob'}):
            with self.assertRaisesRegex(ValueError, 'compilation inputs differ'):
                repack.prepare(Path('.'), 'revision', {}, True)

    def test_changed_compilation_blob_rejected(self):
        old = {str(i): 'old' for i in range(100)}
        new = dict(old, **{'0': 'changed'})
        with patch.object(repack, 'tree', side_effect=[old, new]):
            with self.assertRaisesRegex(ValueError, 'compilation inputs differ'):
                repack.prepare(Path('.'), 'revision', {}, True)

    def test_deterministic_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            for zipped in (False, True):
                one, two = Path(tmp) / ('one' + str(zipped)), Path(tmp) / ('two' + str(zipped))
                repack.write_archive(one, {'tokenforge': b'binary', 'src/file': b'source'}, zipped)
                repack.write_archive(two, {'src/file': b'source', 'tokenforge': b'binary'}, zipped)
                self.assertEqual(one.read_bytes(), two.read_bytes())
                with self.assertRaises(FileExistsError):
                    repack.write_archive(one, {}, zipped)


if __name__ == '__main__':
    unittest.main()
