#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert musl archive/path/authority/ELF checks; never executes a compiler."""
import hashlib
import io
from pathlib import Path
import runpy
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

H = runpy.run_path(str(Path(__file__).with_name('prepare-musl-i386.py')))
G = H['stage'].__globals__


def fixture(kind='regular', name='./usr/include/i386-linux-musl/test.h', duplicate=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        entry = tarfile.TarInfo(name); entry.mode = 0o644
        entry.size = 4
        if kind == 'symlink': entry.type = tarfile.SYMTYPE; entry.linkname = '/private'; entry.size = 0
        if kind == 'hardlink': entry.type = tarfile.LNKTYPE; entry.linkname = 'other'; entry.size = 0
        if kind == 'device': entry.type = tarfile.CHRTYPE; entry.size = 0
        if kind == 'suid': entry.mode = 0o4644
        archive.addfile(entry, io.BytesIO(b'data'))
        if duplicate: archive.addfile(entry, io.BytesIO(b'data'))
    expected = [dict(path=name, bytes=4, kind='0', target='', sha256=hashlib.sha256(b'data').hexdigest())]
    return output.getvalue(), expected


class MuslInput(unittest.TestCase):
    def test_pins_are_closed_to_signed_i386_data_and_original_specs(self):
        value = H['pins']()
        self.assertEqual((value['package'],value['version'],value['architecture']), ('musl-dev','1.2.5-3.1~deb13u1','i386'))
        self.assertEqual(len(value['files']),256)
        self.assertEqual(sum(x['bytes'] for x in value['files']),2661250)
        self.assertEqual(value['archive']['sha256'],H['ARCHIVE_SHA256'])
        self.assertTrue(all(x['kind'] in ('0','5') and not x['target'] for x in value['files']))

    def test_corrupt_or_missing_package_bytes_are_not_extracted(self):
        for data in (b'', b'!<arch>\n', b'corrupt'):
            with self.assertRaises(ValueError): H['package_files'](data,H['pins']()['files'])

    def test_normal_member_and_every_unsafe_path_kind_and_duplicate(self):
        raw, expected = fixture()
        self.assertEqual(H['tar_files'](raw,expected), {'usr/include/i386-linux-musl/test.h':b'data'})
        for kind in ('symlink','hardlink','device','suid'):
            with self.subTest(kind=kind), self.assertRaises(ValueError): H['tar_files'](fixture(kind)[0],expected)
        for name in ('/etc/passwd','../outside','./usr/../outside'):
            with self.subTest(name=name), self.assertRaises(ValueError): H['tar_files'](fixture(name=name)[0],expected)
        with self.assertRaises(ValueError): H['tar_files'](fixture(duplicate=True)[0],expected)
        with self.assertRaises(ValueError): H['tar_files'](raw,[])

    def test_fresh_private_stage_relocates_only_original_specs_and_never_installs(self):
        original=b'-isystem /usr/include/i386-linux-musl -L/usr/lib/i386-linux-musl\n'
        files={'usr/lib/i386-linux-musl/musl-gcc.specs':original,'usr/include/i386-linux-musl/test.h':b'data'}
        with tempfile.TemporaryDirectory() as directory, patch.dict(G,package_files=lambda *_:files,
                SPEC_SHA256=hashlib.sha256(original).hexdigest()):
            prefix=Path(directory)/'input';record=H['stage'](b'inert',prefix)
            self.assertFalse(record['package_installed'])
            self.assertEqual((prefix/'usr/lib/i386-linux-musl/musl-gcc.specs').read_bytes(),original)
            wrapper=(prefix/'musl-gcc').read_text()
            self.assertIn('exec /usr/bin/gcc "$@" -m32 -static -specs=',wrapper)
            self.assertIn(str(prefix/'usr/include/i386-linux-musl'),(prefix/'musl-gcc.specs').read_text())
            self.assertEqual(prefix.stat().st_mode&0o777,0o700)
            self.assertEqual((prefix/'usr/include').stat().st_mode&0o777,0o700)
            with self.assertRaises(ValueError): H['stage'](b'inert',prefix)
            link=Path(directory)/'link';link.symlink_to(prefix)
            with self.assertRaises(ValueError): H['stage'](b'inert',link)

    def test_host_guard_precedes_download_or_compiler(self):
        run=Mock(side_effect=AssertionError('compiler'))
        with patch.dict(H['os'].environ,{},clear=True), patch.object(H['urllib'].request,'build_opener',side_effect=AssertionError('network')):
            with self.assertRaises(ValueError): H['prepare'](Path('/inert'),Path('/output'),run)
        run.assert_not_called()

    def test_probe_rejects_wrong_architecture_dynamic_interpreter_and_bad_headers(self):
        raw=bytearray(84);raw[:7]=b'\x7fELF\x01\x01\x01'
        struct.pack_into('<H',raw,18,3);struct.pack_into('<I',raw,28,52);struct.pack_into('<HH',raw,42,32,1)
        struct.pack_into('<I',raw,52,1);H['static_i386'](raw)
        for field,kind,value in ((18,'<H',62),(52,'<I',3),(28,'<I',100000),(42,'<H',0)):
            changed=bytearray(raw);struct.pack_into(kind,changed,field,value)
            with self.assertRaises(ValueError): H['static_i386'](changed)
        self.assertIn(str(0x123456789*7).encode(),H['PROBE'])


if __name__=='__main__': unittest.main()
