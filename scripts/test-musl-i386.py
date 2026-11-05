#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert musl archive/path/authority/ELF checks; never executes a compiler."""
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

H = runpy.run_path(str(Path(__file__).with_name('prepare-musl-i386.py')))
G = H['stage'].__globals__


def relocatable():
    raw = bytearray(52)
    raw[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHI', raw, 16, 1, 3, 1)
    return bytes(raw)


def gcc_archive(members):
    raw = b'!<arch>\n'
    for name, value in members:
        raw += (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
                + '644'.ljust(8) + str(len(value)).ljust(10) + '`\n').encode()
        raw += value + (b'\n' if len(value) % 2 else b'')
    return raw


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
            self.assertIn('exec /usr/bin/gcc "$@" -m32 -Wl,-m,elf_i386 -static -B'
                          + str(H['GCC_MULTILIB']) + '/ -specs=',wrapper)
            self.assertEqual(record['gcc_multilib_prefix'], str(H['GCC_MULTILIB']) + '/')
            self.assertEqual(record['compiler_architecture_option'], '-m32')
            self.assertEqual(record['linker_emulation_option'], '-Wl,-m,elf_i386')
            self.assertIn(str(prefix/'usr/include/i386-linux-musl'),(prefix/'musl-gcc.specs').read_text())
            self.assertEqual(prefix.stat().st_mode&0o777,0o700)
            self.assertEqual((prefix/'usr/include').stat().st_mode&0o777,0o700)
            with self.assertRaises(ValueError): H['stage'](b'inert',prefix)
            link=Path(directory)/'link';link.symlink_to(prefix)
            with self.assertRaises(ValueError): H['stage'](b'inert',link)

    def wrapper_fixture(self, directory):
        original=b'-isystem /usr/include/i386-linux-musl -L/usr/lib/i386-linux-musl\n*link:\n-nostdlib %{static:-static}\n'
        files={'usr/lib/i386-linux-musl/musl-gcc.specs':original}
        prefix=Path(directory)/'input'
        with patch.dict(G,package_files=lambda *_:files,SPEC_SHA256=hashlib.sha256(original).hexdigest()):
            H['stage'](b'inert',prefix)
        stub=Path(directory)/'inert-gcc.py'
        stub.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["MUSL_INERT_ARGV_FILE"]).write_text(json.dumps(sys.argv[1:]))\n')
        stub.chmod(0o700)
        text=(prefix/'musl-gcc').read_text()
        self.assertEqual(text.count('/usr/bin/gcc'),1)
        # Only this test copy replaces the compiler with a pure argv recorder.
        # No compiler binary is invoked and production has no compiler override.
        wrapper=Path(directory)/'inert-wrapper'
        wrapper.write_text(text.replace('/usr/bin/gcc',str(stub)))
        return prefix,wrapper

    def test_wrapper_selects_both_i386_compilation_and_linking_with_original_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix,wrapper=self.wrapper_fixture(directory)
            output=Path(directory)/'argv.json'
            inputs=['source name.c','-o','output name','-m32','-Wl,-m,elf_i386']
            result=subprocess.run(['sh',str(wrapper),*inputs],env=dict(os.environ,MUSL_INERT_ARGV_FILE=str(output)),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            observed=json.loads(output.read_text())
            self.assertEqual(observed,inputs+['-m32','-Wl,-m,elf_i386','-static',
                                            '-B'+str(H['GCC_MULTILIB'])+'/',
                                            '-specs='+str(prefix/'musl-gcc.specs')])
            self.assertNotIn('-m64',observed)
            self.assertNotIn('-Wl,-m,elf_x86_64',observed)

    def test_known_contradictory_architecture_flags_stop_before_inert_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            _,wrapper=self.wrapper_fixture(directory)
            output=Path(directory)/'argv.json'
            for flag in ('-m64','-mx32','-Wl,-m,elf_x86_64','-Wl,-m,elf32_x86_64',
                         '-B', '-B/private', '-B/usr/lib/gcc/x86_64-linux-gnu/13/32/'):
                with self.subTest(flag=flag):
                    result=subprocess.run(['sh',str(wrapper),'probe.c',flag],env=dict(os.environ,MUSL_INERT_ARGV_FILE=str(output)),capture_output=True,text=True)
                    self.assertEqual(result.returncode,2)
                    self.assertEqual(result.stdout,'')
                    self.assertEqual(result.stderr,'musl wrapper requires i386 compilation and linking\n')
                    self.assertFalse(output.exists())

    def test_support_objects_and_every_archive_code_member_require_i386_relocatable(self):
        good = relocatable()
        H['i386_relocatable'](good)
        raw = gcc_archive([('/', b'index'), ('//', b'long-object-name.o/\n'),
                           ('one.o/', good), ('/0', good)])
        self.assertEqual(H['i386_archive'](raw), 2)
        wrong = [b'', b'\x7fELF', good[:4]+b'\x02'+good[5:]]
        for offset, value in ((5, 2), (6, 0), (16, 2), (18, 62), (20, 0)):
            changed = bytearray(good); changed[offset] = value; wrong.append(bytes(changed))
        for code in wrong:
            with self.subTest(code=code), self.assertRaises(ValueError):
                H['i386_relocatable'](code)
            # An acceptable first member must never hide later foreign code.
            with self.assertRaises(ValueError): H['i386_archive'](gcc_archive([('ok.o/', good), ('bad.o/', code)]))
        for archive in (b'!<thin>\n', b'!<arch>\n', raw[:-1], raw+b'x',
                        gcc_archive([('/', b'index')]),
                        gcc_archive([('/', b'one'), ('/', b'two'), ('ok.o/', good)]),
                        b'!<arch>\n'+b'x'*60, b'!<arch>\n'+bytes(16*1024**2)):
            with self.subTest(archive=archive[:20]), self.assertRaises(ValueError):
                H['i386_archive'](archive)
        with self.assertRaises(ValueError):
            H['i386_archive'](gcc_archive([('part.o/', good)] * 4097))

    def test_multilib_queries_require_four_exact_paths_and_validate_all_input_bytes(self):
        data = {name: gcc_archive([('part.o/', relocatable())]) if name.endswith('.a')
                else relocatable() for name in H['GCC_INPUTS']}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            def run(command, label):
                name = command[-1].removeprefix('-print-file-name=')
                self.assertEqual(command, ['/usr/bin/gcc', '-m32', '-print-file-name='+name])
                (output/(label+'.log')).write_text(str(H['GCC_MULTILIB']/name)+'\n')
            def read(path):
                self.assertEqual(path.parent, H['GCC_MULTILIB'])
                return data[path.name]
            with patch.dict(G, root_owned_bytes=read):
                records = H['multilib_inputs'](output, run)
            self.assertEqual(tuple(records), H['GCC_INPUTS'])
            for name, record in records.items():
                self.assertEqual(record['sha256'], hashlib.sha256(data[name]).hexdigest())
                self.assertEqual(record['elf32_i386_relocatable_members'], 1)
            for bad in ('crtbeginS.o\n', '/usr/lib/gcc/x86_64-linux-gnu/13/crtbeginS.o\n',
                        '/usr/lib/gcc/x86_64-linux-gnu/14/32/crtbeginS.o\n',
                        '/usr/lib/gcc/x86_64-linux-gnu/13/32/../32/crtbeginS.o\n',
                        '/usr/lib/gcc/x86_64-linux-gnu/13/32/libgcc.a\n',
                        '/private/crtbeginS.o\n', str(H['GCC_MULTILIB']/'crtbeginS.o'),
                        str(H['GCC_MULTILIB']/'crtbeginS.o')+'\nextra\n', 'x'*513):
                def rejected_run(_command, label): (output/(label+'.log')).write_text(bad)
                with self.subTest(path=bad), patch.dict(G, root_owned_bytes=Mock(side_effect=AssertionError('read'))):
                    with self.assertRaises(ValueError): H['multilib_inputs'](output, rejected_run)
            for name in H['GCC_INPUTS']:
                original = data[name]
                data[name] = gcc_archive([('foreign.o/', b'ELF64')]) if name.endswith('.a') else b'ELF64'
                with self.subTest(name=name), patch.dict(G, root_owned_bytes=read):
                    with self.assertRaises(ValueError): H['multilib_inputs'](output, run)
                data[name] = original

    def test_trusted_input_rejects_links_wrong_owner_writable_parents_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'crtbeginS.o'; path.write_bytes(relocatable())
            def metadata(current):
                mode = stat.S_IFREG | 0o644 if current == path else stat.S_IFDIR | 0o755
                return SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0, st_dev=1, st_ino=2,
                                       st_size=len(relocatable()), st_mtime_ns=1, st_ctime_ns=1)
            with patch.object(Path, 'lstat', metadata):
                self.assertEqual(H['root_owned_bytes'](path), relocatable())
            for target, field, value in ((path, 'st_uid', 1000), (path.parent, 'st_uid', 1000),
                                         (path, 'st_mode', stat.S_IFREG|0o666),
                                         (path.parent, 'st_mode', stat.S_IFDIR|0o777),
                                         (path, 'st_mode', stat.S_IFLNK|0o777),
                                         (path, 'st_size', 16*1024**2+1), (path, 'st_size', 0)):
                def changed(current):
                    result = metadata(current)
                    if current == target: setattr(result, field, value)
                    return result
                with self.subTest(target=target, field=field, value=value), patch.object(Path, 'lstat', changed):
                    with self.assertRaises(ValueError): H['root_owned_bytes'](path)
            link = Path(directory)/'link'; link.symlink_to(path)
            with self.assertRaises(ValueError): H['root_owned_bytes'](link)
            with self.assertRaises(ValueError): H['root_owned_bytes'](Path('relative'))
            visits = 0
            def unstable(current):
                nonlocal visits
                result = metadata(current)
                if current == path:
                    visits += 1
                    if visits > 2: result.st_ino = 3
                return result
            with patch.object(Path, 'lstat', unstable), self.assertRaises(ValueError):
                H['root_owned_bytes'](path)

    def test_driver_identity_records_only_existing_root_owned_gcc13(self):
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0)), \
             patch.object(Path, 'resolve', return_value=Path('/usr/bin/x86_64-linux-gnu-gcc-13')), \
             patch.dict(G, root_owned_bytes=lambda _: b'inert official driver'):
            record = H['gcc_identity']()
            self.assertEqual(record['command'], '/usr/bin/gcc')
            self.assertEqual(record['sha256'], hashlib.sha256(b'inert official driver').hexdigest())
        for resolved in ('/private/gcc-13', '/usr/bin/gcc-14'):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0)), \
                 patch.object(Path, 'resolve', return_value=Path(resolved)), \
                 patch.dict(G, root_owned_bytes=Mock(side_effect=AssertionError('read'))):
                with self.assertRaises(ValueError): H['gcc_identity']()
        with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=1000)):
            with self.assertRaises(ValueError): H['gcc_identity']()

    def test_hosted_prepare_requires_all_inputs_and_actual_probe_before_success_receipt(self):
        original = b'-isystem /usr/include/i386-linux-musl -L/usr/lib/i386-linux-musl\n'
        files = {'usr/lib/i386-linux-musl/musl-gcc.specs': original}
        driver = dict(command='/usr/bin/gcc', resolved='/usr/bin/gcc-13', bytes=5, sha256='a'*64)
        raw = bytearray(84); raw[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<H', raw, 18, 3); struct.pack_into('<I', raw, 28, 52)
        struct.pack_into('<HH', raw, 42, 32, 1); struct.pack_into('<I', raw, 52, 1)
        for failure in (None, 'query', 'compile', 'execute', 'changed-input'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)/'output'; output.mkdir()
                prefix = Path(directory)/'ctutils-musl-i386'
                calls, changed = [], False
                inputs = {name: gcc_archive([('part.o/', relocatable())]) if name.endswith('.a')
                          else relocatable() for name in H['GCC_INPUTS']}
                def run(command, label):
                    nonlocal changed
                    calls.append(label)
                    log = output/(label+'.log')
                    if label.startswith('musl-gcc-query-'):
                        name = command[-1].removeprefix('-print-file-name=')
                        log.write_text(name+'\n' if failure == 'query' else str(H['GCC_MULTILIB']/name)+'\n')
                    elif label == 'musl-probe-compile':
                        if failure == 'compile': raise subprocess.CalledProcessError(1, command)
                        (prefix/'probe').write_bytes(raw)
                    elif label == 'musl-probe-execute':
                        log.write_bytes(b'wrong\n' if failure == 'execute' else b'musl-i386-static\n')
                        changed = failure == 'changed-input'
                def read(path): return inputs[path.name] + (b'changed' if changed else b'')
                opener = Mock()
                opener.open.side_effect = lambda *args, **kwargs: io.BytesIO(b'inert package')
                environment = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                                   GITHUB_SHA='a'*40, CTUTILS_CORE_REVISION='a'*40, RUNNER_TEMP=directory)
                with patch.dict(os.environ, environment), patch.object(H['os'], 'getuid', return_value=1000), \
                     patch.object(H['urllib'].request, 'build_opener', return_value=opener), \
                     patch.dict(G, gcc_identity=lambda: driver, root_owned_bytes=read,
                                package_files=lambda *_: files, SPEC_SHA256=hashlib.sha256(original).hexdigest()):
                    if failure:
                        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                            H['prepare'](prefix, output, run)
                        self.assertFalse((output/'musl-input.log').exists())
                    else:
                        receipt = H['prepare'](prefix, output, run)
                        self.assertTrue(receipt['static_i386_probe_passed'])
                        self.assertEqual(receipt['gcc_driver'], driver)
                        self.assertEqual(tuple(receipt['gcc_multilib_inputs']), H['GCC_INPUTS'])
                        self.assertEqual(json.loads((output/'musl-input.log').read_text()), receipt)
                if failure == 'query':
                    self.assertFalse(prefix.exists())
                    opener.open.assert_not_called()
                    self.assertFalse((output/'musl-gcc-inputs.log').exists())
                elif failure == 'compile':
                    self.assertNotIn('musl-probe-execute', calls)
                else:
                    self.assertEqual(calls[-2:], ['musl-probe-compile', 'musl-probe-execute'])
                if failure != 'query':
                    observed = json.loads((output/'musl-gcc-inputs.log').read_text())
                    self.assertEqual(observed['gcc_driver'], driver)
                    self.assertEqual(set(observed['gcc_multilib_inputs']), set(H['GCC_INPUTS']))
                    self.assertFalse(observed['static_i386_probe_passed'])

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
        for offset,value in ((4,2),(5,2)):
            changed=bytearray(raw);changed[offset]=value
            with self.assertRaises(ValueError): H['static_i386'](changed)
        self.assertIn(str(0x123456789*7).encode(),H['PROBE'])


if __name__=='__main__': unittest.main()
