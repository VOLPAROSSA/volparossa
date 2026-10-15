# SPDX-License-Identifier: GPL-3.0-only
"""Real tiny hashes and descriptor lifetimes, never models or cache reclamation."""
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import llama_cpu as native
from test_llama_cpu import WORKER, controlled_pipe, control, manifest, source_fixture


def fixture(root):
    selected, profile = source_fixture(root)
    for path in Path(selected['model_root']).iterdir():
        path.chmod(0o600)
    return selected, profile


def bundle(root, selected, template):
    root.mkdir(mode=0o700)
    value = manifest()
    for field, raw in (('library', b'inert library bytes'), ('gguf', b'inert GGUF bytes')):
        (root / value[field]['path']).write_bytes(raw)
        value[field].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    provenance = dict(version=2, abi_version=1, kind=native.KIND, source_commit=native.SOURCE,
        source_tree=native.SOURCE_TREE, source_overlay=native.loader_provenance(),
        loader_compile_source_verified=True, upstream_original_unchanged=True,
        cpu='avx2_fma_f16c', library=value['library'], provisionable=True,
        sanitizers=False, quantization=False)
    raw = json.dumps(provenance).encode()
    (root / 'build.json').write_bytes(raw)
    value['build_manifest_sha256'] = hashlib.sha256(raw).hexdigest()
    value['verification']['chat_template_sha256'] = hashlib.sha256(template.encode()).hexdigest()
    raw = json.dumps(value).encode()
    (root / 'backend.json').write_bytes(raw)
    selected.update(native_backend_root=str(root), native_backend_sha256=hashlib.sha256(raw).hexdigest())


@contextlib.contextmanager
def prepared():
    with tempfile.TemporaryDirectory() as directory:
        selected, profile = fixture(Path(directory))
        with mock.patch.object(WORKER, 'model_profile', return_value=profile):
            with WORKER.NativeSourceCache(selected) as cache:
                result = WORKER.prepare_files(selected, initial_source={}, source_cache=cache)
                yield cache, selected, profile, result


class NativeSourceLifecycleTests(unittest.TestCase):
    def assert_closed(self, descriptors):
        for descriptor in descriptors:
            with self.assertRaises(OSError) as error:
                os.fstat(descriptor)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def test_real_execute_hash_chain_advises_only_verified_shards_before_backend_and_gguf(self):
        self.execute_chain()

    def test_real_execute_keeps_result_when_advice_is_unavailable(self):
        for error in (OSError(errno.EPERM, 'private error'), AttributeError('unsupported')):
            with self.subTest(error=type(error).__name__):
                self.execute_chain(error)

    def execute_chain(self, advice_error=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected, profile = fixture(root)
            template = 'inert template'
            bundle(root / 'native', selected, template)
            events, descriptors, flags = [], [], []
            tokenizer = SimpleNamespace(pad_token_id=151643, eos_token_id=151645, chat_template=template)
            transformers = SimpleNamespace(AutoTokenizer=SimpleNamespace(from_pretrained=lambda *a, **k: tokenizer))
            original_hash, original_open = WORKER.file_hash, os.open

            def hashed(path, *args, **kwargs):
                value = original_hash(path, *args, **kwargs)
                events.append(('hashed', path.name))
                return value

            def opened(path, bits, *args, **kwargs):
                flags.append((Path(path).name, bits))
                return original_open(path, bits, *args, **kwargs)

            def advise(descriptor, offset, size, hint):
                name = next(name for name in profile['weight_shards']
                            if (root / 'source' / name).stat().st_ino == os.fstat(descriptor).st_ino)
                events.append(('advised', name))
                descriptors.append(descriptor)
                self.assertEqual((offset, size, hint), (0, profile['files'][name], os.POSIX_FADV_DONTNEED))
                self.assertFalse(os.get_inheritable(descriptor))
                self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), size)
                if advice_error is not None:
                    raise advice_error

            def load_backend(*args):
                events.append(('backend', 'begin'))
                self.assert_closed(descriptors)
                return mock.Mock(), transformers, mock.Mock(), {}

            def execute(request, session, token, *_args, **kwargs):
                self.assertEqual(kwargs['initial_source_weights'], profile['weights'])
                _, value, _ = native.verified_bundle(request, WORKER, token, session)
                self.assertEqual(value['gguf']['bytes'], len(b'inert GGUF bytes'))
                return 'inert bundle verified; no library loaded'

            session = mock.Mock()
            with mock.patch.object(WORKER, 'model_profile', return_value=profile), \
                    mock.patch.object(WORKER, 'file_hash', side_effect=hashed), \
                    mock.patch.object(WORKER.os, 'open', side_effect=opened), \
                    mock.patch.object(WORKER.os, 'posix_fadvise', side_effect=advise), \
                    mock.patch.object(WORKER, 'configure_offline'), \
                    mock.patch.object(WORKER, 'load_backend', side_effect=load_backend), \
                    mock.patch.dict(WORKER.sys.modules, {'volparossa_llama_cpu': SimpleNamespace(execute=execute)}), \
                    mock.patch.object(native.ctypes, 'CDLL', side_effect=AssertionError('no native loading')):
                self.assertEqual(WORKER.execute_job(selected, session), 'inert bundle verified; no library loaded')
            source_events = [('hashed', name) for name in profile['files']]
            self.assertCountEqual(events[:len(source_events)], source_events)
            self.assertEqual(events[len(source_events):],
                [('advised', name) for name in profile['weight_shards']]
                + [('backend', 'begin'), ('hashed', native.LIBRARY), ('hashed', 'model.gguf')])
            self.assertEqual(len(descriptors), 3)
            for name, bits in flags:
                if name in profile['weight_shards']:
                    self.assertEqual(bits & (os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC),
                                     os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)

    def test_hash_config_and_dataset_failures_never_advise_and_close_retained_fds(self):
        for failure in ('individual', 'aggregate', 'config', 'dataset', 'missing', 'symlink', 'fifo'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                selected, profile = fixture(Path(directory))
                if failure == 'individual':
                    path = Path(selected['model_root']) / profile['weight_shards'][-1]
                    path.write_bytes(b'x' * path.stat().st_size)
                elif failure == 'aggregate':
                    profile['weights']['sha256'] = '0' * 64
                elif failure == 'config':
                    path = Path(selected['model_root']) / 'config.json'
                    path.write_bytes(b'{"auto_map":{}}')
                    profile['files'][path.name] = path.stat().st_size
                    profile['hashes'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
                elif failure == 'dataset':
                    Path(selected['dataset_path']).write_bytes(b'[]')
                else:
                    path = Path(selected['model_root']) / profile['weight_shards'][-1]
                    path.unlink()
                    if failure == 'symlink': path.symlink_to(Path(selected['model_root']) / profile['weight_shards'][0])
                    if failure == 'fifo': os.mkfifo(path, 0o600)
                with mock.patch.object(WORKER, 'model_profile', return_value=profile), \
                        mock.patch.object(WORKER.os, 'posix_fadvise') as advice:
                    cache = WORKER.NativeSourceCache(selected)
                    descriptors = []
                    with self.assertRaises((WORKER.JobError, OSError)), cache:
                        try:
                            WORKER.prepare_files(selected, initial_source={}, source_cache=cache)
                        finally:
                            descriptors = [cache.parent] + [entry[0] for entry in cache.shards]
                            self.assertFalse(cache.prepared)
                        cache.advise(mock.Mock())
                    advice.assert_not_called()
                    self.assert_closed(descriptors)

    def test_pending_cancel_and_deadline_propagate_without_advice_or_reset(self):
        for failure in ('cancel', 'deadline'):
            with self.subTest(failure=failure), prepared() as (cache, *_), \
                    controlled_pipe() as (session, writer, _), \
                    mock.patch.object(WORKER.os, 'posix_fadvise') as advice:
                started = session.started
                if failure == 'cancel':
                    os.write(writer, control(1, 'cancel'))
                    elapsed = 0
                else:
                    elapsed = session.request['max_seconds'] * 1000 + 1
                with mock.patch.object(session, 'elapsed', return_value=elapsed), \
                        self.assertRaisesRegex(WORKER.JobError, 'JOB_CANCELLED|JOB_DEADLINE_EXCEEDED'):
                    cache.advise(session)
                self.assertEqual(session.started, started)
                advice.assert_not_called()

    def test_success_uses_exactly_three_once_and_advice_errors_do_not_replace_result(self):
        for failure in (None, OSError(errno.EPERM, 'private exception must not be exported'), AttributeError('unsupported')):
            with self.subTest(failure=type(failure).__name__), prepared() as (cache, _, _, result), \
                    mock.patch.object(WORKER.os, 'posix_fadvise', side_effect=failure) as advice:
                original = result
                cache.advise(mock.Mock())
                cache.advise(mock.Mock())
                self.assertIs(result, original)
                self.assertEqual(advice.call_count, 3)

    def test_incomplete_verification_cannot_advise_even_with_three_descriptors(self):
        with prepared() as (cache, *_), mock.patch.object(WORKER.os, 'posix_fadvise') as advice:
            cache.prepared = False
            self.assertEqual(len(cache.shards), 3)
            cache.advise(mock.Mock())
            advice.assert_not_called()

    def test_changed_file_parent_mode_link_or_inventory_prevents_advice(self):
        for mutation in ('replace', 'rewrite', 'symlink', 'hardlink', 'mode', 'parent_mode', 'parent_replace', 'extra'):
            with self.subTest(mutation=mutation), prepared() as (cache, selected, profile, _), \
                    mock.patch.object(WORKER.os, 'posix_fadvise') as advice:
                root = Path(selected['model_root'])
                path = root / profile['weight_shards'][0]
                if mutation == 'replace':
                    raw = path.read_bytes()
                    path.unlink()
                    path.write_bytes(raw)
                    path.chmod(0o600)
                elif mutation == 'rewrite':
                    # Metadata binding, not a second content read; make the
                    # identity change deterministic even on coarse-time filesystems.
                    path.write_bytes(b'x' * (path.stat().st_size + 1))
                elif mutation == 'symlink':
                    path.unlink()
                    path.symlink_to(root / profile['weight_shards'][1])
                elif mutation == 'hardlink':
                    os.link(path, root.parent / 'extra-link')
                elif mutation == 'mode':
                    path.chmod(0o644)
                elif mutation == 'parent_mode':
                    root.chmod(0o755)
                elif mutation == 'parent_replace':
                    root.rename(root.parent / 'old-source')
                    root.mkdir(mode=0o700)
                else:
                    (root / 'extra').write_bytes(b'not in the fixed inventory')
                cache.advise(mock.Mock())
                advice.assert_not_called()

    def test_unsafe_binding_skips_advice_without_weakening_existing_validation(self):
        for mutation in ('file_mode', 'parent_mode', 'foreign_file', 'foreign_parent'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                selected, profile = fixture(Path(directory))
                root = Path(selected['model_root'])
                path = root / profile['weight_shards'][0]
                if mutation == 'file_mode': path.chmod(0o644)
                if mutation == 'parent_mode': root.chmod(0o755)
                foreign_inode = (path if mutation == 'foreign_file' else root).stat().st_ino
                real_fstat, real_lstat = os.fstat, Path.lstat

                def metadata(info):
                    if mutation.startswith('foreign') and info.st_ino == foreign_inode:
                        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                        return SimpleNamespace(**dict({name: getattr(info, name) for name in fields}, st_uid=os.geteuid()+1))
                    return info

                with mock.patch.object(WORKER, 'model_profile', return_value=profile), \
                        mock.patch.object(WORKER.os, 'fstat', side_effect=lambda fd: metadata(real_fstat(fd))), \
                        mock.patch.object(Path, 'lstat', lambda path: metadata(real_lstat(path))), \
                        mock.patch.object(WORKER.os, 'posix_fadvise') as advice:
                    with WORKER.NativeSourceCache(selected) as cache:
                        result = WORKER.prepare_files(selected, initial_source={}, source_cache=cache)
                        cache.advise(mock.Mock())
                        self.assertEqual(result[4][profile['weight_shards'][0]]['sha256'], profile['hashes'][profile['weight_shards'][0]])
                    advice.assert_not_called()

    def test_original_non_native_prepare_does_not_open_or_advise_retained_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            selected, profile = fixture(Path(directory))
            for name in ('inference_backend', 'native_backend_root', 'native_backend_sha256'):
                del selected[name]
            with mock.patch.object(WORKER, 'model_profile', return_value=profile), \
                    mock.patch.object(WORKER.os, 'dup', side_effect=AssertionError('legacy must not retain')), \
                    mock.patch.object(WORKER.os, 'posix_fadvise', side_effect=AssertionError('legacy must not advise')):
                self.assertEqual(len(WORKER.prepare_files(selected)), 5)

    def test_close_error_does_not_mask_original_failure_or_skip_remaining_descriptors(self):
        owned, closed = [], []
        original_close = os.close

        def close(descriptor):
            original_close(descriptor)
            if descriptor in owned and descriptor not in closed:
                closed.append(descriptor)
                if len(closed) == 1:
                    raise OSError(errno.EIO, 'close may already have released the descriptor')

        with mock.patch.object(WORKER.os, 'close', side_effect=close):
            with self.assertRaisesRegex(WORKER.JobError, '^ORIGINAL_FAILURE$'):
                with prepared() as (cache, *_):
                    owned.extend([cache.parent] + [entry[0] for entry in cache.shards])
                    raise WORKER.JobError('ORIGINAL_FAILURE')
        self.assertCountEqual(closed, owned)
        self.assert_closed(owned)

    def test_failed_dup_is_not_retried_or_a_new_verification_failure(self):
        with mock.patch.object(WORKER.os, 'dup', side_effect=OSError(errno.EMFILE, 'bounded failure')) as duplicate, \
                mock.patch.object(WORKER.os, 'posix_fadvise') as advice, prepared() as (cache, _, _, result):
            self.assertEqual(len(result), 5)
            self.assertEqual(duplicate.call_count, 1)
            self.assertEqual(cache.shards, [])
            cache.advise(mock.Mock())
            advice.assert_not_called()

    def test_scope_rejected_before_any_new_file_access(self):
        with tempfile.TemporaryDirectory() as directory:
            selected, _ = fixture(Path(directory))
            for change in ({'inference_backend': None}, {'mode': 'train'}, {'model_profile': WORKER.QWEN_MODEL_PROFILE}):
                with self.subTest(change=change), \
                        mock.patch.object(WORKER.os, 'open', side_effect=AssertionError('no files before scope')), \
                        self.assertRaisesRegex(WORKER.JobError, '^NATIVE_SOURCE_PROVENANCE$'):
                    WORKER.NativeSourceCache(dict(selected, **change))


if __name__ == '__main__':
    unittest.main()
