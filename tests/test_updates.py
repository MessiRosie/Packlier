import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import sysconfig
from urllib.error import URLError
from zipfile import ZipFile

import pytest

from packlier import updates


CURRENT = "0.1.1"
TARGET = "0.1.2"


@pytest.fixture(autouse=True)
def reset_restart_state(monkeypatch):
    monkeypatch.setattr(updates, "_RESTART_MESSAGE", None)


def make_wheel(directory, version=TARGET, requirements=(), python_requirement=">=3.10", name="Packlier"):
    package = Path(updates.__file__).parent
    entries = {f"packlier/{source.name}": source.read_bytes() for source in package.glob("*.py")}
    entries["packlier/__init__.py"] = re.sub(
        rb'__version__ = "[^"]+"', f'__version__ = "{version}"'.encode(), entries["packlier/__init__.py"]
    )
    dist_info = f"packlier-{version}.dist-info"
    info = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nRequires-Python: {python_requirement}\n"
    info += "".join(f"Requires-Dist: {requirement}\n" for requirement in requirements)
    entries[f"{dist_info}/METADATA"] = info.encode()
    entries[f"{dist_info}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: Packlier-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = io.StringIO()
    writer = csv.writer(record)
    for filename, content in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        writer.writerow([filename, f"sha256={digest}", len(content)])
    writer.writerow([f"{dist_info}/RECORD", "", ""])
    entries[f"{dist_info}/RECORD"] = record.getvalue().encode()
    path = directory / f"packlier-{version}-py3-none-any.whl"
    with ZipFile(path, "w") as archive:
        for filename, content in entries.items():
            archive.writestr(filename, content)
    payload = path.read_bytes()
    release = updates._Release(
        version,
        f"https://github.com/{updates.REPOSITORY}/releases/download/v{version}/{path.name}",
        hashlib.sha256(payload).hexdigest(), len(payload),
    )
    return path, release


def release_json(version=TARGET, **changes):
    name = f"packlier-{version}-py3-none-any.whl"
    result = {
        "tag_name": f"v{version}", "draft": False, "prerelease": False,
        "assets": [{"name": name, "size": 100, "digest": "sha256:" + "a" * 64,
                    "browser_download_url": f"https://github.com/{updates.REPOSITORY}/releases/download/v{version}/{name}"}],
    }
    result.update(changes)
    return result


def test_patch_selection_and_fixed_origin(monkeypatch):
    releases = [release_json("0.1.0"), release_json("0.1.3"), release_json(),
                release_json("0.2.0"), release_json("1.0.0"),
                release_json("0.1.9", draft=True), release_json("0.1.8", prerelease=True)]
    seen = []

    def read(url, limit, timeout):
        seen.append(url)
        return json.dumps(releases).encode()

    monkeypatch.setattr(updates, "_read_url", read)
    assert updates._fetch_release(CURRENT).version == "0.1.3"
    assert seen == ["https://api.github.com/repos/MessiRosie/Packlier/releases?per_page=100"]


@pytest.mark.parametrize("field,value", [
    ("digest", None), ("digest", "sha256:wrong"), ("size", 0),
    ("size", updates.MAX_WHEEL_BYTES + 1),
    ("browser_download_url", "https://github.com/another/project/releases/download/v0.1.2/wheel.whl"),
    ("name", "packlier-0.1.2.tar.gz"),
])
def test_untrusted_or_invalid_assets_are_ignored(monkeypatch, field, value):
    release = release_json()
    release["assets"][0][field] = value
    monkeypatch.setattr(updates, "_read_url", lambda *args: json.dumps([release]).encode())
    assert updates._fetch_release(CURRENT) is None


def test_prerelease_installation_not_updated(monkeypatch):
    monkeypatch.setattr(updates, "_read_url", lambda *args: json.dumps([release_json()]).encode())
    assert updates._fetch_release("0.1.1rc1") is None


@pytest.mark.parametrize("url", ["http://github.com/a", "https://evil.example/a", "https://github.com.evil.example/a", "https://user:secret@github.com/a"])
def test_untrusted_url_and_redirect_rejected(url):
    assert not updates._allowed_url(url)
    with pytest.raises(updates._CheckFailed):
        updates._read_url(url, 10, 1)
    with pytest.raises(updates._CheckFailed):
        updates._TrustedRedirect().redirect_request(None, None, 302, "", {}, url)


def test_download_verifies_digest_and_metadata(tmp_path, monkeypatch):
    wheel, release = make_wheel(tmp_path)
    monkeypatch.setattr(updates, "_read_url", lambda *args: wheel.read_bytes())
    destination = tmp_path / "download"
    destination.mkdir()
    assert updates._download_wheel(release, destination).read_bytes() == wheel.read_bytes()
    monkeypatch.setattr(updates, "_read_url", lambda *args: b"tampered")
    with pytest.raises(updates._CheckFailed, match="SHA-256"):
        updates._download_wheel(release, destination)


@pytest.mark.parametrize("kwargs", [
    {"python_requirement": ">=99"}, {"name": "Not-Packlier"},
    {"requirements": ["definitely-missing-packlier-test-dependency>=1"]},
    {"requirements": ["numpy>=999"]},
    {"requirements": ["numpy @ https://evil.example/numpy.whl"]},
])
def test_incompatible_wheel_never_reaches_pip(tmp_path, kwargs):
    wheel, release = make_wheel(tmp_path, **kwargs)
    with pytest.raises(updates._CheckFailed):
        updates._validate_wheel(wheel, release)


def test_optional_dependencies_and_valid_dependencies(tmp_path):
    wheel, release = make_wheel(tmp_path, requirements=["numpy>=1.26", "gmpy2>=2.1; extra == 'fast'"])
    updates._validate_wheel(wheel, release)


def test_wheel_traversal_rejected(tmp_path):
    wheel, release = make_wheel(tmp_path)
    with ZipFile(wheel, "a") as archive:
        archive.writestr("../outside.py", "bad")
    with pytest.raises(updates._CheckFailed, match="paths"):
        updates._validate_wheel(wheel, release)


@pytest.mark.parametrize("payload", [b'__version__ = "0.1.0"\n', b"invalid python !\n"])
def test_initializer_must_match_release(tmp_path, payload):
    wheel, release = make_wheel(tmp_path)
    with ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["packlier/__init__.py"] = payload
    with ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    with pytest.raises(updates._CheckFailed):
        updates._validate_wheel(wheel, release)


def test_network_response_limit(monkeypatch):
    class FakeOpener:
        def open(self, *args, **kwargs):
            return io.BytesIO(b"abcdef")

    monkeypatch.setattr(updates, "build_opener", lambda *args: FakeOpener())
    with pytest.raises(updates._CheckFailed, match="size limit"):
        updates._read_url(updates.RELEASES_URL, limit=5, timeout=2)
    assert updates._read_url(updates.RELEASES_URL, limit=6, timeout=2) == b"abcdef"


def test_network_deadline(monkeypatch):
    class FakeOpener:
        def open(self, *args, **kwargs):
            return io.BytesIO(b"abcdef")

    times = iter([0, 3])
    monkeypatch.setattr(updates, "build_opener", lambda *args: FakeOpener())
    monkeypatch.setattr(updates.time, "monotonic", lambda: next(times))
    with pytest.raises(updates._CheckFailed, match="timed out"):
        updates._read_url(updates.RELEASES_URL, limit=10, timeout=2)


@pytest.fixture
def managed(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKLIER_AUTO_UPDATE", "on")
    monkeypatch.setattr(updates, "_installation", lambda *args: tmp_path)
    monkeypatch.setattr(updates.metadata, "version", lambda *args: CURRENT)
    monkeypatch.setattr(updates, "_fetch_release", lambda *args: None)
    return tmp_path


def test_import_without_update_runs_body(managed):
    with updates.import_update_guard(CURRENT, "unused"):
        assert (managed / ".packlier-update.lock").exists()


@pytest.mark.parametrize("setting", ["off", "0", "false", "no"])
def test_opt_out_never_checks_installation(monkeypatch, setting):
    monkeypatch.setenv("PACKLIER_AUTO_UPDATE", setting)

    def forbidden(*args):
        raise AssertionError("opt-out performed I/O")

    monkeypatch.setattr(updates, "_installation", forbidden)
    with updates.import_update_guard(CURRENT, "unused"):
        pass


@pytest.mark.parametrize("error", [URLError("offline"), TimeoutError("slow"), ValueError("invalid JSON"), updates._CheckFailed("bad hash")])
def test_preinstall_failure_keeps_import_working(managed, monkeypatch, error):
    def fail(*args):
        raise error

    monkeypatch.setattr(updates, "_fetch_release", fail)
    with pytest.warns(updates.PacklierUpdateWarning, match="using current version"):
        with updates.import_update_guard(CURRENT, "unused"):
            assert not (managed / ".packlier-update-state.json").exists()


def test_api_import_exception_is_not_swallowed(managed):
    with pytest.raises(ValueError, match="core API failure"):
        with updates.import_update_guard(CURRENT, "unused"):
            raise ValueError("core API failure")


def test_changed_installation_requires_restart(managed, monkeypatch):
    monkeypatch.setattr(updates.metadata, "version", lambda *args: TARGET)
    with pytest.raises(updates.PacklierUpdatedRestartRequired):
        with updates.import_update_guard(CURRENT, "unused"):
            pytest.fail("loaded stale API")
    with pytest.raises(updates.PacklierUpdatedRestartRequired):
        with updates.import_update_guard(TARGET, "unused"):
            pytest.fail("retry in the same process was allowed")


@pytest.mark.parametrize("state", ["failed", "installing", "unknown"])
def test_interrupted_installation_blocks_next_import(managed, state):
    (managed / ".packlier-update-state.json").write_text(json.dumps({"status": state, "target": TARGET}))
    with pytest.raises(updates.PacklierUpdateError):
        with updates.import_update_guard(CURRENT, "unused"):
            pytest.fail("used possibly damaged installation")


def test_success_marker_cleared_on_fresh_import(managed):
    state = managed / ".packlier-update-state.json"
    state.write_text(json.dumps({"status": "complete", "target": CURRENT}))
    with updates.import_update_guard(CURRENT, "unused"):
        assert not state.exists()


def test_installer_is_isolated_and_requires_restart(tmp_path, monkeypatch):
    wheel, release = make_wheel(tmp_path)
    marker = tmp_path / "state.json"
    seen = []
    monkeypatch.setenv("PIP_TARGET", "/untrusted/target")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/modules")
    monkeypatch.setattr(updates.metadata, "version", lambda *args: TARGET)

    def run(command, **kwargs):
        assert json.loads(marker.read_text())["status"] == "installing"
        seen.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(updates.subprocess, "run", run)
    with pytest.raises(updates.PacklierUpdatedRestartRequired, match="restart"):
        updates._install_wheel(wheel, release, CURRENT, marker)
    command, kwargs = seen[0]
    assert command[:4] == [sys.executable, "-I", "-m", "pip"]
    assert all(flag in command for flag in ["--no-deps", "--no-index", "--prefix"])
    assert "PIP_TARGET" not in kwargs["env"] and "PYTHONPATH" not in kwargs["env"]
    assert kwargs["env"]["PACKLIER_AUTO_UPDATE"] == "off"
    assert json.loads(marker.read_text())["status"] == "complete"


@pytest.mark.parametrize("failure", ["exit", "timeout", "interrupt"])
def test_failed_install_is_fatal_and_recorded(tmp_path, monkeypatch, failure):
    wheel, release = make_wheel(tmp_path)
    marker = tmp_path / "state.json"

    def run(command, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        if failure == "interrupt":
            raise KeyboardInterrupt()
        return subprocess.CompletedProcess(command, 1, "", "simulated failure")

    monkeypatch.setattr(updates.subprocess, "run", run)
    with pytest.raises(updates.PacklierUpdateError, match="repair"):
        updates._install_wheel(wheel, release, CURRENT, marker)
    assert json.loads(marker.read_text())["status"] == "failed"


def test_lock_prevents_concurrent_import_update(tmp_path):
    lock_path = tmp_path / "lock"
    script = """
import sys
from packlier.updates import _FileLock, PacklierUpdateError
try:
    with _FileLock(sys.argv[1], timeout=0.1):
        sys.exit(3)
except PacklierUpdateError:
    print('blocked')
"""
    with updates._FileLock(lock_path):
        result = subprocess.run([sys.executable, "-c", script, str(lock_path)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "blocked"
    with updates._FileLock(lock_path, timeout=0.1):
        pass


def test_source_checkout_is_not_updated(monkeypatch, tmp_path):
    assert updates._installation(tmp_path / "src/packlier/__init__.py") is None


def test_editable_installation_is_not_updated(monkeypatch, tmp_path):
    class Distribution:
        def locate_file(self, name):
            return tmp_path / name

        def read_text(self, name):
            return '{"dir_info": {"editable": true}}'

    monkeypatch.setattr(updates.metadata, "distribution", lambda name: Distribution())
    assert updates._installation(tmp_path / "packlier/__init__.py") is None


def test_lock_permission_failure_does_not_install(managed, monkeypatch):
    def denied(*args):
        raise PermissionError("read-only environment")

    monkeypatch.setattr(updates._FileLock, "__enter__", denied)
    monkeypatch.setattr(updates, "_maybe_update", lambda *args: pytest.fail("installation attempted"))
    with pytest.warns(updates.PacklierUpdateWarning, match="lock"):
        with updates.import_update_guard(CURRENT, "unused"):
            pass


def test_real_import_upgrade_in_disposable_environment(tmp_path):
    initial, _ = make_wheel(tmp_path, version=CURRENT, requirements=["numpy>=1.26", "phe>=1.5", "packaging>=24"])
    target, _ = make_wheel(tmp_path, version=TARGET, requirements=["numpy>=1.26", "phe>=1.5", "packaging>=24"])
    environment = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(environment)], check=True, capture_output=True)
    interpreter = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(interpreter), "-m", "pip", "--isolated", "--disable-pip-version-check", "install", "--no-index", "--no-deps", "--ignore-installed", str(initial)], check=True, capture_output=True)
    root = Path(subprocess.check_output([str(interpreter), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], text=True).strip())
    (root / "test-dependencies.pth").write_text(sysconfig.get_paths()["purelib"] + "\n", encoding="utf-8")
    bootstrap = """
import importlib.util, pathlib, sys
module_path = pathlib.Path(sys.argv[1]) / 'packlier/updates.py'
spec = importlib.util.spec_from_file_location('packlier.updates', module_path)
updater = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = updater
spec.loader.exec_module(updater)
"""
    first = bootstrap + """
import hashlib, json
payload = pathlib.Path(sys.argv[2]).read_bytes()
name = 'packlier-0.1.2-py3-none-any.whl'
releases = [{'tag_name': 'v0.1.2', 'draft': False, 'prerelease': False,
             'assets': [{'name': name, 'size': len(payload),
                         'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
                         'browser_download_url': f'https://github.com/{updater.REPOSITORY}/releases/download/v0.1.2/{name}'}]}]
updater._read_url = lambda url, limit, timeout: json.dumps(releases).encode() if url == updater.RELEASES_URL else payload
try:
    import packlier
except updater.PacklierUpdatedRestartRequired:
    assert 'packlier.paillier' not in sys.modules
    assert updater.metadata.version('Packlier') == '0.1.2'
    print('updated-and-stopped')
else:
    raise AssertionError('did not stop after updating')
"""
    child_environment = {**os.environ, "PACKLIER_AUTO_UPDATE": "on"}
    child_environment.pop("PYTHONPATH", None)
    result = subprocess.run([str(interpreter), "-I", "-c", first, str(root), str(target)], env=child_environment, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "updated-and-stopped" in result.stdout
    second = bootstrap + """
updater._read_url = lambda *args: b'[]'
from packlier import generate_paillier_keypair, __version__
assert __version__ == '0.1.2'
public, private = generate_paillier_keypair(128)
assert private.decrypt(public.encrypt(42)) == 42
assert not (pathlib.Path(sys.argv[1]) / '.packlier-update-state.json').exists()
print('fresh-process-works')
"""
    result = subprocess.run([str(interpreter), "-I", "-c", second, str(root)], env=child_environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fresh-process-works" in result.stdout
