"""Import-time updates from a fixed GitHub repository, before loading the API."""

from contextlib import contextmanager
from dataclasses import dataclass
from email.parser import BytesParser
import ast
import hashlib
import importlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import sysconfig
import tempfile
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import warnings
from zipfile import BadZipFile, ZipFile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version


REPOSITORY = "MessiRosie/Packlier"
RELEASES_URL = f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=100"
MAX_WHEEL_BYTES = 20 * 1024 * 1024
CHECK_TIMEOUT = 2.0
DOWNLOAD_TIMEOUT = 30.0
LOCK_TIMEOUT = 15.0
INSTALL_TIMEOUT = 180.0
_RESTART_MESSAGE = None
_ALLOWED_HOSTS = frozenset({
    "api.github.com", "github.com", "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
})


class PacklierUpdateError(ImportError):
    """Import stopped because an update may have changed this installation."""


class PacklierUpdatedRestartRequired(PacklierUpdateError):
    """An update succeeded; rerun the program or restart the notebook kernel."""


class PacklierUpdateWarning(RuntimeWarning):
    """An update check was skipped or failed before installation started."""


class _CheckFailed(Exception):
    pass


@dataclass(frozen=True)
class _Release:
    version: str
    url: str
    digest: str
    size: int


def _warn(message):
    warnings.warn(f"Packlier auto-update: {message}", PacklierUpdateWarning, stacklevel=3)


def _restart(message):
    global _RESTART_MESSAGE
    _RESTART_MESSAGE = message
    raise PacklierUpdatedRestartRequired(message)


def _allowed_url(url):
    parsed = urlsplit(url)
    return (
        parsed.scheme == "https" and parsed.hostname in _ALLOWED_HOSTS
        and parsed.port in (None, 443) and parsed.username is None
        and parsed.password is None
    )


class _TrustedRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if not _allowed_url(newurl):
            raise _CheckFailed("refused an untrusted download redirect")
        return super().redirect_request(request, response, code, message, headers, newurl)


def _read_url(url, limit, timeout):
    if not _allowed_url(url):
        raise _CheckFailed("refused an untrusted update URL")
    request = Request(url, headers={
        "User-Agent": "Packlier-import-updater",
        "Accept": "application/vnd.github+json" if url.startswith("https://api.github.com/") else "application/octet-stream",
    })
    deadline = time.monotonic() + timeout
    with build_opener(_TrustedRedirect()).open(request, timeout=min(timeout, 5.0)) as response:
        chunks = []
        size = 0
        reader = getattr(response, "read1", response.read)
        while True:
            if time.monotonic() >= deadline:
                raise _CheckFailed("update request timed out")
            chunk = reader(min(65536, limit - size + 1))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise _CheckFailed("update response exceeded its size limit")


def _fetch_release(current):
    releases = json.loads(_read_url(RELEASES_URL, 2 * 1024 * 1024, CHECK_TIMEOUT))
    if not isinstance(releases, list):
        raise _CheckFailed("invalid GitHub releases response")
    installed = Version(current)
    if installed.is_prerelease or installed.is_devrelease or installed.local:
        return None
    candidates = []
    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name", "")
        if not isinstance(tag, str) or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            continue
        version = Version(tag[1:])
        if version <= installed or version.release[:2] != installed.release[:2]:
            continue
        name = f"packlier-{version}-py3-none-any.whl"
        url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        assets = release.get("assets", [])
        if not isinstance(assets, list):
            continue
        for asset in assets:
            if not isinstance(asset, dict) or asset.get("name") != name:
                continue
            digest, size = asset.get("digest"), asset.get("size")
            if (
                asset.get("browser_download_url") == url
                and isinstance(digest, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                and isinstance(size, int) and 0 < size <= MAX_WHEEL_BYTES
            ):
                candidates.append(_Release(str(version), url, digest[7:], size))
    return max(candidates, key=lambda item: Version(item.version), default=None)


def _validate_wheel(path, release):
    with ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any(
            name.startswith("/") or ".." in name.split("/") or "\\" in name
            for name in names
        ):
            raise _CheckFailed("invalid wheel paths")
        if sum(item.file_size for item in archive.infolist()) > MAX_WHEEL_BYTES:
            raise _CheckFailed("unpacked wheel exceeds its size limit")
        expected = f"packlier-{release.version}.dist-info/METADATA"
        if [name for name in names if name.endswith(".dist-info/METADATA")] != [expected]:
            raise _CheckFailed("unexpected wheel distribution metadata")
        if "packlier/__init__.py" not in names:
            raise _CheckFailed("wheel is missing the Packlier package")
        try:
            initializer = ast.parse(archive.read("packlier/__init__.py"))
        except (SyntaxError, ValueError) as error:
            raise _CheckFailed("invalid package initializer") from error
        versions = [
            node.value.value for node in initializer.body
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
        ]
        if versions != [release.version]:
            raise _CheckFailed("package initializer version does not match the release")
        wheel_metadata = f"packlier-{release.version}.dist-info/WHEEL"
        if wheel_metadata not in names:
            raise _CheckFailed("wheel is missing its format metadata")
        wheel_info = BytesParser().parsebytes(archive.read(wheel_metadata))
        if (
            wheel_info.get("Wheel-Version") != "1.0"
            or wheel_info.get("Root-Is-Purelib", "").lower() != "true"
            or wheel_info.get_all("Tag") != ["py3-none-any"]
        ):
            raise _CheckFailed("automatic updates require a universal pure-Python wheel")
        info = BytesParser().parsebytes(archive.read(expected))
        if canonicalize_name(info.get("Name", "")) != "packlier" or info.get("Version") != release.version:
            raise _CheckFailed("wheel name/version does not match the release")
        python_constraint = info.get("Requires-Python", "")
        if Version(".".join(map(str, sys.version_info[:3]))) not in SpecifierSet(python_constraint):
            raise _CheckFailed("the new version requires a different Python version")
        for text in info.get_all("Requires-Dist", []):
            requirement = Requirement(text)
            environment = {**default_environment(), "extra": ""}
            if requirement.marker and not requirement.marker.evaluate(environment):
                continue
            if requirement.url:
                raise _CheckFailed("automatic updates do not accept direct-URL dependencies")
            try:
                version = metadata.version(requirement.name)
            except metadata.PackageNotFoundError as error:
                raise _CheckFailed(f"install dependency {requirement.name} manually first") from error
            if version not in requirement.specifier:
                raise _CheckFailed(f"update dependency {requirement.name} manually first")


def _download_wheel(release, directory):
    payload = _read_url(release.url, MAX_WHEEL_BYTES, DOWNLOAD_TIMEOUT)
    if len(payload) != release.size or hashlib.sha256(payload).hexdigest() != release.digest:
        raise _CheckFailed("wheel size or SHA-256 verification failed")
    path = Path(directory) / f"packlier-{release.version}-py3-none-any.whl"
    path.write_bytes(payload)
    _validate_wheel(path, release)
    return path


def _installation(package_file):
    try:
        distribution = metadata.distribution("Packlier")
    except metadata.PackageNotFoundError:
        return None
    installed_file = Path(distribution.locate_file("packlier/__init__.py")).resolve()
    if installed_file != Path(package_file).resolve():
        return None
    direct_url = distribution.read_text("direct_url.json")
    if direct_url and json.loads(direct_url).get("dir_info", {}).get("editable"):
        return None
    root = installed_file.parent.parent
    paths = sysconfig.get_paths()
    if root not in {Path(paths[name]).resolve() for name in ("purelib", "platlib")}:
        _warn("nonstandard/user-site installation; skipping automatic installation")
        return None
    if sys.prefix == sys.base_prefix and (Path(paths["stdlib"]) / "EXTERNALLY-MANAGED").exists():
        _warn("externally managed Python; use a virtual environment for automatic updates")
        return None
    return root


class _FileLock:
    def __init__(self, path, timeout=LOCK_TIMEOUT):
        self.path = path
        self.timeout = timeout
        self.stream = None

    def __enter__(self):
        self.stream = open(self.path, "a+b")
        if os.name == "nt":
            self.stream.seek(0, os.SEEK_END)
            if not self.stream.tell():
                self.stream.write(b"0")
                self.stream.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.stream.seek(0)
                    msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    self.stream.close()
                    raise PacklierUpdateError("Another Packlier import/update holds the lock; retry later.") from None
                time.sleep(0.05)

    def __exit__(self, *args):
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()


def _write_state(path, state):
    descriptor, temporary = tempfile.mkstemp(prefix=".packlier-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _check_state(path, current):
    importlib.invalidate_caches()
    installed = metadata.version("Packlier")
    if installed != current:
        _restart(
            f"Packlier on disk is now {installed}, but this process started importing {current}. "
            "Rerun the program or restart the notebook kernel."
        )
    if path.exists():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(state, dict) or state.get("status") not in {"installing", "failed", "complete"}:
                raise ValueError("invalid update state")
        except (OSError, ValueError) as error:
            raise PacklierUpdateError(f"Cannot verify the previous Packlier update; inspect {path}.") from error
        if state["status"] == "complete" and state.get("target") == current:
            path.unlink()
        else:
            raise PacklierUpdateError(
                f"A previous Packlier update did not finish cleanly. Repair/reinstall Packlier "
                f"manually, then remove {path} before retrying."
            )


def _install_wheel(path, release, current, state_path):
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith("PIP_") and name not in {"PYTHONPATH", "PYTHONHOME"}
    }
    environment.update({"PACKLIER_AUTO_UPDATE": "off", "PIP_CONFIG_FILE": os.devnull})
    command = [
        sys.executable, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
        "--no-input", "install", "--no-index", "--no-deps", "--no-cache-dir",
        "--upgrade", "--prefix", sys.prefix, str(path),
    ]
    state = {"previous": current, "target": release.version, "status": "installing"}
    _write_state(state_path, state)
    try:
        completed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
        if completed.returncode:
            raise RuntimeError(f"pip exited with status {completed.returncode}: {completed.stderr[-2000:]}")
        importlib.invalidate_caches()
        if metadata.version("Packlier") != release.version:
            raise RuntimeError("the installed distribution does not match the requested version")
        _write_state(state_path, {**state, "status": "complete"})
    except BaseException as error:
        try:
            _write_state(state_path, {**state, "status": "failed"})
        except OSError:
            pass
        raise PacklierUpdateError(
            f"Packlier installation failed or was interrupted. Do not continue using this process; "
            f"repair the installation manually and inspect {state_path}. Detail: {error}"
        ) from error
    _restart(
        f"Packlier updated from {current} to {release.version}. "
        "Rerun the program or restart the notebook kernel before using Packlier."
    )


def _maybe_update(current, state_path):
    release = _fetch_release(current)
    if release is None:
        return
    with tempfile.TemporaryDirectory(prefix="packlier-update-", ignore_cleanup_errors=True) as directory:
        wheel = _download_wheel(release, directory)
        _warn(f"installing verified patch {current} -> {release.version}; a restart will be required")
        _install_wheel(wheel, release, current, state_path)


@contextmanager
def import_update_guard(current, package_file):
    """Serialize first imports and run checks only for managed installations."""
    mode = os.environ.get("PACKLIER_AUTO_UPDATE", "on").strip().lower()
    if mode in {"off", "0", "false", "no"}:
        yield
        return
    if mode not in {"on", "1", "true", "yes"}:
        _warn("invalid PACKLIER_AUTO_UPDATE value; automatic updates disabled")
        yield
        return
    if _RESTART_MESSAGE is not None:
        raise PacklierUpdatedRestartRequired(_RESTART_MESSAGE)
    try:
        root = _installation(package_file)
    except (OSError, ValueError) as error:
        _warn(f"cannot inspect installation ({type(error).__name__}); using current version")
        root = None
    if root is None:
        yield
        return
    lock = _FileLock(root / ".packlier-update.lock")
    try:
        lock.__enter__()
    except OSError:
        _warn("cannot acquire installation lock; automatic updates disabled")
        yield
        return
    try:
        state_path = root / ".packlier-update-state.json"
        _check_state(state_path, current)
        try:
            _maybe_update(current, state_path)
        except (_CheckFailed, URLError, OSError, ValueError, BadZipFile) as error:
            _warn(f"check/download failed ({error}); using current version")
        yield
    finally:
        lock.__exit__(None, None, None)
