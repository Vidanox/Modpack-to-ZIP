#!/usr/bin/env python3
"""
Download a portable PrismLauncher build and prefill its shared Minecraft cache.

The generated portable launcher folder contains the same high-value files Prism
downloads on a first vanilla launch:

    assets/indexes/<asset-index>.json
    assets/objects/<sha-prefix>/<sha1>
    libraries/<maven path>
    versions/<minecraft>/<minecraft>.json
    versions/<minecraft>/<minecraft>.jar
    java/eclipse_temurin_jre<version>

By default the script downloads the latest Windows MSVC portable release from
Diegiwg/PrismLauncher-Cracked. Pass --linux for the latest Linux Qt6 portable
tarball. The release repository is configurable with --launcher-repo.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import ssl
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


GITHUB_API = "https://api.github.com"
DEFAULT_LAUNCHER_REPO = "Diegiwg/PrismLauncher-Cracked"
MOJANG_VERSION_MANIFEST = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json"
MOJANG_ASSET_BASE = "https://resources.download.minecraft.net"
MAVEN_BASE = "https://libraries.minecraft.net"
PRISM_META_API = "https://meta.prismlauncher.org/v1"
ADOPTIUM_API = "https://api.adoptium.net/v3"
USER_AGENT = "modpacks-offline-prism-prefetcher/1.0 (+https://prismlauncher.org)"
FABRIC_LOADER_UID = "net.fabricmc.fabric-loader"
FABRIC_INTERMEDIARY_UID = "net.fabricmc.intermediary"
FABRIC_INTERMEDIARY_NAME = "Intermediary Mappings"
FABRIC_MAVEN_BASE = "https://maven.fabricmc.net"
CHUNK_SIZE = 1024 * 1024
DEFAULT_CONCURRENCY = 8
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 60
SSL_CONTEXT: ssl.SSLContext | None = None
SSL_CONTEXTS: tuple[ssl.SSLContext | None, ...] = (None,)


class PrefetchError(RuntimeError):
    """User-facing error raised by the prefetcher."""


@dataclasses.dataclass(frozen=True)
class DownloadItem:
    url: str
    path: Path
    sha1: str | None = None
    sha256: str | None = None
    size: int | None = None
    label: str | None = None


@dataclasses.dataclass(frozen=True)
class MetaCacheItem:
    base: str
    relative_path: str
    path: Path
    eternal: bool = False


@dataclasses.dataclass(frozen=True)
class LauncherAsset:
    name: str
    url: str
    size: int | None
    release_tag: str


@dataclasses.dataclass(frozen=True)
class RuntimeInfo:
    java_major: int
    release_name: str
    url: str
    checksum_url: str | None
    archive_name: str


@dataclasses.dataclass
class MetaPackage:
    uid: str
    name: str
    versions: dict[str, Mapping[str, Any]]


@dataclasses.dataclass(frozen=True)
class LauncherValidation:
    ok: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def log(message: str) -> None:
    print(message, flush=True)


def make_request(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> urllib.request.Request:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8",
    }
    if headers:
        request_headers.update(headers)
    return urllib.request.Request(url, headers=request_headers, method="GET")


def certifi_ca_file() -> str | None:
    try:
        import certifi  # type: ignore[import-not-found]
    except ImportError:
        return None

    path = certifi.where()
    return path if path and Path(path).exists() else None


def windows_root_context() -> ssl.SSLContext | None:
    if not hasattr(ssl, "enum_certificates"):
        return None

    roots: list[str] = []
    for store_name in ("ROOT", "CA"):
        try:
            certificates = ssl.enum_certificates(store_name)  # type: ignore[attr-defined]
        except (OSError, RuntimeError):
            continue
        for cert_bytes, encoding, _trust in certificates:
            if encoding == "x509_asn":
                roots.append(ssl.DER_cert_to_PEM_cert(cert_bytes))
            elif encoding == "x509_pem":
                if isinstance(cert_bytes, bytes):
                    roots.append(cert_bytes.decode("ascii", errors="ignore"))
                else:
                    roots.append(str(cert_bytes))

    if not roots:
        return None

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata="\n".join(roots))
    return context


def verified_ssl_contexts() -> tuple[ssl.SSLContext | None, ...]:
    contexts: list[ssl.SSLContext | None] = [None]
    certifi_file = certifi_ca_file()
    if certifi_file:
        contexts.append(ssl.create_default_context(cafile=certifi_file))
    windows_context = windows_root_context()
    if windows_context is not None:
        contexts.append(windows_context)
    return tuple(contexts)


def is_certificate_verify_error(exc: urllib.error.URLError) -> bool:
    reason = exc.reason
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    if isinstance(reason, ssl.SSLError):
        return "certificate verify failed" in str(reason).lower()
    return False


def open_url(url: str, *, timeout: int = DEFAULT_TIMEOUT):
    request = make_request(url)
    last_certificate_error: urllib.error.URLError | None = None
    contexts = (SSL_CONTEXT,) if SSL_CONTEXT is not None else SSL_CONTEXTS
    for index, context in enumerate(contexts):
        try:
            return urllib.request.urlopen(request, timeout=timeout, context=context)
        except urllib.error.URLError as exc:
            if is_certificate_verify_error(exc) and index + 1 < len(contexts):
                last_certificate_error = exc
                continue
            raise

    if last_certificate_error is not None:
        raise last_certificate_error
    raise urllib.error.URLError(f"Network error for {url}")


def read_url_bytes(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> bytes:
    with open_url(url, timeout=timeout) as response:
        return response.read()


def read_json(url: str, *, timeout: int = DEFAULT_TIMEOUT) -> Any:
    return json.loads(read_url_bytes(url, timeout=timeout).decode("utf-8"))


def normalize_archive_name(name: str) -> str:
    name = name.replace("\\", "/")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in ("", ".", "..") or ":" in part for part in pure.parts):
        raise PrefetchError(f"Unsafe archive path: {name!r}")
    return pure.as_posix()


def archive_root_name(names: Iterable[str]) -> str | None:
    roots: set[str] = set()
    for raw_name in names:
        name = raw_name.replace("\\", "/").strip("/")
        if not name:
            continue
        first = name.split("/", 1)[0]
        if first:
            roots.add(first)
    if len(roots) == 1:
        return next(iter(roots))
    return None


def safe_extract_zip(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as zf:
        members = [member for member in zf.infolist() if not member.is_dir()]
        root = archive_root_name(member.filename for member in members)
        for member in members:
            rel = normalize_archive_name(member.filename)
            target = dest / Path(*PurePosixPath(rel).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, CHUNK_SIZE)
    return dest / root if root and (dest / root).exists() else dest


def safe_extract_tar(tar_path: Path, dest: Path) -> Path:
    with tarfile.open(tar_path) as tf:
        members = [member for member in tf.getmembers() if member.isfile() or member.isdir() or member.issym()]
        root = archive_root_name(member.name for member in members)
        for member in members:
            rel = normalize_archive_name(member.name)
            target = dest / Path(*PurePosixPath(rel).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                linkname = getattr(member, "linkname", "")
                if os.path.isabs(linkname) or ".." in PurePosixPath(linkname).parts:
                    raise PrefetchError(f"Unsafe symlink in tar archive: {member.name!r} -> {linkname!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    target.symlink_to(linkname)
                except (OSError, NotImplementedError):
                    pass
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with extracted, target.open("wb") as out:
                shutil.copyfileobj(extracted, out, CHUNK_SIZE)
            try:
                os.chmod(target, member.mode)
            except OSError:
                pass
    return dest / root if root and (dest / root).exists() else dest


def extract_archive(archive: Path, dest: Path) -> Path:
    suffixes = "".join(archive.suffixes).lower()
    if suffixes.endswith(".zip"):
        return safe_extract_zip(archive, dest)
    if suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz") or suffixes.endswith(".tar"):
        return safe_extract_tar(archive, dest)
    raise PrefetchError(f"Unsupported archive format: {archive.name}")


def prepare_launcher_dir(extracted: Path, target: Path) -> Path:
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    children = list(extracted.iterdir())
    if len(children) == 1 and children[0].is_dir():
        source_root = children[0]
        for child in source_root.iterdir():
            shutil.move(str(child), str(target / child.name))
        return target

    for child in children:
        shutil.move(str(child), str(target / child.name))
    return target


def stage_java_install(launcher_dir: Path, runtime: RuntimeInfo, archive: Path, work_dir: Path) -> Path:
    java_tmp = work_dir / "java-extract" / runtime.release_name
    if java_tmp.exists():
        shutil.rmtree(java_tmp)
    java_tmp.mkdir(parents=True, exist_ok=True)
    extracted_java_root = extract_archive(archive, java_tmp)

    if extracted_java_root == java_tmp:
        children = [child for child in java_tmp.iterdir()]
        if len(children) == 1 and children[0].is_dir():
            extracted_java_root = children[0]
        else:
            extracted_java_root = java_tmp

    target_java = launcher_dir / "java" / temurin_folder_name(runtime)
    if target_java.exists():
        shutil.rmtree(target_java)
    target_java.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(extracted_java_root), str(target_java))
    return target_java


def verify_file(path: Path, *, sha1: str | None = None, sha256: str | None = None, size: int | None = None) -> bool:
    if not path.is_file():
        return False
    if size is not None and path.stat().st_size != size:
        return False
    if sha1 is not None and file_hash(path, "sha1") != sha1.lower():
        return False
    if sha256 is not None and file_hash(path, "sha256") != sha256.lower():
        return False
    return True


def file_hash(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def should_skip_download(item: DownloadItem) -> bool:
    return verify_file(item.path, sha1=item.sha1, sha256=item.sha256, size=item.size)


def download_one(item: DownloadItem, *, retries: int, timeout: int) -> str:
    if should_skip_download(item):
        return "cached"

    item.path.parent.mkdir(parents=True, exist_ok=True)
    tmp = item.path.with_name(item.path.name + ".part")
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            with open_url(item.url, timeout=timeout) as response, tmp.open("wb") as out:
                shutil.copyfileobj(response, out, CHUNK_SIZE)
            if not verify_file(tmp, sha1=item.sha1, sha256=item.sha256, size=item.size):
                raise PrefetchError(f"Downloaded file failed verification: {item.label or item.path.name}")
            tmp.replace(item.path)
            return "downloaded"
        except Exception as exc:  # noqa: BLE001 - present user-facing retry errors.
            last_error = exc
            with contextlib_suppress_file_not_found(tmp):
                tmp.unlink()
            if attempt < retries:
                time.sleep(min(2**attempt, 10))

    raise PrefetchError(f"Failed to download {item.label or item.url}: {last_error}")


class contextlib_suppress_file_not_found:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is FileNotFoundError


def download_many(items: Sequence[DownloadItem], *, concurrency: int, retries: int, timeout: int) -> None:
    unique: dict[Path, DownloadItem] = {}
    for item in items:
        existing = unique.get(item.path)
        if existing is None:
            unique[item.path] = item
        elif existing.url != item.url or existing.sha1 != item.sha1 or existing.sha256 != item.sha256:
            raise PrefetchError(f"Conflicting downloads target the same path: {item.path}")

    total = len(unique)
    if total == 0:
        return

    completed = 0
    downloaded = 0
    cached = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        future_to_item = {
            pool.submit(download_one, item, retries=retries, timeout=timeout): item for item in unique.values()
        }
        for future in concurrent.futures.as_completed(future_to_item):
            result = future.result()
            completed += 1
            if result == "cached":
                cached += 1
            else:
                downloaded += 1
            if completed == total or completed % 25 == 0:
                log(f"  {completed}/{total} files ready ({downloaded} downloaded, {cached} cached)")


def parse_version_tuple(version: str) -> tuple[int, ...]:
    numbers = []
    for part in re.split(r"[.\-+_]", version):
        if part.isdigit():
            numbers.append(int(part))
        else:
            break
    return tuple(numbers)


def looks_like_minecraft_version(value: str) -> bool:
    return bool(
        re.fullmatch(r"1\.\d+(?:\.\d+)?(?:[-_+A-Za-z0-9.]*)?", value)
        or re.fullmatch(r"\d{2}\.\d+(?:\.\d+)?(?:[-_+A-Za-z0-9.]*)?", value)
        or re.fullmatch(r"\d{2}w\d{2}[a-z]", value)
        or re.fullmatch(r"[ab]\d+\.\d+(?:\.\d+)?", value)
        or value.startswith("rd-")
    )


def minecraft_java_major(version: str) -> int:
    parts = parse_version_tuple(version)
    if len(parts) >= 2 and parts[0] == 1 and parts[1] <= 16:
        return 8
    if len(parts) >= 2 and parts[0] == 1 and parts[1] == 17:
        return 17
    return 25


def github_release_assets(repo: str) -> tuple[str, list[dict[str, Any]]]:
    data = read_json(f"{GITHUB_API}/repos/{repo}/releases/latest")
    return str(data.get("tag_name") or data.get("name") or "latest"), list(data.get("assets") or [])


def find_launcher_asset(repo: str, *, linux: bool) -> LauncherAsset:
    release_tag, assets = github_release_assets(repo)
    if linux:
        patterns = [
            re.compile(r"PrismLauncher-Linux-Qt6-Portable-.*\.tar\.gz$", re.I),
            re.compile(r"Linux.*Qt6.*Portable.*\.tar\.gz$", re.I),
        ]
    else:
        patterns = [
            re.compile(r"PrismLauncher-Windows-MSVC-Portable-.*\.zip$", re.I),
            re.compile(r"Windows.*MSVC.*Portable.*\.zip$", re.I),
        ]

    for pattern in patterns:
        matches = [asset for asset in assets if pattern.search(str(asset.get("name", "")))]
        if matches:
            asset = matches[0]
            return LauncherAsset(
                name=str(asset["name"]),
                url=str(asset["browser_download_url"]),
                size=int(asset["size"]) if asset.get("size") is not None else None,
                release_tag=release_tag,
            )

    wanted = "Linux Qt6 portable tar.gz" if linux else "Windows MSVC portable zip"
    names = ", ".join(str(asset.get("name")) for asset in assets)
    raise PrefetchError(f"Could not find a {wanted} asset in {repo} release {release_tag}. Assets: {names}")


def adoptium_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64", "x64"}:
        return "x64"
    if machine in {"aarch64", "arm64"}:
        return "aarch64"
    if machine in {"x86", "i386", "i686"}:
        return "x86"
    raise PrefetchError(f"Unsupported CPU architecture for Adoptium lookup: {platform.machine()}")


def find_temurin_runtime(java_major: int, *, linux: bool, arch: str) -> RuntimeInfo:
    os_name = "linux" if linux else "windows"
    params = urllib.parse.urlencode(
        {
            "architecture": arch,
            "heap_size": "normal",
            "image_type": "jre",
            "jvm_impl": "hotspot",
            "os": os_name,
            "project": "jdk",
            "vendor": "eclipse",
        }
    )
    url = f"{ADOPTIUM_API}/assets/latest/{java_major}/hotspot?{params}"
    data = read_json(url)
    if not isinstance(data, list) or not data:
        raise PrefetchError(f"No Temurin JRE {java_major} build found for {os_name}-{arch}")

    def release_sort_key(entry: Mapping[str, Any]) -> tuple[int, ...]:
        release_name = str(entry.get("release_name") or "")
        return parse_version_tuple(release_name.removeprefix("jdk-"))

    entry = sorted(data, key=release_sort_key, reverse=True)[0]
    binary = entry.get("binary") or {}
    package = binary.get("package") or {}
    package_link = package.get("link")
    if not package_link:
        raise PrefetchError(f"Temurin JRE {java_major} response did not include a package link.")

    return RuntimeInfo(
        java_major=java_major,
        release_name=str(entry.get("release_name") or f"jdk-{java_major}"),
        url=str(package_link),
        checksum_url=str(package.get("checksum_link")) if package.get("checksum_link") else None,
        archive_name=str(package.get("name") or urllib.parse.urlparse(str(package_link)).path.rsplit("/", 1)[-1]),
    )


def sanitize_folder_name(value: str) -> str:
    value = value.replace("+", "+")
    value = re.sub(r'[<>:"/\\|?*]', "_", value)
    value = re.sub(r"\s+", "_", value).strip("._ ")
    return value or "java"


def temurin_folder_name(runtime: RuntimeInfo) -> str:
    version = runtime.release_name.removeprefix("jdk-")
    return sanitize_folder_name(f"eclipse_temurin_jre{version}")


def read_checksum_from_url(url: str) -> str | None:
    try:
        text = read_url_bytes(url).decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    match = re.search(r"\b[a-fA-F0-9]{64}\b", text)
    return match.group(0).lower() if match else None


def fetch_version_manifest() -> dict[str, Any]:
    data = read_json(MOJANG_VERSION_MANIFEST)
    if not isinstance(data, dict) or "versions" not in data:
        raise PrefetchError("Mojang version manifest response was not in the expected format.")
    return data


def select_versions_interactively(manifest: Mapping[str, Any]) -> list[str]:
    versions = [entry for entry in manifest.get("versions", []) if entry.get("type") == "release"]
    latest_release = (manifest.get("latest") or {}).get("release")

    log("Available Minecraft release versions:")
    for idx, entry in enumerate(versions[:40], start=1):
        marker = " (latest)" if entry.get("id") == latest_release else ""
        log(f"  {idx:2d}) {entry.get('id')}{marker}")
    log("")
    log("Type numbers, version ids, ranges, or 'latest'. Examples: 1,3,8  |  1.20.1 1.21.8  |  1-5")

    by_id = {str(entry["id"]): entry for entry in versions}
    selected: list[str] = []
    while not selected:
        raw = input("Minecraft versions to prefetch: ").strip()
        if not raw:
            continue
        for token in re.split(r"[\s,]+", raw):
            if not token:
                continue
            lower = token.lower()
            if lower == "latest":
                if latest_release:
                    selected.append(str(latest_release))
                continue
            if re.fullmatch(r"\d+-\d+", token):
                start, end = (int(part) for part in token.split("-", 1))
                if start > end:
                    start, end = end, start
                for index in range(start, end + 1):
                    if 1 <= index <= len(versions):
                        selected.append(str(versions[index - 1]["id"]))
                continue
            if token.isdigit():
                index = int(token)
                if 1 <= index <= len(versions):
                    selected.append(str(versions[index - 1]["id"]))
                else:
                    log(f"Skipping out-of-range selection: {token}")
                continue
            if token in by_id:
                selected.append(token)
            else:
                log(f"Skipping unknown version: {token}")

    deduped = list(dict.fromkeys(selected))
    log("Selected: " + ", ".join(deduped))
    return deduped


def resolve_version_entries(manifest: Mapping[str, Any], version_ids: Sequence[str]) -> list[dict[str, Any]]:
    by_id = {str(entry["id"]): entry for entry in manifest.get("versions", [])}
    latest_release = str((manifest.get("latest") or {}).get("release") or "")
    resolved: list[dict[str, Any]] = []
    for raw in version_ids:
        version = latest_release if raw.lower() == "latest" else raw
        entry = by_id.get(version)
        if entry is None:
            raise PrefetchError(f"Unknown Minecraft version: {raw}")
        resolved.append(entry)
    return resolved


def rule_applies(rule: Mapping[str, Any], os_name: str) -> bool:
    os_rule = rule.get("os")
    if isinstance(os_rule, Mapping):
        name = os_rule.get("name")
        if name and name != os_name:
            return False
    return True


def library_allowed(library: Mapping[str, Any], os_name: str) -> bool:
    rules = library.get("rules")
    if not rules:
        return True
    allowed = False
    for rule in rules:
        if not isinstance(rule, Mapping) or not rule_applies(rule, os_name):
            continue
        action = rule.get("action")
        if action == "allow":
            allowed = True
        elif action == "disallow":
            allowed = False
    return allowed


def native_classifier_key(library: Mapping[str, Any], os_name: str, arch_bits: str = "64") -> str | None:
    natives = library.get("natives")
    if not isinstance(natives, Mapping):
        return None
    classifier = natives.get(os_name)
    if not classifier:
        return None
    return str(classifier).replace("${arch}", arch_bits)


def maven_path_from_name(name: str, classifier: str | None = None) -> str:
    match = re.fullmatch(r"([^:@]+):([^:@]+):([^:@]+)(?::([^:@]+))?(?:@([^:@]+))?", name)
    if not match:
        raise PrefetchError(f"Cannot parse Maven coordinate: {name}")
    group, artifact, version, embedded_classifier, extension = match.groups()
    classifier = classifier or embedded_classifier
    extension = extension or "jar"
    filename = f"{artifact}-{version}"
    if classifier:
        filename += f"-{classifier}"
    filename += f".{extension}"
    return f"{group.replace('.', '/')}/{artifact}/{version}/{filename}"


def minecraft_client_library_path(version: str) -> str:
    return maven_path_from_name(f"com.mojang:minecraft:{version}:client")


def portable_local_file_url(relative_path: str) -> str:
    normalized = relative_path.replace("\\", "/").lstrip("/")
    return "file:" + urllib.parse.quote(normalized, safe="/._-~")


def localize_minecraft_asset_index_url(version_json: Mapping[str, Any]) -> dict[str, Any]:
    localized = dict(version_json)
    asset_info = localized.get("assetIndex")
    if isinstance(asset_info, Mapping) and asset_info.get("id"):
        asset_id = str(asset_info["id"])
        localized_asset_info = dict(asset_info)
        localized_asset_info["url"] = portable_local_file_url(f"assets/indexes/{asset_id}.json")
        localized["assetIndex"] = localized_asset_info
    return localized


def collect_library_downloads(version_json: Mapping[str, Any], root: Path, *, os_name: str) -> list[DownloadItem]:
    items: list[DownloadItem] = []
    for library in version_json.get("libraries", []):
        if not isinstance(library, Mapping) or not library_allowed(library, os_name):
            continue

        downloads = library.get("downloads")
        name = str(library.get("name") or "")
        if isinstance(downloads, Mapping):
            artifact = downloads.get("artifact")
            if isinstance(artifact, Mapping) and artifact.get("url") and artifact.get("path"):
                items.append(
                    DownloadItem(
                        url=str(artifact["url"]),
                        path=root / "libraries" / Path(*PurePosixPath(str(artifact["path"])).parts),
                        sha1=str(artifact.get("sha1")) if artifact.get("sha1") else None,
                        size=int(artifact["size"]) if artifact.get("size") is not None else None,
                        label=name,
                    )
                )

            classifier_key = native_classifier_key(library, os_name)
            classifiers = downloads.get("classifiers")
            if classifier_key and isinstance(classifiers, Mapping):
                native = classifiers.get(classifier_key)
                if isinstance(native, Mapping) and native.get("url") and native.get("path"):
                    items.append(
                        DownloadItem(
                            url=str(native["url"]),
                            path=root / "libraries" / Path(*PurePosixPath(str(native["path"])).parts),
                            sha1=str(native.get("sha1")) if native.get("sha1") else None,
                            size=int(native["size"]) if native.get("size") is not None else None,
                            label=f"{name}:{classifier_key}",
                        )
                    )
            continue

        if name:
            rel = maven_path_from_name(name)
            url = str(library.get("url") or MAVEN_BASE)
            url = url.rstrip("/") + "/" + rel
            items.append(DownloadItem(url=url, path=root / "libraries" / Path(*PurePosixPath(rel).parts), label=name))

    return items


def collect_asset_downloads(asset_index: Mapping[str, Any], root: Path) -> list[DownloadItem]:
    items: list[DownloadItem] = []
    objects = asset_index.get("objects")
    if not isinstance(objects, Mapping):
        return items
    for logical_name, value in objects.items():
        if not isinstance(value, Mapping):
            continue
        sha1 = str(value.get("hash") or "")
        if not re.fullmatch(r"[a-fA-F0-9]{40}", sha1):
            continue
        rel = f"{sha1[:2]}/{sha1}"
        items.append(
            DownloadItem(
                url=f"{MOJANG_ASSET_BASE}/{rel}",
                path=root / "assets" / "objects" / sha1[:2] / sha1,
                sha1=sha1,
                size=int(value["size"]) if value.get("size") is not None else None,
                label=str(logical_name),
            )
        )
    return items


def reconstruct_assets(asset_id: str, asset_index: Mapping[str, Any], root: Path) -> None:
    objects = asset_index.get("objects")
    if not isinstance(objects, Mapping):
        return

    target: Path | None = None
    if asset_index.get("virtual"):
        target = root / "assets" / "virtual" / asset_id
    elif asset_index.get("map_to_resources"):
        target = root / "resources"
    if target is None:
        return

    copied = 0
    for logical_name, value in objects.items():
        if not isinstance(value, Mapping):
            continue
        sha1 = str(value.get("hash") or "")
        source = root / "assets" / "objects" / sha1[:2] / sha1
        if not source.is_file():
            continue
        rel = normalize_archive_name(str(logical_name))
        dest = target / Path(*PurePosixPath(rel).parts)
        if dest.is_file() and dest.stat().st_size == source.stat().st_size:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, dest)
        copied += 1
    if copied:
        log(f"  reconstructed {copied} virtual/resource assets for {asset_id}")


def prism_meta_url(uid: str, version: str | None = None) -> str:
    if version is None:
        return f"{PRISM_META_API}/{urllib.parse.quote(uid, safe='.')}/index.json"
    return f"{PRISM_META_API}/{urllib.parse.quote(uid, safe='.')}/{urllib.parse.quote(version, safe='')}.json"


def fetch_prism_component(uid: str, version: str, *, timeout: int) -> Mapping[str, Any]:
    data = read_json(prism_meta_url(uid, version), timeout=timeout)
    if not isinstance(data, Mapping):
        raise PrefetchError(f"Prism metadata for {uid} {version} was not a JSON object.")
    return data


def minecraft_meta_for_version(meta_packages: Mapping[str, MetaPackage], version: str) -> Mapping[str, Any] | None:
    package = meta_packages.get("net.minecraft")
    if package is None:
        return None
    return package.versions.get(version)


def synthesize_fabric_intermediary_meta(version: str, meta_packages: Mapping[str, MetaPackage]) -> dict[str, Any]:
    minecraft_meta = minecraft_meta_for_version(meta_packages, version) or {}
    release_time = str(minecraft_meta.get("releaseTime") or minecraft_meta.get("time") or "1970-01-01T00:00:00+00:00")
    version_type = str(minecraft_meta.get("type") or "release")
    return {
        "formatVersion": 1,
        "libraries": [
            {
                "name": f"net.fabricmc:intermediary:{version}",
                "url": FABRIC_MAVEN_BASE,
            }
        ],
        "name": FABRIC_INTERMEDIARY_NAME,
        "order": 11,
        "releaseTime": release_time,
        "requires": [
            {
                "equals": version,
                "uid": "net.minecraft",
            }
        ],
        "type": version_type,
        "uid": FABRIC_INTERMEDIARY_UID,
        "version": version,
        "volatile": True,
    }


def fetch_or_synthesize_prism_component(
    uid: str,
    version: str,
    *,
    timeout: int,
    meta_packages: Mapping[str, MetaPackage],
) -> Mapping[str, Any]:
    try:
        return fetch_prism_component(uid, version, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and uid == FABRIC_INTERMEDIARY_UID and looks_like_minecraft_version(version):
            log(f"Warning: Prism metadata for {uid} {version} is missing; generating Fabric intermediary metadata locally.")
            return synthesize_fabric_intermediary_meta(version, meta_packages)
        raise


def resolve_prism_recommended_version(uid: str, minecraft_version: str, *, timeout: int) -> str:
    data = read_json(prism_meta_url(uid), timeout=timeout)
    versions = data.get("versions") if isinstance(data, Mapping) else None
    if not isinstance(versions, list):
        raise PrefetchError(f"Prism metadata index for {uid} did not contain versions.")
    for version in versions:
        if not isinstance(version, Mapping) or version.get("recommended") is not True:
            continue
        requires = version.get("requires") or []
        if any(isinstance(req, Mapping) and req.get("uid") == "net.minecraft" and req.get("equals") == minecraft_version for req in requires):
            return str(version["version"])
    raise PrefetchError(f"Could not resolve recommended {uid} for Minecraft {minecraft_version}.")


def component_version_from_requires(component_json: Mapping[str, Any], uid: str) -> str | None:
    requires = component_json.get("requires")
    if not isinstance(requires, list):
        return None
    for requirement in requires:
        if isinstance(requirement, Mapping) and requirement.get("uid") == uid:
            return str(requirement.get("equals") or requirement.get("suggests") or "") or None
    return None


def package_display_name(uid: str) -> str:
    names = {
        "net.minecraft": "Minecraft",
        FABRIC_LOADER_UID: "Fabric Loader",
        FABRIC_INTERMEDIARY_UID: FABRIC_INTERMEDIARY_NAME,
        "net.minecraftforge": "Forge",
        "net.neoforged": "NeoForge",
        "org.quiltmc.quilt-loader": "Quilt Loader",
        "org.lwjgl": "LWJGL",
        "org.lwjgl3": "LWJGL 3",
    }
    return names.get(uid, uid)


def add_meta_package_version(packages: dict[str, MetaPackage], uid: str, version_json: Mapping[str, Any]) -> None:
    version = str(version_json.get("version") or version_json.get("id") or "")
    if not version:
        return
    package = packages.setdefault(uid, MetaPackage(uid=uid, name=package_display_name(uid), versions={}))
    package.versions[version] = dict(version_json)


def minimal_version_list_entry(version_json: Mapping[str, Any]) -> dict[str, Any]:
    version = str(version_json.get("version") or version_json.get("id") or "")
    release_time = str(version_json.get("releaseTime") or version_json.get("time") or "1970-01-01T00:00:00+00:00")
    entry: dict[str, Any] = {
        "version": version,
        "releaseTime": release_time,
        "type": str(version_json.get("type") or "release"),
    }
    if version_json.get("recommended") is not None:
        entry["recommended"] = bool(version_json.get("recommended"))
    if version_json.get("volatile") is not None:
        entry["volatile"] = bool(version_json.get("volatile"))
    if isinstance(version_json.get("requires"), list):
        entry["requires"] = version_json["requires"]
    if isinstance(version_json.get("conflicts"), list):
        entry["conflicts"] = version_json["conflicts"]
    return entry


def write_meta_packages(root: Path, packages: Mapping[str, MetaPackage]) -> list[MetaCacheItem]:
    cache_items: list[MetaCacheItem] = []
    meta_index = {
        "formatVersion": 1,
        "packages": [{"uid": uid, "name": package.name} for uid, package in sorted(packages.items())],
    }
    meta_index_path = root / "meta" / "index.json"
    write_json(meta_index_path, meta_index)
    cache_items.append(MetaCacheItem(base="meta", relative_path="index.json", path=meta_index_path))

    for uid, package in sorted(packages.items()):
        package_dir = root / "meta" / uid
        index_json = {
            "formatVersion": 1,
            "uid": uid,
            "name": package.name,
            "versions": [minimal_version_list_entry(version_json) for version_json in package.versions.values()],
        }
        index_path = package_dir / "index.json"
        write_json(index_path, index_json)
        cache_items.append(MetaCacheItem(base="meta", relative_path=f"{uid}/index.json", path=index_path))

        for version, version_json in package.versions.items():
            version_path = package_dir / f"{version}.json"
            write_json(version_path, version_json)
            cache_items.append(MetaCacheItem(base="meta", relative_path=f"{uid}/{version}.json", path=version_path))
    return cache_items


def minecraft_meta_from_mojang(version_json: Mapping[str, Any]) -> dict[str, Any]:
    version = str(version_json.get("id") or version_json.get("version") or "")
    meta = localize_minecraft_asset_index_url(version_json)
    meta["formatVersion"] = 1
    meta["uid"] = "net.minecraft"
    meta["name"] = "Minecraft"
    meta["version"] = version
    meta["releaseTime"] = str(meta.get("releaseTime") or meta.get("time") or "1970-01-01T00:00:00+00:00")
    return meta


def collect_component_downloads(
    components: Sequence[tuple[str, str]],
    root: Path,
    *,
    minecraft_version: str,
    os_name: str,
    timeout: int,
    meta_packages: dict[str, MetaPackage],
) -> list[DownloadItem]:
    downloads: list[DownloadItem] = []
    seen: set[tuple[str, str]] = set()
    queue = list(components)

    while queue:
        uid, version = queue.pop(0)
        if uid == "net.minecraft" or not version:
            continue
        key = (uid, version)
        if key in seen:
            continue
        seen.add(key)

        log(f"Reading Prism component {uid} {version}")
        component_json = fetch_or_synthesize_prism_component(
            uid,
            version,
            timeout=timeout,
            meta_packages=meta_packages,
        )
        add_meta_package_version(meta_packages, uid, component_json)

        for lib_download in collect_library_downloads(component_json, root, os_name=os_name):
            downloads.append(lib_download)

        for requirement in component_json.get("requires") or []:
            if not isinstance(requirement, Mapping):
                continue
            req_uid = str(requirement.get("uid") or "")
            req_version = str(requirement.get("equals") or requirement.get("suggests") or "")
            if req_uid == FABRIC_INTERMEDIARY_UID and not req_version:
                req_version = minecraft_version
            if req_uid and req_uid != "net.minecraft" and req_version:
                queue.append((req_uid, req_version))

    return downloads


def component_inputs_by_build(builds: Sequence[Any], *, timeout: int) -> tuple[list[str], list[tuple[str, list[tuple[str, str]]]]]:
    minecraft_versions: list[str] = []
    component_groups: list[tuple[str, list[tuple[str, str]]]] = []
    for build in builds:
        metadata_minecraft_version = minecraft_version_from_build_metadata(build)
        minecraft_version = ""
        components: list[tuple[str, str]] = []
        for uid, version in components_from_mmc_pack(build):
            if uid == "net.minecraft":
                minecraft_version = version if looks_like_minecraft_version(version) else (metadata_minecraft_version or version)
                if minecraft_version != version:
                    log(f"Warning: ignoring invalid Minecraft component version {version!r}; using {minecraft_version!r}.")
                minecraft_versions.append(minecraft_version)
            elif version == "recommended" and minecraft_version:
                components.append((uid, resolve_prism_recommended_version(uid, minecraft_version, timeout=timeout)))
            else:
                components.append((uid, version))
        component_groups.append((minecraft_version, list(dict.fromkeys(components))))
    return list(dict.fromkeys(minecraft_versions)), component_groups


def installed_instance_dir_for_build(launcher_dir: Path, build: Any) -> Path | None:
    instances_dir = launcher_dir / "instances"
    for instance_dir in sorted(instances_dir.iterdir()) if instances_dir.exists() else []:
        if not instance_dir.is_dir():
            continue
        cfg = parse_ini_key_values(instance_dir / "instance.cfg")
        if (
            cfg.get("ManagedPackID") == str(getattr(build, "managed_id", ""))
            and cfg.get("ManagedPackVersionID") == str(getattr(build, "managed_version_id", ""))
        ):
            return instance_dir
    return None


def component_versions_from_meta(
    components: Sequence[tuple[str, str]],
    meta_packages: Mapping[str, MetaPackage],
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    seen = set(components)
    for uid, version in components:
        package = meta_packages.get(uid)
        version_json = package.versions.get(version) if package else None
        if not version_json:
            continue
        for requirement in version_json.get("requires") or []:
            if not isinstance(requirement, Mapping):
                continue
            req_uid = str(requirement.get("uid") or "")
            req_version = str(requirement.get("equals") or requirement.get("suggests") or "")
            if req_uid == FABRIC_INTERMEDIARY_UID and not req_version:
                req_version = next((candidate for candidate_uid, candidate in components if candidate_uid == "net.minecraft"), "")
            if not req_uid or not req_version or req_uid == "net.minecraft":
                continue
            key = (req_uid, req_version)
            if key not in seen:
                seen.add(key)
                result.append(key)
    return result


def ensure_mmc_pack_components(pack_path: Path, components_to_add: Sequence[tuple[str, str]]) -> None:
    if not components_to_add or not pack_path.exists():
        return
    data = json.loads(pack_path.read_text(encoding="utf-8"))
    components = data.get("components")
    if not isinstance(components, list):
        return

    existing_uids = {
        str(component.get("uid") or "")
        for component in components
        if isinstance(component, Mapping)
    }
    changed = False
    for uid, version in components_to_add:
        if uid in existing_uids:
            continue
        components.append(
            {
                "uid": uid,
                "version": version,
                "dependencyOnly": True,
                "cachedName": package_display_name(uid),
                "cachedVersion": version,
            }
        )
        existing_uids.add(uid)
        changed = True

    if changed:
        pack_path.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")


def write_instance_component_patches(launcher_dir: Path, builds: Sequence[Any], meta_packages: Mapping[str, MetaPackage]) -> None:
    instances_dir = launcher_dir / "instances"
    for build in builds:
        instance_dir = installed_instance_dir_for_build(launcher_dir, build)
        if instance_dir is None:
            continue
        patch_dir = instance_dir / "patches"
        pack_path = instance_dir / "mmc-pack.json"
        components = components_from_mmc_pack(build)
        implicit_components = component_versions_from_meta(components, meta_packages)
        ensure_mmc_pack_components(pack_path, implicit_components)
        for uid, version in [*components, *implicit_components]:
            package = meta_packages.get(uid)
            if package is None:
                continue
            version_json = package.versions.get(version)
            if not version_json:
                continue
            patch_path = patch_dir / f"{uid}.json"
            write_json(patch_path, version_json)


def prefetch_minecraft_version(
    entry: Mapping[str, Any],
    root: Path,
    *,
    os_name: str,
    timeout: int,
) -> tuple[list[DownloadItem], list[MetaCacheItem], list[tuple[str, Mapping[str, Any]]], int, Mapping[str, Any]]:
    version_id = str(entry["id"])
    log(f"Reading Minecraft {version_id} metadata")
    version_json = read_json(str(entry["url"]), timeout=timeout)
    localized_version_json = localize_minecraft_asset_index_url(version_json)
    write_json(root / "versions" / version_id / f"{version_id}.json", localized_version_json)

    downloads: list[DownloadItem] = []
    metacache: list[MetaCacheItem] = []
    asset_indexes: list[tuple[str, Mapping[str, Any]]] = []

    client = (version_json.get("downloads") or {}).get("client") if isinstance(version_json.get("downloads"), Mapping) else None
    if isinstance(client, Mapping) and client.get("url"):
        client_sha1 = str(client.get("sha1")) if client.get("sha1") else None
        client_size = int(client["size"]) if client.get("size") is not None else None
        client_url = str(client["url"])
        client_library_rel = minecraft_client_library_path(version_id)
        client_library_path = root / "libraries" / Path(*PurePosixPath(client_library_rel).parts)
        downloads.append(
            DownloadItem(
                url=client_url,
                path=root / "versions" / version_id / f"{version_id}.jar",
                sha1=client_sha1,
                size=client_size,
                label=f"Minecraft {version_id} client",
            )
        )
        downloads.append(
            DownloadItem(
                url=client_url,
                path=client_library_path,
                sha1=client_sha1,
                size=client_size,
                label=f"Minecraft {version_id} client library",
            )
        )
        metacache.append(MetaCacheItem(base="libraries", relative_path=client_library_rel, path=client_library_path))

    for lib_download in collect_library_downloads(version_json, root, os_name=os_name):
        downloads.append(lib_download)
        rel = lib_download.path.relative_to(root / "libraries").as_posix()
        metacache.append(MetaCacheItem(base="libraries", relative_path=rel, path=lib_download.path))

    asset_info = version_json.get("assetIndex")
    if isinstance(asset_info, Mapping) and asset_info.get("url") and asset_info.get("id"):
        asset_id = str(asset_info["id"])
        asset_index_bytes = read_url_bytes(str(asset_info["url"]), timeout=timeout)
        asset_index = json.loads(asset_index_bytes.decode("utf-8"))
        asset_index_path = root / "assets" / "indexes" / f"{asset_id}.json"
        asset_index_path.parent.mkdir(parents=True, exist_ok=True)
        asset_index_path.write_bytes(asset_index_bytes)
        metacache.append(MetaCacheItem(base="asset_indexes", relative_path=f"{asset_id}.json", path=asset_index_path))
        downloads.extend(collect_asset_downloads(asset_index, root))
        asset_indexes.append((asset_id, asset_index))

    return downloads, metacache, asset_indexes, minecraft_java_major(version_id), minecraft_meta_from_mojang(version_json)


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_metacache(root: Path, items: Sequence[MetaCacheItem]) -> None:
    entries: list[dict[str, Any]] = []
    for item in items:
        if not item.path.exists():
            continue
        stat = item.path.stat()
        entries.append(
            {
                "base": item.base,
                "path": item.relative_path,
                "md5sum": file_hash(item.path, "md5"),
                "etag": "",
                "last_changed_timestamp": int(stat.st_mtime * 1000),
                "remote_changed_timestamp": "",
                "eternal": item.eternal,
                "current_age": 0,
                "max_age": 604800,
            }
        )

    cache_path = root / "metacache"
    cache_path.write_text(json.dumps({"version": "1", "entries": entries}, indent=2) + "\n", encoding="utf-8")


def parse_ini_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def write_ini_key_values(path: Path, updates: Mapping[str, str]) -> None:
    lines: list[str] = []
    seen: set[str] = set()
    if path.exists():
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in raw_line and not raw_line.lstrip().startswith(("#", ";")):
                key, _value = raw_line.split("=", 1)
                stripped_key = key.strip()
                if stripped_key in updates:
                    lines.append(f"{stripped_key}={updates[stripped_key]}")
                    seen.add(stripped_key)
                    continue
            lines.append(raw_line)
    for key, value in updates.items():
        if key not in seen:
            lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def launcher_executable_batch() -> str:
    return """@echo off
setlocal
cd /d "%~dp0"
set "PLAYER=%~1"
if not defined PLAYER set "PLAYER=Player"
set "LAUNCHER="
if exist "PrismLauncher.exe" set "LAUNCHER=%CD%\\PrismLauncher.exe"
if not defined LAUNCHER if exist "prismlauncher.exe" set "LAUNCHER=%CD%\\prismlauncher.exe"
if not defined LAUNCHER for %%F in (*PrismLauncher*.exe prism*.exe) do if /i not "%%~nxF"=="PrismLauncher_updater.exe" if /i not "%%~nxF"=="prismlauncher_updater.exe" if not defined LAUNCHER set "LAUNCHER=%CD%\\%%~nxF"
if not defined LAUNCHER for %%F in (*.exe) do if /i not "%%~nxF"=="PrismLauncher_updater.exe" if /i not "%%~nxF"=="prismlauncher_updater.exe" if /i not "%%~nxF"=="updater.exe" if not defined LAUNCHER set "LAUNCHER=%CD%\\%%~nxF"
if not defined LAUNCHER (
  echo Could not find the PrismLauncher executable in %CD%.
  pause
  exit /b 1
)
"""


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def launcher_executable_shell(instance_id: str) -> str:
    return f"""#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
PLAYER="${{1:-Player}}"
LAUNCHER=""
for candidate in ./PrismLauncher ./prismlauncher ./bin/PrismLauncher ./bin/prismlauncher ./PrismLauncher.AppImage ./prismlauncher.AppImage; do
  if [ -x "$candidate" ] && [ -f "$candidate" ]; then
    LAUNCHER="$candidate"
    break
  fi
done
if [ -z "$LAUNCHER" ]; then
  for candidate in ./*PrismLauncher* ./prismlauncher* ./bin/*PrismLauncher* ./bin/prismlauncher*; do
    case "$candidate" in
      *updater*) continue ;;
    esac
    if [ -x "$candidate" ] && [ -f "$candidate" ]; then
      LAUNCHER="$candidate"
      break
    fi
  done
fi
if [ -z "$LAUNCHER" ]; then
  echo "Could not find the PrismLauncher executable."
  exit 1
fi
exec "$LAUNCHER" --launch {shell_quote(instance_id)} --offline "$PLAYER"
"""


def instance_display_name(instance_dir: Path) -> str:
    return parse_ini_key_values(instance_dir / "instance.cfg").get("name") or instance_dir.name


def unique_launcher_script_path(root: Path, stem: str, suffix: str, used: set[Path]) -> Path:
    path = root / f"{stem}{suffix}"
    if path not in used and not path.exists():
        used.add(path)
        return path
    for index in range(2, 1000):
        path = root / f"{stem} {index}{suffix}"
        if path not in used and not path.exists():
            used.add(path)
            return path
    raise PrefetchError(f"Could not create a unique launch helper name for {stem!r}.")


def write_offline_launch_helpers(root: Path) -> None:
    instances_dir = root / "instances"
    instance_dirs = [path for path in sorted(instances_dir.iterdir()) if path.is_dir()] if instances_dir.exists() else []
    if not instance_dirs:
        return

    used: set[Path] = set()
    for instance_dir in instance_dirs:
        display_name = instance_display_name(instance_dir)
        script_stem = "Launch Offline" if len(instance_dirs) == 1 else f"Launch Offline - {slugify(display_name, instance_dir.name)}"
        batch_path = unique_launcher_script_path(root, script_stem, ".bat", used)
        batch_path.write_text(
            launcher_executable_batch() + f'start "" "%LAUNCHER%" --launch "{instance_dir.name}" --offline "%PLAYER%"\n',
            encoding="utf-8",
            newline="\r\n",
        )

        shell_path = unique_launcher_script_path(root, script_stem, ".sh", used)
        shell_path.write_text(launcher_executable_shell(instance_dir.name), encoding="utf-8", newline="\n")
        try:
            shell_path.chmod(shell_path.stat().st_mode | 0o755)
        except OSError:
            pass


def configure_portable_launcher_settings(root: Path) -> None:
    # Prism checks this before deciding whether local metadata is enough in a normal launch.
    updates = {
        "MetaRefreshOnLaunch": "false",
        "DownloadGameFilesDuringInstanceCreation": "false",
        "LastOfflinePlayerName": "Player",
    }
    (root / "portable.txt").write_text("Portable data lives next to the launcher.\n", encoding="utf-8")
    primary = root / "prismlauncher.cfg"
    write_ini_key_values(primary, updates)
    for fallback_name in ("polymc.cfg", "multimc.cfg"):
        fallback = root / fallback_name
        if fallback.exists():
            write_ini_key_values(fallback, updates)
    write_offline_launch_helpers(root)


def slugify(value: str, fallback: str = "instance") -> str:
    value = re.sub(r"[^\w.\- ]+", "-", value, flags=re.UNICODE).strip()
    value = re.sub(r"[\s\-]+", "-", value).strip(".-")
    return value or fallback


def unique_child_dir(parent: Path, base_name: str) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    base = slugify(base_name)
    candidate = parent / base
    if not candidate.exists():
        return candidate
    for index in range(2, 1000):
        candidate = parent / f"{base}-{index}"
        if not candidate.exists():
            return candidate
    raise PrefetchError(f"Could not find an unused instance directory for {base_name!r}")


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        raise PrefetchError(f"Destination already exists: {dst}")
    shutil.copytree(src, dst)


def load_modpack_exporter() -> Any:
    script_path = Path(__file__).with_name("make_prism_modpack.py")
    if not script_path.exists():
        raise PrefetchError(f"Could not find make_prism_modpack.py next to {Path(__file__).name}")
    spec = importlib.util.spec_from_file_location("make_prism_modpack", script_path)
    if spec is None or spec.loader is None:
        raise PrefetchError(f"Could not import {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["make_prism_modpack"] = module
    spec.loader.exec_module(module)
    configure_exporter_ssl(module)
    return module


def configure_exporter_ssl(exporter: Any) -> None:
    if SSL_CONTEXT is not None:
        exporter.SSL_CONTEXT = SSL_CONTEXT
        exporter.SSL_CONTEXTS = (SSL_CONTEXT,)
    else:
        exporter.SSL_CONTEXT = None
        exporter.SSL_CONTEXTS = exporter.verified_ssl_contexts()


def split_modpack_urls(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def build_modpack_instances(args: argparse.Namespace, launcher_dir: Path, work_dir: Path) -> list[Any]:
    urls = split_modpack_urls(args.modpacks)
    if not urls:
        return []

    exporter = load_modpack_exporter()
    instances_dir = launcher_dir / "instances"
    builds: list[Any] = []
    for index, url in enumerate(urls, start=1):
        log(f"Building modpack instance {index}/{len(urls)}: {url}")
        pack_work = work_dir / "modpacks" / str(index)
        pack_work.mkdir(parents=True, exist_ok=True)
        pack_args = argparse.Namespace(
            url=url,
            output=None,
            version=args.modpack_version,
            name=args.modpack_name if len(urls) == 1 else None,
            concurrency=args.concurrency,
            retries=args.retries,
            skip_optional=args.skip_optional,
            no_icon=args.no_icon,
            curseforge_api_key=args.curseforge_api_key,
            keep_work_dir=None,
            insecure=False,
            self_test=False,
        )
        provider, identifier, url_version_selector = exporter.parse_pack_url(url)
        if url_version_selector and not pack_args.version:
            pack_args.version = url_version_selector
        if provider == "modrinth":
            try:
                build = exporter.build_modrinth_pack(identifier, pack_args, pack_work)
            except Exception as exc:  # noqa: BLE001 - normalize imported exporter errors.
                raise PrefetchError(str(exc)) from exc
        elif provider == "curseforge":
            try:
                build = exporter.build_curseforge_pack(identifier, pack_args, pack_work)
            except Exception as exc:  # noqa: BLE001 - normalize imported exporter errors.
                raise PrefetchError(str(exc)) from exc
        else:
            raise PrefetchError(f"Unsupported modpack provider for {url}")
        exporter.write_instance_files(build, pack_args)
        normalize_instance_minecraft_component(build)

        target = unique_child_dir(instances_dir, f"{build.name}-{build.version_name}")
        copy_tree(build.instance_root, target)
        log(f"  installed instance {target.relative_to(launcher_dir).as_posix()}")
        builds.append(build)
    return builds


def minecraft_version_from_build_metadata(build: Any) -> str | None:
    for attr in ("minecraft_version", "mc_version", "game_version"):
        value = str(getattr(build, attr, "") or "")
        if looks_like_minecraft_version(value):
            return value

    components = getattr(build, "components", ())
    for component in components:
        if str(getattr(component, "uid", "") or "") == "net.minecraft":
            value = str(getattr(component, "version", "") or "")
            if looks_like_minecraft_version(value):
                return value

    mrpack_index = Path(build.instance_root) / "mrpack" / "modrinth.index.json"
    if mrpack_index.exists():
        try:
            data = json.loads(mrpack_index.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        dependencies = data.get("dependencies") if isinstance(data, Mapping) else None
        if isinstance(dependencies, Mapping):
            value = str(dependencies.get("minecraft") or "")
            if looks_like_minecraft_version(value):
                return value
        game_versions = data.get("game_versions") if isinstance(data, Mapping) else None
        if isinstance(game_versions, list):
            for value in game_versions:
                version = str(value)
                if looks_like_minecraft_version(version):
                    return version
    flame_manifest = Path(build.instance_root) / "flame" / "manifest.json"
    if flame_manifest.exists():
        try:
            data = json.loads(flame_manifest.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
        minecraft = data.get("minecraft") if isinstance(data, Mapping) else None
        if isinstance(minecraft, Mapping):
            value = str(minecraft.get("version") or "").rstrip(".")
            if looks_like_minecraft_version(value):
                return value
    return None


def normalize_instance_minecraft_component(build: Any) -> None:
    metadata_version = minecraft_version_from_build_metadata(build)
    if not metadata_version:
        return
    pack_path = Path(build.instance_root) / "mmc-pack.json"
    if not pack_path.exists():
        return
    data = json.loads(pack_path.read_text(encoding="utf-8"))
    components = data.get("components")
    if not isinstance(components, list):
        return
    changed = False
    for component in components:
        if not isinstance(component, dict) or component.get("uid") != "net.minecraft":
            continue
        current_version = str(component.get("version") or "")
        if not looks_like_minecraft_version(current_version):
            log(f"Warning: replacing invalid Minecraft component version {current_version!r} with {metadata_version!r}.")
            component["version"] = metadata_version
            changed = True
        if component.get("cachedVersion"):
            component.pop("cachedVersion", None)
            changed = True
        if component.get("cachedName"):
            component.pop("cachedName", None)
            changed = True
    if not any(isinstance(component, Mapping) and component.get("uid") == "net.minecraft" for component in components):
        components.insert(0, {"uid": "net.minecraft", "version": metadata_version, "important": True})
        changed = True
    if changed:
        pack_path.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")


def components_from_mmc_pack(build: Any) -> list[tuple[str, str]]:
    pack_path = Path(build.instance_root) / "mmc-pack.json"
    if pack_path.exists():
        data = json.loads(pack_path.read_text(encoding="utf-8"))
        components = data.get("components")
        if isinstance(components, list):
            result: list[tuple[str, str]] = []
            for component in components:
                if isinstance(component, Mapping):
                    uid = str(component.get("uid") or "")
                    version = str(component.get("version") or "")
                    if uid and version:
                        result.append((uid, version))
            return result
    return [(str(component.uid), str(component.version)) for component in build.components]


def components_from_builds(builds: Sequence[Any], *, timeout: int) -> tuple[list[str], list[tuple[str, str]]]:
    minecraft_versions: list[str] = []
    component_versions: list[tuple[str, str]] = []
    for build in builds:
        metadata_minecraft_version = minecraft_version_from_build_metadata(build)
        minecraft_version = ""
        for uid, version in components_from_mmc_pack(build):
            if uid == "net.minecraft":
                minecraft_version = version if looks_like_minecraft_version(version) else (metadata_minecraft_version or version)
                if minecraft_version != version:
                    log(f"Warning: ignoring invalid Minecraft component version {version!r}; using {minecraft_version!r}.")
                minecraft_versions.append(minecraft_version)
            elif version == "recommended" and minecraft_version:
                component_versions.append((uid, resolve_prism_recommended_version(uid, minecraft_version, timeout=timeout)))
            else:
                component_versions.append((uid, version))
    return list(dict.fromkeys(minecraft_versions)), list(dict.fromkeys(component_versions))


def validate_local_asset_index(root: Path, metadata_path: Path, label: str, errors: list[str]) -> None:
    if not metadata_path.exists():
        return
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{label}: {metadata_path.relative_to(root).as_posix()} is not valid JSON: {exc}")
        return
    asset_info = metadata.get("assetIndex") if isinstance(metadata, Mapping) else None
    if not isinstance(asset_info, Mapping):
        errors.append(f"{label}: {metadata_path.relative_to(root).as_posix()} has no assetIndex.")
        return
    asset_id = str(asset_info.get("id") or "")
    asset_url = str(asset_info.get("url") or "")
    if not asset_id:
        errors.append(f"{label}: {metadata_path.relative_to(root).as_posix()} assetIndex has no id.")
        return
    expected_url = portable_local_file_url(f"assets/indexes/{asset_id}.json")
    if asset_url != expected_url:
        errors.append(
            f"{label}: {metadata_path.relative_to(root).as_posix()} assetIndex url is {asset_url!r}, expected {expected_url!r}."
        )
    asset_index_path = root / "assets" / "indexes" / f"{asset_id}.json"
    if not asset_index_path.exists():
        errors.append(f"{label}: missing assets/indexes/{asset_id}.json.")
        return
    expected_sha1 = str(asset_info.get("sha1") or "")
    if re.fullmatch(r"[a-fA-F0-9]{40}", expected_sha1) and file_hash(asset_index_path, "sha1") != expected_sha1.lower():
        errors.append(f"{label}: assets/indexes/{asset_id}.json does not match the Minecraft metadata SHA1.")


def validate_launcher_bundle(root: Path) -> LauncherValidation:
    errors: list[str] = []
    warnings: list[str] = []
    meta_index_path = root / "meta" / "index.json"
    if not meta_index_path.exists():
        warnings.append("meta/index.json is missing; Prism will need the network for component metadata.")

    cfg_values = parse_ini_key_values(root / "prismlauncher.cfg")
    if cfg_values.get("MetaRefreshOnLaunch", "").lower() not in {"false", "0"}:
        warnings.append("prismlauncher.cfg does not disable MetaRefreshOnLaunch.")

    instances_dir = root / "instances"
    if not instances_dir.exists():
        return LauncherValidation(ok=not errors, errors=tuple(errors), warnings=tuple(warnings))

    for pack_path in sorted(instances_dir.glob("*/mmc-pack.json")):
        instance_name = pack_path.parent.name
        try:
            data = json.loads(pack_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{instance_name}: mmc-pack.json is not valid JSON: {exc}")
            continue
        components = data.get("components")
        if not isinstance(components, list):
            errors.append(f"{instance_name}: mmc-pack.json has no components list.")
            continue
        minecraft_components = [
            component for component in components if isinstance(component, Mapping) and component.get("uid") == "net.minecraft"
        ]
        if not minecraft_components:
            errors.append(f"{instance_name}: missing net.minecraft component.")
        for component in minecraft_components:
            version = str(component.get("version") or "")
            if not looks_like_minecraft_version(version):
                errors.append(f"{instance_name}: net.minecraft version {version!r} does not look like a Minecraft version.")
                continue
            if component.get("cachedVersion") and str(component.get("cachedVersion")) != version:
                errors.append(f"{instance_name}: net.minecraft cachedVersion does not match version.")
            meta_path = root / "meta" / "net.minecraft" / f"{version}.json"
            patch_path = pack_path.parent / "patches" / "net.minecraft.json"
            version_path = root / "versions" / version / f"{version}.json"
            if not meta_path.exists():
                errors.append(f"{instance_name}: missing meta/net.minecraft/{version}.json.")
            if not patch_path.exists():
                errors.append(f"{instance_name}: missing patches/net.minecraft.json.")
            if not version_path.exists():
                errors.append(f"{instance_name}: missing versions/{version}/{version}.json.")
            if not (root / "versions" / version / f"{version}.jar").exists():
                errors.append(f"{instance_name}: missing versions/{version}/{version}.jar.")
            client_library_path = root / "libraries" / Path(*PurePosixPath(minecraft_client_library_path(version)).parts)
            if not client_library_path.exists():
                errors.append(f"{instance_name}: missing libraries/{minecraft_client_library_path(version)}.")
            validate_local_asset_index(root, meta_path, instance_name, errors)
            validate_local_asset_index(root, patch_path, instance_name, errors)
            validate_local_asset_index(root, version_path, instance_name, errors)
        for component in components:
            if not isinstance(component, Mapping):
                continue
            uid = str(component.get("uid") or "")
            version = str(component.get("version") or "")
            if not uid or not version or uid == "net.minecraft":
                continue
            if not (root / "meta" / uid / f"{version}.json").exists():
                errors.append(f"{instance_name}: missing meta/{uid}/{version}.json.")
            if not (root / "meta" / uid / "index.json").exists():
                errors.append(f"{instance_name}: missing meta/{uid}/index.json.")
            if not (pack_path.parent / "patches" / f"{uid}.json").exists():
                errors.append(f"{instance_name}: missing patches/{uid}.json.")
    return LauncherValidation(ok=not errors, errors=tuple(errors), warnings=tuple(warnings))


def report_validation(validation: LauncherValidation) -> None:
    for warning in validation.warnings:
        log(f"Warning: {warning}")
    if validation.errors:
        details = "\n".join(f"  - {error}" for error in validation.errors)
        raise PrefetchError("Generated launcher bundle failed validation:\n" + details)


def zip_dir(source_dir: Path, output_zip: Path) -> None:
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_dir():
                continue
            zf.write(path, path.relative_to(source_dir.parent).as_posix())


def move_or_replace(src: Path, dst: Path) -> Path:
    if dst.exists():
        raise PrefetchError(f"Output folder already exists: {dst}")
    shutil.move(str(src), str(dst))
    return dst


def default_output_zip(asset: LauncherAsset, root: Path) -> Path:
    return root / f"{launcher_archive_stem(asset.name)}-prefetched.zip"


def launcher_archive_stem(name: str) -> str:
    stem = name
    for suffix in (".tar.gz", ".tgz", ".zip", ".tar"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return stem


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download portable PrismLauncher and prefetch Minecraft assets, libraries, clients, and Temurin JREs."
    )
    parser.add_argument("--linux", action="store_true", help="Download Linux Qt6 portable PrismLauncher and Linux Temurin JREs.")
    parser.add_argument(
        "--versions",
        nargs="+",
        help="Minecraft versions to prefetch. If omitted and no --modpacks are supplied, an interactive selector is shown.",
    )
    parser.add_argument(
        "--modpacks",
        help="Comma-separated Modrinth or CurseForge modpack URLs to install as portable Prism instances.",
    )
    parser.add_argument(
        "--modpack-version",
        help="Version id/name/number for all --modpacks; file-id URLs still override this when omitted.",
    )
    parser.add_argument(
        "--modpack-name",
        help="Instance name for a single --modpacks URL.",
    )
    parser.add_argument(
        "--skip-optional",
        action="store_true",
        help="Skip optional modpack files. By default optional files are included disabled.",
    )
    parser.add_argument(
        "--no-icon",
        action="store_true",
        help="Do not download and embed modpack icons.",
    )
    parser.add_argument(
        "--curseforge-api-key",
        help="CurseForge API key for CurseForge modpacks; can also be supplied with CURSEFORGE_API_KEY.",
    )
    parser.add_argument(
        "--launcher-repo",
        default=DEFAULT_LAUNCHER_REPO,
        help=f"GitHub owner/repo for PrismLauncher releases. Default: {DEFAULT_LAUNCHER_REPO}",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output zip path. Defaults to '<portable-release-name>-prefetched.zip' in the current directory.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="Directory used for downloads and extraction. Defaults to a temporary directory.",
    )
    parser.add_argument(
        "--keep-extracted",
        action="store_true",
        help="Keep the extracted PrismLauncher directory after creating the zip.",
    )
    parser.add_argument(
        "--no-zip",
        action="store_true",
        help="Do not create a zip; implies --keep-extracted.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Concurrent file downloads. Default: {DEFAULT_CONCURRENCY}",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Download attempts per file. Default: {DEFAULT_RETRIES}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--java-arch",
        default=adoptium_arch(),
        help="Adoptium architecture value, such as x64 or aarch64. Defaults to this machine's architecture.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for this run.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    global SSL_CONTEXT, SSL_CONTEXTS

    args = parse_args(argv or sys.argv[1:])
    if args.no_zip:
        args.keep_extracted = True

    modpack_urls = split_modpack_urls(args.modpacks)

    os_name = "linux" if args.linux else "windows"

    temp_context: tempfile.TemporaryDirectory[str] | None = None
    if args.work_dir:
        work_dir = args.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_context = tempfile.TemporaryDirectory(prefix="prism-prefetch-")
        work_dir = Path(temp_context.name)

    try:
        if args.insecure:
            log("Warning: TLS certificate verification is disabled for this run.")
            SSL_CONTEXT = ssl._create_unverified_context()
        else:
            SSL_CONTEXTS = verified_ssl_contexts()

        if args.modpack_name and len(modpack_urls) != 1:
            raise PrefetchError("--modpack-name can only be used with exactly one --modpacks URL.")

        manifest = fetch_version_manifest()
        version_ids = args.versions if args.versions else ([] if modpack_urls else select_versions_interactively(manifest))

        launcher = find_launcher_asset(args.launcher_repo, linux=args.linux)
        output_zip = args.output or default_output_zip(launcher, Path.cwd())
        if output_zip.suffix.lower() != ".zip" and not args.no_zip:
            output_zip = output_zip.with_suffix(".zip")

        log(f"Launcher release: {args.launcher_repo} {launcher.release_tag}")
        launcher_archive = work_dir / "downloads" / launcher.name
        download_many(
            [DownloadItem(launcher.url, launcher_archive, size=launcher.size, label=launcher.name)],
            concurrency=1,
            retries=args.retries,
            timeout=args.timeout,
        )

        extract_dir = work_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        extracted_root = extract_archive(launcher_archive, extract_dir)
        launcher_dir = prepare_launcher_dir(extracted_root, work_dir / launcher_archive_stem(launcher.name))
        log(f"Extracted launcher to {launcher_dir}")

        builds = build_modpack_instances(args, launcher_dir, work_dir)
        modpack_versions, component_groups = component_inputs_by_build(builds, timeout=args.timeout)
        version_ids = list(dict.fromkeys([*version_ids, *modpack_versions]))
        version_entries = resolve_version_entries(manifest, version_ids)

        all_downloads: list[DownloadItem] = []
        metacache_items: list[MetaCacheItem] = []
        runtime_majors: set[int] = set()
        asset_indexes_for_reconstruct: list[tuple[str, Mapping[str, Any]]] = []
        meta_packages: dict[str, MetaPackage] = {}

        for entry in version_entries:
            downloads, cache_items, asset_indexes, java_major, minecraft_meta = prefetch_minecraft_version(
                entry,
                launcher_dir,
                os_name=os_name,
                timeout=args.timeout,
            )
            all_downloads.extend(downloads)
            metacache_items.extend(cache_items)
            asset_indexes_for_reconstruct.extend(asset_indexes)
            runtime_majors.add(java_major)
            add_meta_package_version(meta_packages, "net.minecraft", minecraft_meta)

        modpack_components = list(dict.fromkeys(component for _minecraft_version, components in component_groups for component in components))
        component_downloads: list[DownloadItem] = []
        for minecraft_version, components in component_groups:
            component_downloads.extend(
                collect_component_downloads(
                    components,
                    launcher_dir,
                    minecraft_version=minecraft_version,
                    os_name=os_name,
                    timeout=args.timeout,
                    meta_packages=meta_packages,
                )
            )
        all_downloads.extend(component_downloads)
        metacache_items.extend(write_meta_packages(launcher_dir, meta_packages))
        write_instance_component_patches(launcher_dir, builds, meta_packages)

        for lib_download in component_downloads:
            rel = lib_download.path.relative_to(launcher_dir / "libraries").as_posix()
            metacache_items.append(MetaCacheItem(base="libraries", relative_path=rel, path=lib_download.path))

        log(f"Downloading Minecraft cache files for {len(version_entries)} version(s) and {len(modpack_components)} loader component(s)")
        download_many(all_downloads, concurrency=args.concurrency, retries=args.retries, timeout=args.timeout)

        for asset_id, asset_index in asset_indexes_for_reconstruct:
            reconstruct_assets(asset_id, asset_index, launcher_dir)

        write_metacache(launcher_dir, metacache_items)
        configure_portable_launcher_settings(launcher_dir)
        report_validation(validate_launcher_bundle(launcher_dir))

        for java_major in sorted(runtime_majors):
            runtime = find_temurin_runtime(java_major, linux=args.linux, arch=args.java_arch)
            sha256 = read_checksum_from_url(runtime.checksum_url) if runtime.checksum_url else None
            runtime_archive = work_dir / "downloads" / runtime.archive_name
            log(f"Downloading Temurin JRE {java_major}: {runtime.release_name}")
            download_many(
                [DownloadItem(runtime.url, runtime_archive, sha256=sha256, label=runtime.archive_name)],
                concurrency=1,
                retries=args.retries,
                timeout=args.timeout,
            )
            target_java = stage_java_install(launcher_dir, runtime, runtime_archive, work_dir)
            log(f"  installed {target_java.relative_to(launcher_dir).as_posix()}")

        if not args.no_zip:
            log(f"Creating {output_zip}")
            zip_dir(launcher_dir, output_zip.resolve())

        kept_path: Path | None = None
        if args.keep_extracted:
            target = (Path.cwd() / launcher_dir.name).resolve()
            kept_path = move_or_replace(launcher_dir, target)
            log(f"Kept extracted launcher at {kept_path}")
        elif args.no_zip:
            kept_path = launcher_dir
            log(f"Extracted launcher is at {kept_path}")

        if not args.no_zip:
            log(f"Done: {output_zip.resolve()}")
        elif kept_path:
            log(f"Done: {kept_path}")
        return 0
    except KeyboardInterrupt:
        log("Cancelled.")
        return 130
    except PrefetchError as exc:
        log(f"Error: {exc}")
        return 1
    finally:
        if temp_context is not None:
            temp_context.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
