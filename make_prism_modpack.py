#!/usr/bin/env python3
"""
Create a PrismLauncher/PolyMC/MultiMC import ZIP from a Modrinth or CurseForge
modpack URL.

The output ZIP contains a ready-to-import instance root:

    instance.cfg
    mmc-pack.json
    minecraft/

Modrinth packs are fully supported through the public API. CurseForge packs need
the official CurseForge API; set CURSEFORGE_API_KEY or pass --curseforge-api-key.
Files that CurseForge marks as unavailable to third-party launchers cannot be
downloaded by this script.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import configparser
import contextlib
import dataclasses
import email.utils
import hashlib
import json
import os
import random
import re
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


MODRINTH_API = "https://api.modrinth.com/v2"
CURSEFORGE_API = "https://api.curseforge.com/v1"
PRISM_META_API = "https://meta.prismlauncher.org/v1"
USER_AGENT = "modpacks-offline-prism-exporter/1.0 (+https://prismlauncher.org)"
CHUNK_SIZE = 1024 * 1024
DEFAULT_CONCURRENCY = 6
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 60
SSL_CONTEXT: ssl.SSLContext | None = None
SSL_CONTEXTS: tuple[ssl.SSLContext | None, ...] = (None,)


class PackError(RuntimeError):
    """User-facing pack creation error."""


class DownloadError(PackError):
    """A download failed after all fallback URLs and retry attempts."""


class DownloadHTTPError(PackError):
    def __init__(self, url: str, status: int, detail: str, retry_after: str | None = None) -> None:
        self.url = url
        self.status = status
        self.detail = detail
        self.retry_after = retry_after
        super().__init__(f"HTTP {status} for {url}\n{detail}")


@dataclasses.dataclass(frozen=True)
class DownloadItem:
    url: str
    relative_path: str
    sha1: str | None = None
    sha512: str | None = None
    size: int | None = None
    required: bool = True
    display_name: str | None = None
    fallback_urls: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class Component:
    uid: str
    version: str
    important: bool = False
    cached_name: str | None = None
    cached_version: str | None = None


@dataclasses.dataclass(frozen=True)
class PackBuild:
    provider: str
    name: str
    version_name: str
    managed_id: str
    managed_version_id: str
    icon_key: str
    minecraft_dir: Path
    instance_root: Path
    components: tuple[Component, ...]
    recommended_ram: int | None = None
    manifest_dir_name: str | None = None
    icon_path: Path | None = None


def log(message: str) -> None:
    print(message, flush=True)


def slugify(value: str, fallback: str = "modpack") -> str:
    value = re.sub(r"[^\w.\- ]+", "-", value, flags=re.UNICODE).strip()
    value = re.sub(r"[\s\-]+", "-", value).strip(".-")
    return value or fallback


def normalize_zip_path(path: str) -> str:
    path = path.replace("\\", "/")
    path = re.sub(r"/+", "/", path).strip("/")
    if not path or path == ".":
        return ""
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") or ":" in part for part in pure.parts):
        raise PackError(f"Unsafe path in pack metadata: {path!r}")
    return pure.as_posix()


def safe_dest(root: Path, relative_path: str) -> Path:
    rel = normalize_zip_path(relative_path)
    if not rel:
        raise PackError("Empty file path in pack metadata.")
    return root / Path(*PurePosixPath(rel).parts)


def merge_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    for item in sorted(src.rglob("*")):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)


def safe_extract_zip(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            target = safe_dest(dest, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, CHUNK_SIZE)


def make_request(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 60,
) -> urllib.request.Request:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/octet-stream;q=0.9, */*;q=0.8",
    }
    if headers:
        request_headers.update(headers)
    return urllib.request.Request(url, data=data, headers=request_headers, method=method)


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


def open_url(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 60,
):
    request = make_request(url, method=method, headers=headers, data=data, timeout=timeout)
    last_certificate_error: urllib.error.URLError | None = None
    contexts = (SSL_CONTEXT,) if SSL_CONTEXT is not None else SSL_CONTEXTS
    for index, context in enumerate(contexts):
        try:
            return urllib.request.urlopen(request, timeout=timeout, context=context)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            raise DownloadHTTPError(url, exc.code, detail, retry_after) from exc
        except urllib.error.URLError as exc:
            if is_certificate_verify_error(exc) and index + 1 < len(contexts):
                last_certificate_error = exc
                continue
            raise PackError(f"Network error for {url}: {exc.reason}") from exc

    if last_certificate_error is not None:
        raise PackError(f"Network error for {url}: {last_certificate_error.reason}") from last_certificate_error
    raise PackError(f"Network error for {url}")


def modrinth_pack_name(project: Mapping[str, Any], selected: Mapping[str, Any], fallback: str) -> str:
    return str(project.get("title") or project.get("slug") or selected.get("name") or fallback)


def get_json(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    data_obj: Any | None = None,
    timeout: int = 60,
) -> Any:
    body = None
    method = "GET"
    final_headers = dict(headers or {})
    if data_obj is not None:
        body = json.dumps(data_obj).encode("utf-8")
        final_headers["Content-Type"] = "application/json"
        method = "POST"
    with open_url(url, method=method, headers=final_headers, data=body, timeout=timeout) as response:
        raw = response.read()
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise PackError(f"Invalid JSON returned from {url}") from exc


def download_file(
    urls: Iterable[str],
    dest: Path,
    *,
    sha1: str | None = None,
    sha512: str | None = None,
    expected_size: int | None = None,
    headers: Mapping[str, str] | None = None,
    label: str | None = None,
    retries: int = DEFAULT_RETRIES,
) -> None:
    errors: list[str] = []
    for url in urls:
        attempts = max(1, retries)
        for attempt in range(1, attempts + 1):
            temp = dest.with_suffix(dest.suffix + ".part")
            temp.parent.mkdir(parents=True, exist_ok=True)
            sha1_hash = hashlib.sha1() if sha1 else None
            sha512_hash = hashlib.sha512() if sha512 else None
            size = 0
            try:
                with open_url(url, headers=headers, timeout=DEFAULT_TIMEOUT) as response, temp.open("wb") as out:
                    while True:
                        chunk = response.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        out.write(chunk)
                        size += len(chunk)
                        if sha1_hash:
                            sha1_hash.update(chunk)
                        if sha512_hash:
                            sha512_hash.update(chunk)

                if expected_size is not None and size != expected_size:
                    raise PackError(f"expected {expected_size} bytes, got {size}")
                if sha1 and sha1_hash and sha1_hash.hexdigest().lower() != sha1.lower():
                    raise PackError(f"sha1 mismatch for {url}")
                if sha512 and sha512_hash and sha512_hash.hexdigest().lower() != sha512.lower():
                    raise PackError(f"sha512 mismatch for {url}")

                temp.replace(dest)
                return
            except Exception as exc:  # noqa: BLE001 - every fallback should be attempted.
                with contextlib.suppress(FileNotFoundError):
                    temp.unlink()
                errors.append(f"{url} (attempt {attempt}/{attempts}): {exc}")
                if isinstance(exc, DownloadHTTPError) and exc.status == 404:
                    break
                if attempt >= attempts or not is_retryable_download_error(exc):
                    break
                time.sleep(retry_delay_for(exc, attempt))
    name = label or dest.name
    raise DownloadError(f"Could not download {name}\n" + "\n".join(errors))


def batched(values: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def parse_pack_url(pack_url: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(pack_url)
    host = parsed.netloc.lower()
    parts = [part for part in parsed.path.split("/") if part]

    if host in {"modrinth.com", "www.modrinth.com"}:
        if len(parts) >= 2 and parts[0] == "modpack":
            return "modrinth", parts[1]
        raise PackError("Modrinth URL must look like https://modrinth.com/modpack/<slug>")

    if host in {"curseforge.com", "www.curseforge.com"}:
        if len(parts) >= 3 and parts[0] == "minecraft" and parts[1] == "modpacks":
            return "curseforge", parts[2]
        if len(parts) >= 2 and parts[0] == "projects":
            return "curseforge", parts[1]
        raise PackError("CurseForge URL must look like https://www.curseforge.com/minecraft/modpacks/<slug>")

    if parsed.scheme == "curseforge":
        query = urllib.parse.parse_qs(parsed.query)
        addon = query.get("addonId", [""])[0]
        if addon:
            return "curseforge", addon

    raise PackError(f"Unsupported modpack URL: {pack_url}")


def find_version(versions: list[dict[str, Any]], version_selector: str | None) -> dict[str, Any]:
    if not versions:
        raise PackError("No versions were returned for this modpack.")
    if not version_selector or version_selector.lower() == "latest":
        return versions[0]

    wanted = version_selector.lower()
    for version in versions:
        candidates = [
            str(version.get("id", "")),
            str(version.get("version_number", "")),
            str(version.get("name", "")),
            str(version.get("displayName", "")),
        ]
        if any(candidate.lower() == wanted for candidate in candidates):
            return version
    raise PackError(f"Could not find version {version_selector!r}.")


def modrinth_project_versions(project_id: str) -> list[dict[str, Any]]:
    encoded = urllib.parse.quote(project_id, safe="")
    versions = get_json(f"{MODRINTH_API}/project/{encoded}/version")
    if not isinstance(versions, list):
        raise PackError("Unexpected Modrinth project versions response.")
    return versions


def choose_modrinth_file(version: dict[str, Any]) -> dict[str, Any]:
    files = version.get("files") or []
    for file in files:
        if file.get("primary") and str(file.get("filename", "")).lower().endswith(".mrpack"):
            return file
    for file in files:
        if str(file.get("filename", "")).lower().endswith(".mrpack"):
            return file
    raise PackError("Selected Modrinth version does not contain a .mrpack file.")


def build_modrinth_pack(
    slug: str,
    args: argparse.Namespace,
    work_dir: Path,
) -> PackBuild:
    project = get_json(f"{MODRINTH_API}/project/{urllib.parse.quote(slug, safe='')}")
    project_id = str(project.get("id") or slug)
    versions = modrinth_project_versions(project_id)
    selected = find_version(versions, args.version)
    mrpack_file = choose_modrinth_file(selected)

    name = modrinth_pack_name(project, selected, slug)
    version_id = str(selected.get("id") or "")
    version_name = str(selected.get("version_number") or selected.get("name") or "latest")
    sha512 = (mrpack_file.get("hashes") or {}).get("sha512")
    sha1 = (mrpack_file.get("hashes") or {}).get("sha1")
    mrpack_path = work_dir / "download.mrpack"

    log(f"Downloading Modrinth pack {name} {version_name}")
    download_file(
        [str(mrpack_file["url"])],
        mrpack_path,
        sha1=sha1,
        sha512=sha512,
        expected_size=mrpack_file.get("size"),
        label=str(mrpack_file.get("filename") or "modpack.mrpack"),
        retries=max(1, int(args.retries)),
    )

    unpacked = work_dir / "mrpack-unpacked"
    unpacked.mkdir()
    safe_extract_zip(mrpack_path, unpacked)

    index_path = unpacked / "modrinth.index.json"
    if not index_path.exists():
        raise PackError("Downloaded .mrpack does not contain modrinth.index.json.")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    dependencies = index.get("dependencies") or {}
    minecraft_version = dependencies.get("minecraft")
    if not minecraft_version:
        raise PackError("Modrinth pack is missing the minecraft dependency.")

    instance_root = work_dir / "instance"
    minecraft_dir = instance_root / "minecraft"
    minecraft_dir.mkdir(parents=True)
    project_slug = str(project.get("slug") or slugify(name))
    logo_url = str(project.get("icon_url") or "")
    logo_name = f"{project_slug}{url_extension(logo_url)}"
    pack_icon_key = icon_key("modrinth", logo_name, project_slug)
    pack_icon_path = None
    if not args.no_icon:
        pack_icon_path = download_pack_icon(
            instance_root,
            pack_icon_key,
            logo_url,
            retries=max(1, int(args.retries)),
        )
    if pack_icon_path is None:
        pack_icon_key = "modrinth"

    mrpack_meta = instance_root / "mrpack"
    mrpack_meta.mkdir()
    shutil.copy2(index_path, mrpack_meta / "modrinth.index.json")
    merge_tree(unpacked / "overrides", minecraft_dir)
    merge_tree(unpacked / "client-overrides", minecraft_dir)

    downloads: list[DownloadItem] = []
    used_paths: dict[str, str] = {}
    for entry in index.get("files") or []:
        env = entry.get("env") or {}
        if env.get("client", "required") == "unsupported":
            continue

        relative_path = normalize_zip_path(str(entry.get("path") or ""))
        required = env.get("client", "required") != "optional"
        if not required and args.skip_optional:
            continue
        if not required:
            relative_path += ".disabled"

        urls = tuple(str(url) for url in (entry.get("downloads") or []) if url)
        if not urls:
            raise PackError(f"Modrinth file {relative_path!r} has no downloads.")
        hashes = entry.get("hashes") or {}
        identity = str(hashes.get("sha512") or hashes.get("sha1") or urls[0])
        unique_path = unique_relative_path(relative_path, used_paths, identity)
        if unique_path is None:
            continue
        relative_path = unique_path
        downloads.append(
            DownloadItem(
                url=urls[0],
                fallback_urls=urls[1:],
                relative_path=relative_path,
                sha1=hashes.get("sha1"),
                sha512=hashes.get("sha512"),
                size=entry.get("fileSize"),
                required=required,
            )
        )

    download_items(downloads, minecraft_dir, "Modrinth files", args=args)
    components = components_from_dependencies(dependencies)

    return PackBuild(
        provider="modrinth",
        name=name,
        version_name=version_name,
        managed_id=project_id,
        managed_version_id=version_id,
        icon_key=pack_icon_key,
        minecraft_dir=minecraft_dir,
        instance_root=instance_root,
        components=components,
        icon_path=pack_icon_path,
        manifest_dir_name="mrpack",
    )


def components_from_dependencies(dependencies: Mapping[str, str]) -> tuple[Component, ...]:
    components = [Component("net.minecraft", str(dependencies["minecraft"]), important=True)]
    mapping = [
        ("quilt-loader", "org.quiltmc.quilt-loader", "Quilt Loader"),
        ("fabric-loader", "net.fabricmc.fabric-loader", "Fabric Loader"),
        ("forge", "net.minecraftforge", "Forge"),
        ("neoforge", "net.neoforged", "NeoForge"),
    ]
    for key, uid, name in mapping:
        if dependencies.get(key):
            version = str(dependencies[key])
            components.append(Component(uid, version, cached_name=name, cached_version=version))
    return tuple(components)


def curseforge_headers(api_key: str) -> dict[str, str]:
    return {"x-api-key": api_key}


def curseforge_download_headers(url: str, api_key: str) -> dict[str, str] | None:
    return curseforge_headers(api_key) if urllib.parse.urlparse(url).netloc == "api.curseforge.com" else None


def url_extension(url: str, default: str = ".png") -> str:
    suffix = Path(urllib.parse.urlparse(url).path).suffix.lower()
    if suffix in {".svg", ".png", ".ico", ".gif", ".jpg", ".jpeg", ".webp"}:
        return suffix
    return default


def icon_key(provider: str, logo_name: str, fallback: str) -> str:
    raw = logo_name or fallback
    raw = sanitize_filename(raw)
    ext = filename_extension(raw) or Path(raw).suffix
    if ext:
        raw = raw[: -len(ext)]
    return f"{provider}_{raw or sanitize_filename(fallback)}"


def download_pack_icon(
    instance_root: Path,
    key: str,
    url: str | None,
    *,
    headers: Mapping[str, str] | None = None,
    retries: int = DEFAULT_RETRIES,
) -> Path | None:
    if not url:
        return None
    extension = url_extension(url)
    icon_file = instance_root / f"{key}{extension}"
    try:
        log(f"Downloading pack icon {key}{extension}")
        download_file([url], icon_file, headers=headers, retries=retries, label=f"{key}{extension}")
        return icon_file
    except PackError as exc:
        log(f"Warning: could not download pack icon: {exc}")
        with contextlib.suppress(FileNotFoundError):
            icon_file.unlink()
        return None


def retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    with contextlib.suppress(ValueError):
        return max(0.0, float(value))
    parsed = email.utils.parsedate_to_datetime(value)
    if parsed is None:
        return None
    return max(0.0, parsed.timestamp() - time.time())


def is_retryable_download_error(exc: BaseException) -> bool:
    if isinstance(exc, DownloadHTTPError):
        return exc.status == 429 or 500 <= exc.status < 600
    if isinstance(exc, PackError):
        text = str(exc).lower()
        return any(marker in text for marker in ("network error", "mismatch", "expected"))
    return isinstance(exc, (TimeoutError, ConnectionError, OSError))


def retry_delay_for(exc: BaseException, attempt: int) -> float:
    if isinstance(exc, DownloadHTTPError) and exc.status == 429:
        retry_after = retry_after_seconds(exc.retry_after)
        if retry_after is not None:
            return min(retry_after, 60.0)
        return min(10.0 * (2 ** max(0, attempt - 1)), 60.0)
    return min(1.5 * (2 ** max(0, attempt - 1)), 15.0) + random.uniform(0.0, 0.5)


def curseforge_search_project(slug_or_id: str, api_key: str) -> dict[str, Any]:
    headers = curseforge_headers(api_key)
    if slug_or_id.isdigit():
        data = get_json(f"{CURSEFORGE_API}/mods/{slug_or_id}", headers=headers)
        return data["data"]

    query = urllib.parse.urlencode(
        {
            "gameId": 432,
            "classId": 4471,
            "slug": slug_or_id,
            "pageSize": 50,
        }
    )
    data = get_json(f"{CURSEFORGE_API}/mods/search?{query}", headers=headers)
    matches = data.get("data") or []
    for project in matches:
        if str(project.get("slug", "")).lower() == slug_or_id.lower():
            return project
    if matches:
        return matches[0]

    query = urllib.parse.urlencode(
        {
            "gameId": 432,
            "classId": 4471,
            "searchFilter": slug_or_id,
            "pageSize": 50,
        }
    )
    data = get_json(f"{CURSEFORGE_API}/mods/search?{query}", headers=headers)
    matches = data.get("data") or []
    for project in matches:
        if str(project.get("slug", "")).lower() == slug_or_id.lower():
            return project
    if not matches:
        raise PackError(f"Could not find CurseForge modpack {slug_or_id!r}.")
    return matches[0]


def curseforge_project_files(project_id: int, api_key: str) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    index = 0
    page_size = 50
    headers = curseforge_headers(api_key)
    while True:
        query = urllib.parse.urlencode({"pageSize": page_size, "index": index})
        data = get_json(f"{CURSEFORGE_API}/mods/{project_id}/files?{query}", headers=headers)
        chunk = data.get("data") or []
        files.extend(chunk)
        pagination = data.get("pagination") or {}
        total = int(pagination.get("totalCount") or len(files))
        if len(files) >= total or not chunk:
            break
        index += len(chunk)
    return files


def curseforge_file_details(file_ids: list[int], api_key: str) -> list[dict[str, Any]]:
    if not file_ids:
        return []
    headers = curseforge_headers(api_key)
    out: list[dict[str, Any]] = []
    for group in batched(file_ids, 50):
        data = get_json(f"{CURSEFORGE_API}/mods/files", headers=headers, data_obj={"fileIds": group})
        out.extend(data.get("data") or [])
    return out


def curseforge_project_details(project_ids: list[int], api_key: str) -> dict[int, dict[str, Any]]:
    if not project_ids:
        return {}
    headers = curseforge_headers(api_key)
    out: dict[int, dict[str, Any]] = {}
    for group in batched(project_ids, 50):
        data = get_json(f"{CURSEFORGE_API}/mods", headers=headers, data_obj={"modIds": group})
        for project in data.get("data") or []:
            out[int(project["id"])] = project
    return out


def choose_curseforge_file(files: list[dict[str, Any]], version_selector: str | None) -> dict[str, Any]:
    modpack_files = [
        file
        for file in files
        if str(file.get("fileName", "")).lower().endswith(".zip")
        and int(file.get("releaseType") or 0) in {1, 2, 3}
    ]
    if not modpack_files:
        raise PackError("No CurseForge modpack ZIP files were returned.")
    return find_version(modpack_files, version_selector)


def curseforge_hashes(file: Mapping[str, Any]) -> tuple[str | None, str | None]:
    sha1 = None
    md5 = None
    for entry in file.get("hashes") or []:
        algo = int(entry.get("algo") or 0)
        if algo == 1:
            sha1 = str(entry.get("value") or "")
        elif algo == 2:
            md5 = str(entry.get("value") or "")
    return sha1 or None, md5 or None


def modrinth_versions_by_sha1(sha1_values: list[str]) -> dict[str, dict[str, Any]]:
    if not sha1_values:
        return {}
    data = get_json(
        f"{MODRINTH_API}/version_files",
        data_obj={"hashes": sha1_values, "algorithm": "sha1"},
    )
    if isinstance(data, dict):
        return data
    return {}


def resource_type_from_class_id(class_id: int | None) -> str:
    if class_id == 17:
        return "saves"
    if class_id == 12:
        return "resourcepacks"
    if class_id == 6552:
        return "shaderpacks"
    if class_id == 6945:
        return "datapacks"
    return "mods"


def report_output_dir(args: argparse.Namespace) -> Path:
    if args.keep_work_dir:
        return Path(args.keep_work_dir).resolve()
    if args.output:
        output = Path(args.output).resolve()
        return output.parent if output.suffix.lower() == ".zip" else output
    return Path.cwd()


def build_curseforge_pack(
    slug_or_id: str,
    args: argparse.Namespace,
    work_dir: Path,
) -> PackBuild:
    api_key = args.curseforge_api_key or os.environ.get("CURSEFORGE_API_KEY")
    if not api_key:
        raise PackError(
            "CurseForge support requires an API key. Set CURSEFORGE_API_KEY or pass --curseforge-api-key."
        )

    project = curseforge_search_project(slug_or_id, api_key)
    project_id = int(project["id"])
    files = curseforge_project_files(project_id, api_key)
    selected = choose_curseforge_file(files, args.version)

    name = str(project.get("name") or selected.get("displayName") or slug_or_id)
    version_name = str(selected.get("displayName") or selected.get("fileName") or selected.get("id"))
    version_id = str(selected.get("id"))
    selected_sha1, _ = curseforge_hashes(selected)
    archive_path = work_dir / "download.zip"
    download_url = selected.get("downloadUrl")
    if not download_url:
        raise PackError(
            f"CurseForge file {selected.get('fileName')!r} has no API download URL. "
            "Choose another version or download the pack ZIP manually."
        )

    log(f"Downloading CurseForge pack {name} {version_name}")
    download_file(
        [str(download_url)],
        archive_path,
        sha1=selected_sha1,
        expected_size=selected.get("fileLength"),
        headers=curseforge_download_headers(str(download_url), api_key),
        label=str(selected.get("fileName") or "modpack.zip"),
        retries=max(1, int(args.retries)),
    )

    unpacked = work_dir / "curseforge-unpacked"
    unpacked.mkdir()
    safe_extract_zip(archive_path, unpacked)

    manifest_path = unpacked / "manifest.json"
    if not manifest_path.exists():
        raise PackError("Downloaded CurseForge pack does not contain manifest.json.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    minecraft = manifest.get("minecraft") or {}
    minecraft_version = str(minecraft.get("version") or "").rstrip(".")
    if not minecraft_version:
        raise PackError("CurseForge manifest is missing minecraft.version.")
    manifest_version = str(manifest.get("version") or "").strip()
    if manifest_version:
        version_name = manifest_version

    instance_root = work_dir / "instance"
    minecraft_dir = instance_root / "minecraft"
    minecraft_dir.mkdir(parents=True)
    logo = project.get("logo") or {}
    logo_url = str(logo.get("thumbnailUrl") or logo.get("url") or "")
    logo_name = str(logo.get("title") or f"{slugify(name)}{url_extension(logo_url)}")
    pack_icon_key = icon_key("curseforge", logo_name, str(project_id))
    pack_icon_path = None
    if not args.no_icon:
        pack_icon_path = download_pack_icon(
            instance_root,
            pack_icon_key,
            logo_url,
            headers=curseforge_download_headers(logo_url, api_key) if logo_url else None,
            retries=max(1, int(args.retries)),
        )
    if pack_icon_path is None:
        pack_icon_key = "flame"

    flame_meta = instance_root / "flame"
    flame_meta.mkdir()
    shutil.copy2(manifest_path, flame_meta / "manifest.json")
    overrides_name = str(manifest.get("overrides") or "overrides")
    merge_tree(unpacked / overrides_name, minecraft_dir)

    mod_entries = manifest.get("files") or []
    file_ids = [int(entry["fileID"]) for entry in mod_entries]
    file_data = {int(file["id"]): file for file in curseforge_file_details(file_ids, api_key)}
    project_ids = sorted({int(entry["projectID"]) for entry in mod_entries})
    project_data = curseforge_project_details(project_ids, api_key)

    sha1_for_blocked: list[str] = []
    for file in file_data.values():
        url = str(file.get("downloadUrl") or "")
        sha1, _ = curseforge_hashes(file)
        if not url and sha1:
            sha1_for_blocked.append(sha1)
    modrinth_fallbacks = modrinth_versions_by_sha1(sha1_for_blocked)

    downloads: list[DownloadItem] = []
    missing: list[str] = []
    used_paths: dict[str, str] = {}
    for entry in mod_entries:
        file_id = int(entry["fileID"])
        project_id_for_file = int(entry["projectID"])
        required = bool(entry.get("required", True))
        if not required and args.skip_optional:
            continue
        file = file_data.get(file_id)
        if not file:
            missing.append(f"{project_id_for_file}/{file_id}: API did not return file details")
            continue
        raw_file_name = str(file.get("fileName") or f"{file_id}.jar")

        sha1, _ = curseforge_hashes(file)
        urls: list[str] = []
        if file.get("downloadUrl"):
            urls.append(str(file["downloadUrl"]))
        if sha1 and sha1 in modrinth_fallbacks:
            modrinth_file = ((modrinth_fallbacks[sha1] or {}).get("files") or [{}])[0]
            fallback_url = modrinth_file.get("url")
            if fallback_url:
                urls.append(str(fallback_url))
        if not urls:
            website = (
                f"https://www.curseforge.com/projects/{project_id_for_file}/files/{file_id}"
            )
            missing.append(f"{sanitize_filename(raw_file_name)} ({website})")
            continue

        file_name = normalize_curseforge_filename(raw_file_name, urls)
        project_info = project_data.get(project_id_for_file, {})
        target_folder = resource_type_from_class_id(project_info.get("classId"))
        if int(project_info.get("classId") or 0) == 17:
            target_folder = "saves"
        relative_path = normalize_zip_path(f"{target_folder}/{file_name}")
        if not required:
            relative_path += ".disabled"
        identity = f"{project_id_for_file}-{file_id}"
        unique_path = unique_relative_path(relative_path, used_paths, identity)
        if unique_path is None:
            continue
        relative_path = unique_path

        downloads.append(
            DownloadItem(
                url=urls[0],
                fallback_urls=tuple(urls[1:]),
                relative_path=relative_path,
                sha1=sha1,
                size=file.get("fileLength"),
                required=required,
                display_name=file_name,
            )
        )

    if missing:
        report_dir = report_output_dir(args)
        report_dir.mkdir(parents=True, exist_ok=True)
        report = report_dir / f"{slugify(name)}-{slugify(version_name, 'latest')}-missing-files.txt"
        report.write_text("\n".join(missing) + "\n", encoding="utf-8")
        raise PackError(
            "Some CurseForge files are unavailable through the third-party API:\n"
            + "\n".join(f"  - {item}" for item in missing[:25])
            + ("\n  ..." if len(missing) > 25 else "")
            + f"\nFull list: {report}"
        )

    download_items(downloads, minecraft_dir, "CurseForge files", headers=curseforge_headers(api_key), args=args)
    components = components_from_curseforge_manifest(minecraft, minecraft_version)
    recommended_ram = manifest.get("minecraft", {}).get("recommendedRam")

    return PackBuild(
        provider="flame",
        name=name,
        version_name=version_name,
        managed_id=str(project_id),
        managed_version_id=version_id,
        icon_key=pack_icon_key,
        minecraft_dir=minecraft_dir,
        instance_root=instance_root,
        components=components,
        recommended_ram=recommended_ram if isinstance(recommended_ram, int) and recommended_ram > 0 else None,
        icon_path=pack_icon_path,
        manifest_dir_name="flame",
    )


def components_from_curseforge_manifest(minecraft: Mapping[str, Any], minecraft_version: str) -> tuple[Component, ...]:
    components = [Component("net.minecraft", minecraft_version, important=True)]
    for loader in minecraft.get("modLoaders") or []:
        loader_id = str(loader.get("id") or "")
        uid = None
        name = None
        version = None
        if loader_id.startswith("neoforge-"):
            version = remove_prefix(loader_id, "neoforge-")
            if version.startswith("1.20.1-"):
                version = remove_prefix(version, "1.20.1-")
            uid = "net.neoforged"
            name = "NeoForge"
        elif loader_id.startswith("forge-"):
            version = remove_prefix(loader_id, "forge-")
            uid = "net.minecraftforge"
            name = "Forge"
        elif loader_id.startswith("fabric-"):
            version = remove_prefix(loader_id, "fabric-")
            uid = "net.fabricmc.fabric-loader"
            name = "Fabric Loader"
        elif loader_id.startswith("quilt-"):
            version = remove_prefix(loader_id, "quilt-")
            uid = "org.quiltmc.quilt-loader"
            name = "Quilt Loader"
        if uid and version:
            if version == "recommended":
                version = resolve_recommended_loader(uid, minecraft_version)
            components.append(Component(uid, version, cached_name=name, cached_version=version))
            break
    return tuple(components)


def resolve_recommended_loader(uid: str, minecraft_version: str) -> str:
    index = get_json(f"{PRISM_META_API}/{uid}/index.json")
    versions = index.get("versions") or []
    for version in versions:
        if version.get("recommended") is not True:
            continue
        requires = version.get("requires") or []
        if any(req.get("uid") == "net.minecraft" and req.get("equals") == minecraft_version for req in requires):
            return str(version["version"])
    raise PackError(f"Could not resolve recommended loader {uid} for Minecraft {minecraft_version}.")


def sanitize_filename(file_name: str) -> str:
    file_name = file_name.replace("\\", "_").replace("/", "_")
    file_name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", file_name)
    file_name = file_name.strip(" .")
    return file_name or "download.jar"


def collapse_repeated_extension(file_name: str) -> str:
    for ext in (".jar", ".zip", ".mrpack"):
        doubled = ext + ext
        while file_name.lower().endswith(doubled):
            file_name = file_name[: -len(ext)]
    return file_name


def collapse_repeated_leading_groups(stem: str) -> str:
    parts = stem.split("-")
    if len(parts) < 5:
        return stem
    max_group = min(8, len(parts) // 2)
    for group_size in range(2, max_group + 1):
        group = parts[:group_size]
        repeats = 1
        while parts[repeats * group_size : (repeats + 1) * group_size] == group:
            repeats += 1
        if repeats > 1 and repeats * group_size < len(parts):
            return "-".join(group + parts[repeats * group_size :])
    return stem


def filename_extension(file_name: str) -> str:
    lowered = file_name.lower()
    for ext in (".jar", ".zip", ".mrpack"):
        if lowered.endswith(ext):
            return ext
    return ""


def normalize_curseforge_filename(file_name: str, urls: Iterable[str]) -> str:
    name = collapse_repeated_extension(sanitize_filename(file_name))
    ext = filename_extension(name)
    if not ext:
        for url in urls:
            url_name = sanitize_filename(urllib.parse.unquote(PurePosixPath(urllib.parse.urlparse(url).path).name))
            ext = filename_extension(collapse_repeated_extension(url_name))
            if ext:
                name += ext
                break

    name = collapse_repeated_extension(name)
    ext = filename_extension(name)
    stem = name[: -len(ext)] if ext else name
    stem = collapse_repeated_leading_groups(stem)
    return stem + ext


def unique_relative_path(
    relative_path: str,
    used_paths: dict[str, str],
    identity: str,
) -> str | None:
    normalized = normalize_zip_path(relative_path)
    key = normalized.casefold()
    previous = used_paths.get(key)
    if previous == identity:
        return None
    if previous is None:
        used_paths[key] = identity
        return normalized

    disabled_suffix = ".disabled" if normalized.endswith(".disabled") else ""
    raw_path = normalized[: -len(disabled_suffix)] if disabled_suffix else normalized
    folder, _, file_name = raw_path.rpartition("/")
    stem, ext = os.path.splitext(file_name)
    safe_identity = sanitize_filename(identity)
    prefix = f"{folder}/" if folder else ""
    for index in range(1, 1000):
        suffix = safe_identity if index == 1 else f"{safe_identity}-{index}"
        candidate = normalize_zip_path(f"{prefix}{stem}-{suffix}{ext}{disabled_suffix}")
        candidate_key = candidate.casefold()
        if candidate_key not in used_paths:
            used_paths[candidate_key] = identity
            return candidate
    raise PackError(f"Could not create a unique destination for {relative_path!r}")


def remove_prefix(value: str, prefix: str) -> str:
    return value[len(prefix) :] if value.startswith(prefix) else value


def download_items(
    downloads: list[DownloadItem],
    minecraft_dir: Path,
    label: str,
    *,
    headers: Mapping[str, str] | None = None,
    args: argparse.Namespace,
) -> None:
    if not downloads:
        log(f"No {label} to download.")
        return

    concurrency = max(1, int(args.concurrency))
    retries = max(1, int(args.retries))
    log(f"Downloading {len(downloads)} {label} with {concurrency} concurrent downloads ({retries} tries each).")

    def worker(item: DownloadItem) -> str:
        dest = safe_dest(minecraft_dir, item.relative_path)
        item_headers = headers if urllib.parse.urlparse(item.url).netloc == "api.curseforge.com" else None
        download_file(
            [item.url, *item.fallback_urls],
            dest,
            sha1=item.sha1,
            sha512=item.sha512,
            expected_size=item.size,
            headers=item_headers,
            label=item.display_name or item.relative_path,
            retries=retries,
        )
        return item.relative_path

    failures: list[str] = []
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_item = {executor.submit(worker, item): item for item in downloads}
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            try:
                path = future.result()
                completed += 1
                log(f"[{completed}/{len(downloads)}] Finished {path}")
            except Exception as exc:  # noqa: BLE001 - collect all failed files like Prism's NetJob.
                completed += 1
                failures.append(f"{item.relative_path}: {exc}")
                log(f"[{completed}/{len(downloads)}] Failed {item.relative_path}")

    if failures:
        raise DownloadError("One or more downloads failed:\n" + "\n\n".join(failures))


def write_instance_files(build: PackBuild, args: argparse.Namespace) -> None:
    write_instance_cfg(build, args)
    write_mmc_pack(build)


def ini_bool(value: bool) -> str:
    return "true" if value else "false"


def write_instance_cfg(build: PackBuild, args: argparse.Namespace) -> None:
    cfg_path = build.instance_root / "instance.cfg"
    name = args.name or build.name
    cfg = configparser.RawConfigParser()
    cfg.optionxform = str
    cfg["General"] = {
        "ConfigVersion": "1.3",
        "InstanceType": "OneSix",
        "name": name,
        "iconKey": build.icon_key,
        "ManagedPack": ini_bool(True),
        "ManagedPackType": build.provider,
        "ManagedPackID": build.managed_id,
        "ManagedPackName": build.name,
        "ManagedPackVersionID": build.managed_version_id,
        "ManagedPackVersionName": build.version_name,
        "lastLaunchTime": "0",
        "lastTimePlayed": "0",
        "totalTimePlayed": "0",
    }
    if build.recommended_ram:
        cfg["General"]["OverrideMemory"] = ini_bool(True)
        cfg["General"]["MaxMemAlloc"] = str(build.recommended_ram)

    with cfg_path.open("w", encoding="utf-8", newline="\n") as out:
        cfg.write(out, space_around_delimiters=False)


def write_mmc_pack(build: PackBuild) -> None:
    components = []
    for component in build.components:
        obj: dict[str, Any] = {
            "uid": component.uid,
            "version": component.version,
        }
        if component.important:
            obj["important"] = True
        if component.cached_name:
            obj["cachedName"] = component.cached_name
        if component.cached_version:
            obj["cachedVersion"] = component.cached_version
        components.append(obj)

    data = {"formatVersion": 1, "components": components}
    (build.instance_root / "mmc-pack.json").write_text(
        json.dumps(data, indent=4, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def create_zip(instance_root: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(instance_root.rglob("*")):
            if path.is_dir():
                continue
            arcname = path.relative_to(instance_root).as_posix()
            zf.write(path, arcname)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="prism-pack-self-test-") as temp:
        root = Path(temp) / "instance"
        minecraft = root / "minecraft"
        minecraft.mkdir(parents=True)
        safe_dest(minecraft, "mods/fabric-api-0.146.1+26.1.2.jar")
        safe_dest(minecraft, "mods/ferritecore-9.0.0-fabric.jar")
        try:
            safe_dest(minecraft, "../escape.jar")
        except PackError:
            pass
        else:
            raise PackError("Self-test failed: path traversal was not rejected.")
        repeated = "Distant-Horizons-Iris-Shaders-Distant-Horizons-Iris-Shaders-Distant-Horizons-Iris-Shaders-0.4.1-26.1.2-Fabric.zip.zip"
        fixed = normalize_curseforge_filename(repeated, [])
        expected = "Distant-Horizons-Iris-Shaders-0.4.1-26.1.2-Fabric.zip"
        if fixed != expected:
            raise PackError(f"Self-test failed: normalized {fixed!r}, expected {expected!r}.")
        used: dict[str, str] = {}
        first = unique_relative_path("mods/example.jar", used, "project-file-a")
        duplicate_same = unique_relative_path("mods/example.jar", used, "project-file-a")
        duplicate_other = unique_relative_path("mods/example.jar", used, "project-file-b")
        if first != "mods/example.jar" or duplicate_same is not None or duplicate_other == "mods/example.jar":
            raise PackError("Self-test failed: duplicate destination handling is broken.")
        noisy_build = PackBuild(
            provider="flame",
            name="Distant Horizons & Iris Shaders",
            version_name="Distant Horizons & Iris Shaders Distant Horizons & Iris Shaders 0.4.1 26.1.2 Fabric.zip",
            managed_id="1156104",
            managed_version_id="7985845",
            icon_key="flame",
            minecraft_dir=minecraft,
            instance_root=root,
            components=(Component("net.minecraft", "26.1.2", important=True),),
        )
        output_name = default_output_path(noisy_build, str(Path(temp) / "out")).name
        if output_name.endswith(".zip.zip") or "Distant-Horizons-Iris-Shaders-Distant-Horizons-Iris-Shaders-Distant-Horizons-Iris-Shaders" in output_name:
            raise PackError(f"Self-test failed: bad output name {output_name!r}.")
        modrinth_name = modrinth_pack_name({"title": "Optifabric"}, {"name": "7.2.1", "version_number": "7.2.1"}, "optifabric")
        if modrinth_name != "Optifabric":
            raise PackError(f"Self-test failed: Modrinth pack name is {modrinth_name!r}.")
        modrinth_output_name = default_output_path(
            PackBuild(
                provider="modrinth",
                name=modrinth_name,
                version_name="7.2.1",
                managed_id="bHUKuhiA",
                managed_version_id="DgreaLlQ",
                icon_key="modrinth",
                minecraft_dir=minecraft,
                instance_root=root,
                components=(Component("net.minecraft", "1.21.8", important=True),),
            ),
            str(Path(temp) / "out"),
        ).name
        if modrinth_output_name != "Optifabric-7.2.1.zip":
            raise PackError(f"Self-test failed: bad Modrinth output name {modrinth_output_name!r}.")
        (minecraft / "mods").mkdir()
        (minecraft / "config").mkdir()
        (minecraft / "kubejs").mkdir()
        (minecraft / "mods" / "example.jar").write_bytes(b"example")
        (minecraft / "config" / "example.toml").write_text("enabled=true\n", encoding="utf-8")
        (minecraft / "kubejs" / "startup_scripts").mkdir(parents=True)
        (minecraft / "kubejs" / "startup_scripts" / "example.js").write_text("// test\n", encoding="utf-8")
        icon_file = root / "modrinth_self-test.png"
        icon_file.write_bytes(b"\x89PNG\r\n\x1a\n")
        args = argparse.Namespace(name=None)
        build = PackBuild(
            provider="modrinth",
            name="Self Test Pack",
            version_name="1.0.0",
            managed_id="self-test",
            managed_version_id="self-test-version",
            icon_key="modrinth_self-test",
            minecraft_dir=minecraft,
            instance_root=root,
            components=(
                Component("net.minecraft", "1.20.1", important=True),
                Component("net.fabricmc.fabric-loader", "0.15.11", cached_name="Fabric Loader", cached_version="0.15.11"),
            ),
            icon_path=icon_file,
        )
        write_instance_files(build, args)
        output = Path(temp) / "self-test.zip"
        create_zip(root, output)
        with zipfile.ZipFile(output) as zf:
            names = set(zf.namelist())
            cfg_text = zf.read("instance.cfg").decode("utf-8")
        required = {
            "instance.cfg",
            "modrinth_self-test.png",
            "mmc-pack.json",
            "minecraft/mods/example.jar",
            "minecraft/config/example.toml",
            "minecraft/kubejs/startup_scripts/example.js",
        }
        missing = required - names
        if missing:
            raise PackError(f"Self-test ZIP missing files: {sorted(missing)}")
        if "iconKey=modrinth_self-test" not in cfg_text:
            raise PackError("Self-test ZIP has the wrong iconKey.")
    log("Self-test passed.")


def default_output_path(build: PackBuild, output_arg: str | None) -> Path:
    base_name = normalize_curseforge_filename(
        f"{slugify(build.name)}-{slugify(build.version_name, 'latest')}.zip",
        [],
    )
    if output_arg:
        path = Path(output_arg)
        if path.suffix.lower() != ".zip":
            path.mkdir(parents=True, exist_ok=True)
            return path / base_name
        return path
    return Path.cwd() / base_name


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a PrismLauncher import ZIP from a CurseForge or Modrinth modpack URL."
    )
    parser.add_argument("url", nargs="?", help="Modrinth or CurseForge modpack URL")
    parser.add_argument("-o", "--output", help="Output ZIP path or output directory")
    parser.add_argument("--version", help="Version id/name/number to export; defaults to latest")
    parser.add_argument("--name", help="Instance name written to instance.cfg")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help=f"Concurrent file downloads; PrismLauncher defaults to {DEFAULT_CONCURRENCY}.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Download attempts per URL; PrismLauncher retries failed NetJobs up to {DEFAULT_RETRIES} times.",
    )
    parser.add_argument(
        "--skip-optional",
        action="store_true",
        help="Do not include optional mods. By default they are included as disabled .disabled files.",
    )
    parser.add_argument(
        "--no-icon",
        action="store_true",
        help="Do not download and embed the Modrinth/CurseForge pack thumbnail as the Prism instance icon.",
    )
    parser.add_argument(
        "--curseforge-api-key",
        help="CurseForge API key; can also be supplied with CURSEFORGE_API_KEY",
    )
    parser.add_argument(
        "--keep-work-dir",
        help="Keep the working directory at this path for inspection/debugging",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification. Use only when the local certificate store is broken.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def run(argv: list[str]) -> int:
    global SSL_CONTEXT, SSL_CONTEXTS

    args = parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if not args.url:
        raise PackError("A Modrinth or CurseForge modpack URL is required.")
    if args.concurrency < 1:
        raise PackError("--concurrency must be at least 1.")
    if args.retries < 1:
        raise PackError("--retries must be at least 1.")
    if args.insecure:
        log("Warning: TLS certificate verification is disabled for this run.")
        SSL_CONTEXT = ssl._create_unverified_context()
    else:
        SSL_CONTEXTS = verified_ssl_contexts()
    provider, identifier = parse_pack_url(args.url)
    started = time.time()

    if args.keep_work_dir:
        work_dir = Path(args.keep_work_dir).resolve()
        if work_dir.exists():
            raise PackError(f"--keep-work-dir path already exists: {work_dir}")
        work_dir.mkdir(parents=True)
        cleanup = contextlib.nullcontext(work_dir)
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="prism-pack-")

    with cleanup as temp:
        work_dir = Path(temp).resolve()
        if provider == "modrinth":
            build = build_modrinth_pack(identifier, args, work_dir)
        elif provider == "curseforge":
            build = build_curseforge_pack(identifier, args, work_dir)
        else:
            raise PackError(f"Unsupported provider: {provider}")

        write_instance_files(build, args)
        output_path = default_output_path(build, args.output).resolve()
        log(f"Writing PrismLauncher import ZIP: {output_path}")
        create_zip(build.instance_root, output_path)

    elapsed = time.time() - started
    log(f"Done in {elapsed:.1f}s")
    return 0


def main() -> None:
    try:
        raise SystemExit(run(sys.argv[1:]))
    except PackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("Canceled.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
