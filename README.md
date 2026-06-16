# Modpacks Offline Prism Tools

This repo contains two Python scripts:

- `make_prism_modpack.py` creates a ready-to-import PrismLauncher, PolyMC, or MultiMC ZIP from a Modrinth or CurseForge modpack URL.
- `prefetch_prism_launcher.py` downloads a portable PrismLauncher build, preloads Minecraft assets/libraries/runtime files, and can also install modpack instances into that launcher.

## Requirements

- Python 3
- A CurseForge API key for CurseForge modpacks
- Optional: `certifi` as a fallback certificate bundle when Python's default trust store is stale

Both scripts use only Python's standard library otherwise.

## `make_prism_modpack.py`

Create a ZIP from a Modrinth modpack:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack"
```

Create a ZIP from a CurseForge modpack:

```powershell
$env:CURSEFORGE_API_KEY = "your-api-key"
python make_prism_modpack.py "https://www.curseforge.com/minecraft/modpacks/example-pack"
```

Create a ZIP from a specific CurseForge file from the pack's Files page:

```powershell
python make_prism_modpack.py "https://www.curseforge.com/minecraft/modpacks/wynncraft-plus/files/7740118"
```

You can also pass the CurseForge key directly:

```powershell
python make_prism_modpack.py "https://www.curseforge.com/minecraft/modpacks/example-pack" --curseforge-api-key "your-api-key"
```

By default, the ZIP is written to the current directory using the pack name and selected version, for example:

```text
OptiFabric-7.2.1.zip
```

Write to a specific output directory:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack" -o .\exports
```

Write to a specific ZIP path:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack" -o .\exports\OptiFabric.zip
```

Options:

```text
--version VERSION
    Version id, name, number, or CurseForge filename to export. Defaults to
    latest. For CurseForge packs, you can also use a Files page URL such as
    https://www.curseforge.com/minecraft/modpacks/wynncraft-plus/files/7740118.

--name NAME
    Instance name written to instance.cfg.

--concurrency N
    Number of concurrent file downloads. Defaults to 6.

--retries N
    Download attempts per URL. Defaults to 3.

--skip-optional
    Skip optional mods. By default optional mods are included as disabled
    .disabled files.

--no-icon
    Do not download and embed the pack thumbnail as the Prism instance icon.

--curseforge-api-key KEY
    CurseForge API key. You can also use the CURSEFORGE_API_KEY environment
    variable.

--keep-work-dir PATH
    Keep the temporary working directory for inspection or debugging.

--insecure
    Disable TLS certificate verification. Use only as a last resort when the
    local certificate store is broken.
```

Notes:

- CurseForge files marked as unavailable to third-party launchers cannot be downloaded by this script.
- Modrinth downloads verify hashes from the `.mrpack` metadata when available.
- CurseForge and Modrinth pack icons are embedded when available unless `--no-icon` is used.
- The script retries transient download failures and rate limits.

Troubleshooting:

If a Modrinth or CurseForge download fails with a certificate error, try running without `--insecure` first. The script already tries Python's default trust store, `certifi` if installed, and Windows root certificates when available.

If downloads still fail, update Python or your system certificates. Use `--insecure` only for a one-off run on a trusted network.

For debugging pack contents, keep the work directory:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack" --keep-work-dir .\work-optifabric
```

## `prefetch_prism_launcher.py`

Download a portable PrismLauncher build and prefill its shared Minecraft cache:

```powershell
python prefetch_prism_launcher.py --versions 1.21.8 1.20.1
```

Install modpacks into the portable launcher too:

```powershell
python prefetch_prism_launcher.py --modpacks "https://modrinth.com/modpack/optifabric-modpack"
```

Build the Linux portable bundle instead of the Windows one:

```powershell
python prefetch_prism_launcher.py --linux --versions 1.21.8
```

By default, the script downloads the latest Windows portable PrismLauncher release and writes `<portable-release-name>-prefetched.zip` in the current directory. Use `-o` for a different zip path, `--keep-extracted` to preserve the extracted launcher folder, or `--no-zip` to skip zip creation.

Options:

```text
--linux
    Download Linux Qt6 portable PrismLauncher and Linux Temurin JREs.

--versions VERSIONS [VERSIONS ...]
    Minecraft versions to prefetch. If omitted and no --modpacks are supplied,
    an interactive selector is shown.

--modpacks MODPACKS
    Comma-separated Modrinth or CurseForge modpack URLs to install as portable
    Prism instances. This expects make_prism_modpack.py to be present next to
    this script.

--modpack-version MODPACK_VERSION
    Version id/name/number for all --modpacks; file-id URLs still override this
    when omitted.

--modpack-name MODPACK_NAME
    Instance name for a single --modpacks URL.

--skip-optional
    Skip optional modpack files. By default optional files are included
    disabled.

--no-icon
    Do not download and embed modpack icons.

--curseforge-api-key CURSEFORGE_API_KEY
    CurseForge API key for CurseForge modpacks; can also be supplied with
    CURSEFORGE_API_KEY.

--launcher-repo LAUNCHER_REPO
    GitHub owner/repo for PrismLauncher releases. Default:
    Diegiwg/PrismLauncher-Cracked.

-o, --output OUTPUT
    Output zip path. Defaults to '<portable-release-name>-prefetched.zip' in
    the current directory.

--work-dir WORK_DIR
    Directory used for downloads and extraction. Defaults to a temporary
    directory.

--keep-extracted
    Keep the extracted PrismLauncher directory after creating the zip.

--no-zip
    Do not create a zip; implies --keep-extracted.

--concurrency CONCURRENCY
    Concurrent file downloads. Default: 8

--retries RETRIES
    Download attempts per file. Default: 3

--timeout TIMEOUT
    HTTP timeout in seconds. Default: 60

--java-arch JAVA_ARCH
    Adoptium architecture value, such as x64 or aarch64. Defaults to this
    machine's architecture.

--insecure
    Disable TLS certificate verification for this run.
```

Notes:

- The portable bundle includes the launcher, shared Minecraft cache data, and any installed modpack instances.
- The script retries transient download failures and certificate-store issues much like the pack exporter.

Troubleshooting:

If a download fails with a certificate error, try running without `--insecure` first. The script already tries Python's default trust store, `certifi` if installed, and Windows root certificates when available.

If downloads still fail, update Python or your system certificates. Use `--insecure` only for a one-off run on a trusted network.

For debugging the extracted launcher, keep it on disk:

```powershell
python prefetch_prism_launcher.py --versions 1.21.8 --keep-extracted
```
