# Modpacks Offline Prism Exporter

Create a ready-to-import PrismLauncher, PolyMC, or MultiMC ZIP from a Modrinth or CurseForge modpack URL.

The generated ZIP contains an instance root with:

```text
instance.cfg
mmc-pack.json
minecraft/
```

Modrinth packs are downloaded through the public Modrinth API. CurseForge packs use the official CurseForge API and require an API key.

## Requirements

- Python 3
- A CurseForge API key for CurseForge modpacks

The script uses only Python's standard library. If the optional `certifi` package is installed, it can be used as a fallback certificate bundle when Python's default certificate store is stale.

## Basic Usage

Create a ZIP from a Modrinth modpack:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack"
```

Create a ZIP from a CurseForge modpack:

```powershell
$env:CURSEFORGE_API_KEY = "your-api-key"
python make_prism_modpack.py "https://www.curseforge.com/minecraft/modpacks/example-pack"
```

You can also pass the CurseForge key directly:

```powershell
python make_prism_modpack.py "https://www.curseforge.com/minecraft/modpacks/example-pack" --curseforge-api-key "your-api-key"
```

## Output

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

## Options

```text
--version VERSION
    Version id, name, or number to export. Defaults to latest.

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

## Notes

- CurseForge files marked as unavailable to third-party launchers cannot be downloaded by this script.
- Modrinth downloads verify hashes from the `.mrpack` metadata when available.
- CurseForge and Modrinth pack icons are embedded when available unless `--no-icon` is used.
- The script retries transient download failures and rate limits.

## Troubleshooting

If a Modrinth or CurseForge download fails with a certificate error, try running without `--insecure` first. The script already tries Python's default trust store, `certifi` if installed, and Windows root certificates when available.

If downloads still fail, update Python or your system certificates. Use `--insecure` only for a one-off run on a trusted network.

For debugging pack contents, keep the work directory:

```powershell
python make_prism_modpack.py "https://modrinth.com/modpack/optifabric-modpack" --keep-work-dir .\work-optifabric
```
