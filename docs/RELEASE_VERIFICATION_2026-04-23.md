# Release verification 2026-04-23

Verified release:

- Repository: https://github.com/Esperosa/service-fingerprinting-passive-analysis
- Tag: `v0.1.0-thesis`
- Asset: `bakula-program-20260423-083911.zip`
- Asset size: `69 423 335 B`
- SHA-256: `BA5076C7BC49568401A5DA24FC1C86C096BB0D54EFB629B0CDA92E928FC83B09`

Verification was performed from the ZIP downloaded from the GitHub release, not only from the local build folder.

## Contents checked

The release ZIP contains:

- `bakula-program.exe`
- static web UI in `ui/index.html`, `ui/app.js`, `ui/styles.css`
- demo/reference data in `data`
- controlled `nuclei` templates in `resources/nuclei-templates/controlled`
- bundled `httpx.exe` and `nuclei.exe` with license files for optional web checks
- smoke-test workspaces generated during local release preparation

## Commands executed

```powershell
gh release download v0.1.0-thesis `
  --repo Esperosa/service-fingerprinting-passive-analysis `
  --pattern bakula-program-20260423-083911.zip `
  --dir D:\Bakula\_release_verify\public-release

Get-FileHash D:\Bakula\_release_verify\public-release\bakula-program-20260423-083911.zip -Algorithm SHA256

Expand-Archive `
  -LiteralPath D:\Bakula\_release_verify\public-release\bakula-program-20260423-083911.zip `
  -DestinationPath D:\Bakula\_release_verify\public-release -Force

.\bakula-program.exe --help
.\bakula-program.exe demo e2e --workspace .\workspace_release_verify
.\bakula-program.exe server spust --workspace .\workspace_release_verify --host 127.0.0.1 --port 8131
```

HTTP checks against the running server:

- `GET /` returned `200` and contained the UI shell.
- `GET /app.js` returned `200`, length `167223`.
- `GET /styles.css` returned `200`, length `49955`.
- `GET /api/health` returned `200`, body `{"stav":"ok"}`.
- `GET /api/runs` returned `200`.

## Result

The release asset is usable: the executable starts, the demo workflow completes, and the packaged UI is served by the release binary.
