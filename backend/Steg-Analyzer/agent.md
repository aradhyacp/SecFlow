# Steg-Analyzer Context (Working Notes)

This file captures repository-specific context for `backend/Steg-Analyzer` so future changes can be made quickly and consistently.

## Scope

- Service type: Flask API + Redis/RQ worker + Postgres-backed state.
- Primary purpose: run multiple steganography-focused analyzers on uploaded images and store per-tool outputs in `results.json`.
- Runtime split:
  - `web` process handles API.
  - `worker` process executes analyzers asynchronously.
  - `initdb` initializes schema and IHDR lookup table.

## Key Paths

- App entrypoint: `secflow/app.py`
- Worker pipeline: `secflow/workers.py`
- Analyzer base abstraction: `secflow/analyzers/base_analyzer.py`
- Analyzer implementations: `secflow/analyzers/*.py`
- Models + cleanup: `secflow/models.py`
- Config: `secflow/config.py`
- WSGI target: `secflow/utils/wsgi.py`
- Local compose: `compose.yml`

## API Surface (current)

Blueprint prefix: `/api/steg-analyzer`

- `GET /api/steg-analyzer/`
  - Health/info message.
- `POST /api/steg-analyzer/upload`
  - Multipart form fields:
    - `image` (required)
    - `password` (optional)
    - `deep=true|false` (optional)
  - Enqueues async job and returns:
    - `{ "submission_hash": "<hash>" }`
- `GET /api/steg-analyzer/status/<hash>`
  - Returns submission status (`pending`, `running`, `completed`, `error`).
- `GET /api/steg-analyzer/result/<hash>`
  - Returns `{ "results": {...} }` when ready, else 425.
- `GET /api/steg-analyzer/infos/<hash>`
  - Metadata for image/submissions.
- `GET /api/steg-analyzer/download/<hash>/<tool>`
  - Downloads `<tool>.7z` if available.
- `POST /api/steg-analyzer/remove/<hash>`
  - Removes image/results under retention and IP ownership constraints.
- `POST /api/steg-analyzer/remove_password/<hash>`
  - Removes stored password under constraints.
- `GET /api/steg-analyzer/image/<img_name>`
- `GET /api/steg-analyzer/image/<hash>/<img_name>`

## Upload and Execution Flow

1. `upload` validates extension and max size.
2. MD5 image hash + submission hash are computed.
3. UploadLog is written (IP + User-Agent + hashes).
4. Existing submission short-circuits if same submission already exists.
5. Image/submission DB rows are created/updated.
6. RQ job `secflow.workers.analyze_image` is enqueued.
7. Worker loads submission + image, marks status `running`.
8. Worker starts one thread per analyzer and waits for all joins.
9. Analyzer outputs are merged into a shared `results.json`.
10. Submission status set to `completed` or `error`.

## Analyzer Framework

`SubprocessAnalyzer` in `base_analyzer.py` provides:

- subprocess execution with timeout `MAX_PENDING_TIME`
- optional extracted-output archiving to `.7z`
- synchronized `results.json` updates
  - thread lock + `fcntl` lock + atomic replace
- common result format:
  - success: `{ "status": "ok", "output": ..., "note"?: ..., "download"?: ... }`
  - error: `{ "status": "error", "error": ... }`

Current analyzers in worker list:

- `binwalk`, `color_remapping`, `decomposer`, `exiftool`, `file`, `foremost`,
  `identify`, `jpseek`, `jsteg`, `openstego`, `pngcheck`, `pcrt`, `strings`,
  `steghide`, `zsteg`
- deep-only: `outguess`

Notable detail:

- `color_remapping.py` is non-subprocess logic using `Pillow + numpy` and emits derived images under `/image/<submission>/<name>.png`.

## Data Model Notes

Tables in `models.py`:

- `Image`: canonical file record and upload counters.
- `Submission`: one analysis job variant (filename + password + deep flag).
- `IHDR`: CRC lookup data for PNG recovery workflows.
- `UploadLog`: audit trail by IP and user agent.

Cleanup behavior:

- stale `pending/running` submissions are removed after `MAX_PENDING_TIME`.
- old images/submissions removed after `MAX_STORE_TIME`.
- broken completed submissions without `results.json` are cleaned.

## Environment/Infra Notes

From `.env.example`:

- `DB_URI`, `POSTGRES_*`
- `REDIS_URL` (indirectly via defaults)
- `MAX_CONTENT_LENGTH`, `MAX_PENDING_TIME`, `MAX_STORE_TIME`
- `CLEAR_AT_RESTART`, `REMOVAL_MIN_AGE_SECONDS`

From `compose.yml`:

- app maps host `5000 -> container 5000`.
- separate services: `web`, `worker`, `redis`, `postgres`, `initdb`, `rqdashboard`.

## Integration Notes for SecFlow Orchestrator

Current API is async (`/upload` then poll `/status` + `/result`), while SecFlow docs expect a synchronous analyzer call pattern.

To integrate cleanly, choose one:

1. Adapter-level async bridge in orchestrator:
   - POST upload
   - poll status
   - fetch result
   - transform to SecFlow contract
2. Add a new synchronous endpoint in this service dedicated to orchestrator use.

Also note expected field mismatch:

- this service expects multipart field name `image` (not `file`).

## Safe Change Guidelines

- Do not remove locking in `update_result`; parallel analyzers depend on it.
- Preserve submission status transitions (`pending -> running -> completed/error`).
- Keep route prefix `/api/steg-analyzer` stable unless all consumers are updated.
- Avoid schema changes in `models.py` without migration planning.
- Keep analyzer failures isolated (one tool error should not fail full run).

## Quick Local Commands

From `backend/Steg-Analyzer/`:

```bash
docker compose up --build
```

Test upload:

```bash
curl -X POST "http://localhost:5000/api/steg-analyzer/upload" \
  -F "image=@example/example1.png"
```

Then query:

```bash
curl "http://localhost:5000/api/steg-analyzer/status/<submission_hash>"
curl "http://localhost:5000/api/steg-analyzer/result/<submission_hash>"
```
