# Integrating Existing Malware Analyzer into SecFlow Orchestration

This guide explains how to integrate your existing `Malware-Analyzer` service into the SecFlow orchestration pipeline without rewriting analyzer internals.

## Goal

Use the analyzer as an external HTTP microservice and normalize its response through an adapter so the orchestrator can:

1. call it in any loop pass,
2. store findings in a unified format,
3. let AI route to the next analyzer.

## Integration Model

Keep analyzer code unchanged. Add integration logic in the orchestrator layer only:

1. `orchestrator` calls malware service over HTTP.
2. `malware_adapter.py` converts analyzer-native JSON into SecFlow contract.
3. `FindingsStore` saves normalized result.
4. `AI Decision Engine` uses `raw_output` + findings to choose next tool.

## 1. Place the Malware Analyzer Service

Expected backend layout:

```text
backend/
  Malware-Analyzer/            # your existing service (or malware-analyzer/)
  orchestrator/                # SecFlow orchestrator service
  compose.yml
```

Recommended: use lowercase service directory for consistency:

```text
backend/malware-analyzer/
```

If your folder is `Malware-Analyzer`, either:

1. keep it and point `compose.yml` build path to it, or
2. rename to `malware-analyzer` and update references once.

## 2. Expose a Stable Malware API Route

Orchestrator expects an HTTP endpoint like:

```text
POST /api/malware-analyzer/
Content-Type: multipart/form-data
file=<binary>
```

Response can remain analyzer-native JSON. Do not force analyzer to return SecFlow contract directly.

## 3. Add Malware Service to `backend/compose.yml`

```yaml
services:
  malware-analyzer:
    build: ./Malware-Analyzer   # or ./malware-analyzer
    ports:
      - "5001:5001"
    networks:
      - secflow-net

  orchestrator:
    build: ./orchestrator
    environment:
      - MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
    depends_on:
      - malware-analyzer
    networks:
      - secflow-net

networks:
  secflow-net:
    driver: bridge
```

## 4. Register Service URL in Orchestrator

In orchestrator config (for example `app/orchestrator.py`):

```python
ANALYZER_URLS = {
    "malware": os.getenv(
        "MALWARE_ANALYZER_URL",
        "http://malware-analyzer:5001/api/malware-analyzer/",
    ),
}
```

Add to `.env.example`:

```env
MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
```

## 5. Implement `malware_adapter.py`

Create:

```text
backend/orchestrator/app/adapters/malware_adapter.py
```

Adapter input:

1. raw analyzer JSON,
2. current pass number,
3. original input.

Adapter output must be SecFlow contract:

```python
{
  "analyzer": "malware",
  "pass": 2,
  "input": "/tmp/payload.exe",
  "findings": [
    {"type": "signature_match", "detail": "...", "severity": "critical", "evidence": "..."}
  ],
  "risk_score": 8.5,
  "raw_output": "{...raw malware json...}"
}
```

Severity policy (recommended):

1. `critical` = 4.0
2. `high` = 2.5
3. `medium` = 1.0
4. `low` = 0.3
5. `info` = 0.0

`risk_score = min(10.0, sum(weights))`

## 6. Wire Adapter into Orchestrator Dispatch

In orchestrator analyzer map:

```python
ADAPTERS = {
    "malware": malware_adapter.adapt,
}
```

In HTTP call logic:

```python
if tool == "malware":
    with open(input_data, "rb") as f:
        resp = requests.post(url, files={"file": f}, timeout=120)
```

If call fails, return error-shaped finding instead of crashing the pipeline.

## 7. First-Pass Classification Rule

Ensure classifier routes executable inputs to malware on pass 1:

1. MIME matches executable/PE/ELF, or
2. magic output indicates PE/ELF/Mach-O.

Important: when deterministic rule matches on pass 1, do not call AI before malware analyzer.

## 8. Multi-Pass Behavior

Malware can run:

1. as first analyzer for executable inputs, or
2. later if AI selects it (for example, steg extracted an `.exe`).

After malware pass:

1. store normalized output,
2. pass result to AI decision engine,
3. continue with returned `next_tool` or stop if `null`.

## 9. Validation Checklist

1. `docker compose up --build` starts malware service and orchestrator.
2. Direct malware API call returns JSON.
3. Orchestrator can trigger malware in pass 1 for `.exe`.
4. Adapter output always includes required fields.
5. `risk_score` stays within `0.0-10.0`.
6. HTTP failures from malware return graceful `error` finding.
7. Pipeline does not crash if malware returns unexpected JSON keys.
8. Findings are persisted and visible in final report.

## 10. Common Integration Issues

1. Service name mismatch in Docker URL.
2. Route mismatch (`/api/malware-analyzer/` vs different path).
3. Wrong request format (must be multipart file upload).
4. Adapter assumes keys not present in real response.
5. Timeout too low for large binaries.

## 11. Minimal End-to-End Test

1. Submit suspicious executable to orchestrator:
   - `POST /api/smart-analyze?passes=3` with file upload.
2. Verify pass 1 analyzer is `malware`.
3. Confirm response includes:
   - `findings_summary[0].analyzer == "malware"`
   - `findings_summary[0].findings` list
   - non-empty `raw_output`.
4. Confirm report generation still succeeds after malware integration.

---

If you also want, add a second doc for `Steg-Analyzer -> Malware` transition flow (embedded payload extraction to malware pass) as a dedicated integration scenario.
