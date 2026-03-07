# SecFlow — Pipeline Flow

This document describes the precise logic of the SecFlow analysis pipeline from input submission to report generation.

---

## Pipeline Entry Point

The user submits one of:
- A **file** (any format: PNG, JPG, EXE, PDF, ZIP, TXT, etc.)
- A **URL** string
- An **IP address** string
- A **domain** string

The user also specifies (or defaults to) a **max passes** value: `3`, `4`, or `5`.

---

## Stage 1 — Input Classification (Pass 1 Only)

```
User Input
    │
    ▼
┌─────────────────────────────────────────────┐
│  file command + python-magic                │
│  Determine: MIME type, file type string     │
└─────────────┬───────────────────────────────┘
              │
     ┌────────▼─────────┐
     │ Deterministic    │
     │ Rule Match?      │
     └────────┬─────────┘
              │
    ┌─────────┴────────────┐
   Yes                     No (unknown type)
    │                       │
    ▼                       ▼
Route to first          AI Fallback:
analyzer by rule        Pass to Gemini:
(see table below)       - file/magic output
                        - head -100 of file
                        → Gemini returns first_tool
```

### Routing Rules (Deterministic)

| Condition | First Analyzer |
|---|---|
| MIME type is `image/*` (PNG, JPG, BMP, GIF…) | Steganography Analyzer |
| MIME type is `application/x-executable`, `application/x-dosexec`, PE binary | Malware Analyzer |
| Input is a valid URL string | Web Vulnerability Analyzer |
| Input is a valid IP address or domain | Reconnaissance Analyzer |
| None of the above | AI Fallback (Gemini) |

---

## Stage 2 — Analyzer Execution

The selected analyzer runs on the input and produces a structured output object:

```python
{
    "analyzer": "steg",          # which analyzer ran
    "pass": 1,                   # current pass number
    "input": "suspicious.png",   # what was analyzed
    "findings": [...],           # list of finding dicts
    "risk_score": 7.5,           # 0.0 – 10.0
    "raw_output": "..."          # raw tool output (text)
}
```

This output is **immediately appended to the Findings Store**.

---

## Stage 3 — AI Routing Decision

After each analyzer run, the orchestrator submits the analyzer output to the AI Decision Engine:

```
Analyzer Output (raw_output)
    │
    ▼
┌────────────────────────────────────────────┐
│  AI Decision Engine (Gemini tool-calling)  │
│                                            │
│  Prompt includes:                          │
│  - Current analyzer name                  │
│  - raw_output of this pass                │
│  - Available tools: malware, steg,         │
│    recon, web (excluding current)          │
│  - Pass counter and max passes             │
└────────────┬───────────────────────────────┘
             │
    ┌────────▼──────────┐
    │  Gemini confident? │
    └────────┬──────────┘
             │
    ┌────────┴───────────────┐
   Yes                       No
    │                         │
    ▼                         ▼
Return next_tool        Fallback strategy:
                        1. If unclear → pass full output to Gemini
                        2. If noisy   → grep keywords.txt
                                        pass matched lines to Gemini
                        → return next_tool
```

### AI Response Contract

```python
{
    "next_tool": "malware" | "steg" | "recon" | "web" | None,
    "reasoning": "..."   # human-readable explanation
}
```

`next_tool: None` = terminate the loop now.

---

## Stage 4 — Loop Control

```
┌─────────────────────────────────────────────────────┐
│                  Orchestrator Loop                  │
│                                                     │
│  current_pass = 1                                   │
│  max_passes = N  (user-configured: 3, 4, or 5)      │
│                                                     │
│  while current_pass <= max_passes:                  │
│                                                     │
│    1. Run analyzer(current_tool, input)             │
│    2. Append output → Findings Store                │
│    3. AI Decision → next_tool                       │
│    4. If next_tool is None: BREAK (early exit)      │
│    5. current_tool = next_tool                      │
│    6. input = extract_relevant_input(last_findings) │
│    7. current_pass += 1                             │
│                                                     │
│  → Proceed to Report Generation                     │
└─────────────────────────────────────────────────────┘
```

### Early Termination Conditions

| Condition | Action |
|---|---|
| AI returns `next_tool: None` | Break loop immediately |
| Max passes reached | Break loop after completing current pass |
| Analyzer returns no findings (`findings: []`) | Optionally break (configurable) |

---

## Stage 5 — Report Generation

Once the loop ends:

```
Findings Store (all passes)
    │
    ▼
┌──────────────────────────────────────────┐
│  Report Generator                        │
│                                          │
│  1. Serialize Findings Store → JSON      │
│  2. Pass to Gemini with PWNDoc template  │
│  3. Validate output vs pwndoc_schema     │
│  4. Render output:                       │
│     - JSON (raw structured)              │
│     - PDF (rendered)                     │
│     - HTML (rendered)                    │
└──────────────────────────────────────────┘
```

### Report Contents

- **Threat summary** per analyzer with pass number
- **Overall risk score** (aggregated across all passes)
- **Findings timeline** (pass 1 → pass N)
- **Actionable recommendations** per finding
- **Metadata:** input file, total passes run, timestamp

---

## Full Walk-Through Example

```
Input: suspicious.png   Max passes: 5

─── Pass 1 ──────────────────────────────────────────
Classifier: image/png → Steg Analyzer
Steg Analyzer output: embedded EXE found (steg_payload.exe)
AI Decision: → Malware Analyzer (found an EXE payload)
Findings Store: [steg_pass1]

─── Pass 2 ──────────────────────────────────────────
Malware Analyzer input: steg_payload.exe
Malware Analyzer output: C2 callout to http://192.168.1.100/beacon
AI Decision: → Web Analyzer (found HTTP callout URL)
Findings Store: [steg_pass1, mal_pass2]

─── Pass 3 ──────────────────────────────────────────
Web Analyzer input: http://192.168.1.100/beacon
Web Analyzer output: endpoint alive, CVE-XXXX-XXXX found
AI Decision: → Recon Analyzer (found a live IP)
Findings Store: [steg_pass1, mal_pass2, web_pass3]

─── Pass 4 ──────────────────────────────────────────
Recon Analyzer input: 192.168.1.100
Recon Analyzer output: open ports, ASN data, threat intel match
AI Decision: → None (no further signals)
Findings Store: [steg_pass1, mal_pass2, web_pass3, recon_pass4]

EARLY EXIT at pass 4 (AI signalled no further analysis needed).

─── Report Generation ───────────────────────────────
All 4 pass findings → Gemini → PWNDoc
Output: report.json, report.pdf, report.html
```

---

## Input Extraction Between Passes

When the AI selects the next analyzer, the orchestrator must extract the appropriate input for that analyzer from the previous findings:

| Next Analyzer | Extract from Findings |
|---|---|
| Malware | File path of any extracted binary/executable |
| Steganography | File path of any extracted image |
| Reconnaissance | First IP address or domain found |
| Web | First URL or HTTP endpoint found |

If no extractable input is found, the pipeline logs a warning and ends the loop early.
