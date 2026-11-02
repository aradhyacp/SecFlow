# SecFlow — AI Model Migration History: Gemini → Groq → OpenRouter

> **Historical note:** the Groq orchestrator has been retired. The active
> orchestrator is TypeScript/LangGraph and uses OpenRouter
> (`OPENROUTER_MODEL`, default `nvidia/nemotron-3-ultra-550b-a55b:free`). See
> [ts-migration/11-cutover.md](ts-migration/11-cutover.md). The analyzer
> services and their optional Gemini endpoints are unchanged.

This document covers the history of SecFlow's AI integration, why the team migrated from Google Gemini to Groq, and what changed technically.

---

## Original Architecture (Gemini)

SecFlow was initially designed around **Google Gemini** (`gemini-1.5-flash` / `gemini-2.0-flash`), using the `google-generativeai` Python SDK.

The AI Decision Engine called Gemini after each analyzer pass, asking it to select the next tool. The integration used Gemini's native function-calling schema to constrain output to a structured `{"next_tool": ..., "reasoning": ...}` response.

**Problems encountered with Gemini:**

1. **Slow response times.** Gemini flash models on the free tier often had high latency (3–8 seconds per call), which multiplied across 3–5 loop passes.
2. **Unpredictable JSON output.** Despite function-calling prompts, Gemini would occasionally return narrative text rather than structured JSON, requiring extra post-processing.
3. **Rate limit instability.** The free tier hit quota limits during testing with large binaries (Ghidra output is verbose).
4. **No chain-of-thought toggle.** Flash models produced verbose reasoning that bloated responses even when only the routing decision was needed.
5. **SDK maintenance overhead.** The `google-generativeai` SDK has a different interface from the widely-used OpenAI SDK, complicating code and contributor ramp-up.

---

## Migration to Groq

The team migrated to **Groq** with model `qwen/qwen3-32b`.

Groq uses LPU (Language Processing Unit) inference hardware, which delivers ultra-low latency for large models. The `qwen/qwen3-32b` model is run entirely on Groq infrastructure.

**Why Groq was chosen:**

| Factor | Gemini | Groq + Qwen3-32B |
|---|---|---|
| Inference latency | 3–8 s | 0.3–1.5 s |
| SDK compatibility | Proprietary `google-generativeai` | OpenAI-compatible (`openai>=1.0`) |
| JSON reliability | Inconsistent | Consistent with explicit prompt instruction |
| Chain-of-thought | Always on (flash) | `/no_think` disables it for speed |
| Free tier rate limits | Quota errors at scale | Comfortably handles pipeline volumes |
| Model parameter count | ~8B (flash) | 32B — better instruction following |

---

## What Changed in `engine.py`

**Before (Gemini):**
```python
import google.generativeai as genai

genai.configure(api_key=os.environ["GEMINI_API_KEY"])
model = genai.GenerativeModel("gemini-1.5-flash")
response = model.generate_content(prompt)
text = response.text
```

**After (Groq via OpenAI SDK):**
```python
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1",
)

response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=[
        {"role": "system", "content": "/no_think"},
        {"role": "user",   "content": prompt},
    ],
    temperature=0.1,
)
text = response.choices[0].message.content
```

The `base_url` swap is the only infrastructure change — everything else uses the standard OpenAI SDK interface.

---

## The `/no_think` System Message

`qwen/qwen3-32b` is a "thinking" model: by default it outputs a long chain-of-thought reasoning block before the final answer. SecFlow does not need the reasoning text — only the final JSON routing decision matters.

Prefixing the system message with `/no_think` instructs Qwen3 to skip chain-of-thought and return only the final answer. This reduces response size by ~80% and latency by ~50% in typical routing calls.

---

## Env Var Changes

| Removed | Added |
|---|---|
| `GEMINI_API_KEY` | `GROQ_API_KEY` |

Update your `.env` file:

```
# Remove:
GEMINI_API_KEY=...

# Add:
GROQ_API_KEY=gsk_...
```

The Malware Analyzer and Web Analyzer still have their own optional `GEMINI_API_KEY` for their internal AI summary features (`/ai-summary`, `/diagram-generator`). Those are called independently of the Orchestrator's AI engine and are unaffected by the Groq migration.

---

## Requirements Changes

```
# Remove:
google-generativeai>=0.8.0

# Add:
openai>=1.0.0
```

---

## Macro Analyzer: Why It Is a Separate Service

When Office document / VBA macro analysis was added, it was implemented as a new microservice (`macro-analyzer`) rather than extending the Malware Analyzer. Reasons:

1. **Different base image.** Macro analysis needs `oletools` (Python) and is lightweight. Malware analysis needs JDK 21 + Ghidra (4 GB). Merging them would balloon the malware container unnecessarily.
2. **Different input types.** `.docx`/`.xlsm`/`.pptx` are not PE binaries — the malware analyzer rejects them (HTTP 400 for non-EXE extensions).
3. **Different risk model.** VBA macro risk is computed from olevba indicator categories. PE risk is computed from Ghidra decompile + AV detections.
4. **Independent scalability.** Macro analysis is fast (< 5s). Malware analysis is slow (30–180s due to Ghidra JVM). A separate service prevents macro requests from queuing behind large binary analyses.

---

## Download-and-Analyze: Not a New Service

The download-and-analyze feature lives entirely inside `orchestrator.py`. It is not a new microservice. The Orchestrator:

1. Scans `raw_output` for HTTP/S URLs using regex.
2. Downloads the file to a temp directory (50 MB cap, streaming).
3. Picks the right existing analyzer by content-type / extension / python-magic.
4. Routes to that analyzer in the next loop pass.
5. Cleans up temp files after the loop ends.

Download chains (e.g., Office doc → macro analysis → download `.exe` → malware analysis → C2 IP → recon analysis) are handled entirely within the main loop at no extra infrastructure cost.
