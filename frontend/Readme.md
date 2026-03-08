# SecFlow Frontend

React + Vite dashboard for SecFlow analyzers.

## Run

```bash
npm install
npm run dev
```

## Backend Integration

The frontend now integrates these backend services:

- Orchestrator: `/api/smart-analyze`, `/api/health`, `/api/report/*`
- Malware Analyzer: `/api/malware-analyzer/*`
- Macro Analyzer: `/api/macro-analyzer/*`
- Steg Analyzer: `/api/steg-analyzer/*`
- Recon Analyzer: `/api/Recon-Analyzer/*`
- Web Analyzer: `/api/web-analyzer/*`

In local development, `vite.config.js` proxies each API route to the correct Docker Compose host port.

## Environment Overrides

If you need direct API URLs instead of proxy paths, copy `.env.example` to `.env` and uncomment the `VITE_*_API_BASE` values.