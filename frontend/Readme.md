# SecFlow — Frontend

> **Status: Planned — Not yet under development.**
> The backend pipeline is the current focus. Frontend development begins after the backend pipeline is stable and tested.

---

## Planned Scope

The frontend will provide a web-based interface for SecFlow, allowing users to:

- Upload files, paste URLs, IPs, or domains
- Choose between Full Auto-Pipeline mode or Single Analyzer mode
- Configure the loop depth (3, 4, or 5 passes)
- View real-time or post-run analysis progress
- Download the generated PWNDoc report (PDF / HTML / JSON)
- View a findings summary dashboard per analyzer pass

---

## Planned Tech Stack

| Layer | Technology (TBD) |
|---|---|
| Framework | React / Next.js (TBD) |
| Styling | TailwindCSS (TBD) |
| API Communication | REST or WebSocket to backend |
| File Upload | Multipart form / drag-and-drop |
| Report Viewer | PDF viewer component, JSON viewer |

---

## Notes

- Frontend communicates with the backend via a REST API exposed by the orchestrator.
- All analysis logic lives in the backend — the frontend is purely a presentation and interaction layer.
- See [backend/Readme.md](../backend/Readme.md) for the backend pipeline details.
