# AI-Driven SOC Analyst Panel

This is the project's React analyst UI. It is built with Vite, React, Ant Design, React Query and Tailwind CSS.

## Local development

```bash
npm install
npm run dev
```

For a standalone local frontend, set `VITE_API_URL=http://localhost:8000` in `.env.local`.

## Production deployment

From the repository root:

```bash
npm run panel:install
npm run panel:build
npm start
```

The Express backend serves the built panel at `/panel/` and falls back to the React entrypoint for client-side routes.

## V1 AI workflow

- Every alert stays in the queue.
- `AI Analyze` calls `POST /alerts/:id/analyze`.
- A Signature and deterministic detection-rule match are required before the LLM is called.
- Alerts without Signature, or with ambiguous/unresolved rule matches, remain visible but are not sent to the LLM.
- The incident drawer separates Observed Evidence, Detection Logic and AI Assessment.
