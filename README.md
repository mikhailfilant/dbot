# Railway-ready Discord bot + key server

## Deploy
1. Push this folder to GitHub.
2. Create a Railway project from the repo.
3. Add all variables from `.env.example` in Railway Variables.
4. Add a Railway Volume and mount it to `/app/data`.
5. Deploy.

## Notes
- Do not commit `.env`, `keys.json`, or `data/`.
- The app listens on `process.env.PORT`.
- Health check endpoints: `/` `/ping` `/healthz`.
- Persistent keys should live on the mounted volume at `/app/data/keys.json`.
