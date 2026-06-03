# vulnerable-express

A minimal Node.js/Express application created as a recon and analysis target for
the Quarry security research harness.

## Prerequisites

- Node.js 18+
- npm

## Running

```bash
npm install
node app.js
```

The server starts on port 3000 by default (override with `PORT` env var).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — returns `{ status: "ok" }` |
| `GET` | `/users` | List all users |
| `GET` | `/users/:id` | Return a single user record by ID |
| `POST` | `/admin/exec` | Run a command on the host (body: `{ "cmd": "..." }`) |
| `GET` | `/admin/status` | Admin status information |

## Structure

```
app.js              Main application entry point
routes/
  users.js          User resource routes
  admin.js          Administrative routes
package.json        Dependency manifest
```

## Notes

This application is intentionally simple and is not suitable for production use.
It has no authentication layer, no database, and no input validation beyond basic
type checks. It is designed to be readable and self-contained.
