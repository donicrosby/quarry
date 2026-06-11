# vulnerable-go

A minimal Go HTTP service created as a recon and analysis target for
the Quarry security research harness.

## Prerequisites

- Go 1.22+

## Running

```bash
go run .
```

The server starts on port 8080 by default (override with `PORT` env var).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check — returns `{"status":"ok"}` |
| `GET` | `/users` | List all user records |
| `GET` | `/users/{id}` | Return a single user record by ID |
| `POST` | `/admin/exec` | Execute a host command (body: `{"cmd":"..."}`) |

## Structure

```
main.go             Application entry point and route registration
handlers/
  users.go          User resource handlers
  admin.go          Administrative handlers
go.mod              Module manifest
```

## Notes

This application is intentionally simple and self-contained, designed to be
readable for use as a static analysis target.
