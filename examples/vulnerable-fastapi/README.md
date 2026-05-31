# Vulnerable FastAPI Target

Local-only seeded target for Quarry development.

Intentional vulnerabilities:

- hardcoded secret exposed in source and response data
- direct object access without authorization checks
- shell command construction from request input
- local-only URL fetch shape for SSRF testing

Run it locally with:

```bash
uv run quarry target start examples/vulnerable-fastapi
```
