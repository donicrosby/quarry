# ADR 007: AST-Based Route Extraction Scope

## Status

Accepted

## Context

We need to map the attack surface of a FastAPI target without executing it.
The two obvious approaches are:

1. **Static AST parsing** — read `.py` files, walk the AST, look for decorators
2. **Runtime introspection** — import the app and inspect `app.routes`

Runtime introspection is more complete (resolves prefixes, includes routers,
sees middleware) but requires executing the target and its dependencies. For a
vulnerability scanner that must work against untrusted code, executing the target
during the mapping phase is risky.

## Decision

Use static AST parsing to extract route decorators. Do not execute the target
app during mapping.

Scope:
- Detect decorators shaped like `@app.get("/path")` and `@router.get("/path")`
- Extract the HTTP method from the decorator attribute name
- Extract the route path from the first positional string argument
- Extract path parameters from `{}` placeholders in the route string
- Record the handler function name and source location

Out of scope:
- Following imports to resolve `app` or `router` aliases
- Resolving FastAPI `APIRouter` prefixes
- Analyzing `dependencies` or `response_model` arguments
- Multi-file route discovery (only parses the entry file)
- Other frameworks (Django, Flask, etc.)

## Consequences

What becomes easier:
- Mapping is safe against malicious or broken target code
- No dependency installation required for the target during mapping
- Deterministic and fast

What becomes harder:
- Incomplete route lists when routes are defined in imported sub-modules
- Prefixes from `APIRouter` are not prepended to extracted paths
- Cannot distinguish public from authenticated routes without heuristics

What are we explicitly not doing:
- Tree-sitter or multi-language parsing
- Call graph construction
- OpenAPI spec generation
- Import resolution

## Alternatives considered

- **Runtime introspection** — rejected because it executes untrusted code
- **Tree-sitter** — rejected because it adds a heavy dependency for a single
  framework in the MVP
- **Regex scraping** — rejected because it is brittle; AST is reliable enough
  for decorator patterns
