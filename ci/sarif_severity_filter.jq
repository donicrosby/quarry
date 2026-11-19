# Quarry severity-threshold filter (SARIF 2.1.0).
#
# Keeps only the results whose Quarry severity ranks at or above the requested
# threshold, judged on the *pre-mapping* severity carried in
# `result.properties.quarry.severity` — the severity->level mapping collapses
# `low` and `info` onto `note`, so filtering on `result.level` would be lossy.
#
# Usage: jq --arg threshold "$SEVERITY_THRESHOLD" -f ci/sarif_severity_filter.jq <log>
#
# A result with no (or an unknown) quarry severity ranks below every threshold
# and is dropped, so a malformed log can never smuggle a finding past the gate.

def quarry_rank:
  if type == "string"
  then ({info: 0, low: 1, medium: 2, high: 3, critical: 4}[.] // -1)
  else -1
  end;

.runs[0].results |= map(
  select((.properties.quarry.severity | quarry_rank) >= ($threshold | quarry_rank))
)
