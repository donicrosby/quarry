# budget-enforcement Specification

## Purpose

A scan must not spend without bound. Cost and token budgets are checked at activity
boundaries, and when a budget is reached the scan halts gracefully at the next boundary
and still produces a partial report rather than aborting. An unset budget means uncapped;
benchmark runs always set one.

## Requirements

### Requirement: Cost and token budgets are enforced at boundaries

The scan SHALL check cumulative estimated cost and token usage against the configured
budget at activity boundaries. An unset budget SHALL mean uncapped.

#### Scenario: Budget is checked at each boundary

- **WHEN** an activity boundary is reached during a budgeted scan
- **THEN** cumulative cost is compared against the budget before continuing

#### Scenario: Unset budget is uncapped

- **WHEN** no budget is configured
- **THEN** the scan is not cost-limited

### Requirement: Graceful halt with a partial report

When the budget is reached the scan SHALL halt at the next boundary, record a
budget-exceeded reason, proceed to the terminal coverage and report stages, and emit a
partial report rather than failing.

#### Scenario: Reaching the budget produces a partial report

- **WHEN** cumulative cost reaches the budget mid-scan
- **THEN** the scan stops advancing new work and still renders a report of what it found
