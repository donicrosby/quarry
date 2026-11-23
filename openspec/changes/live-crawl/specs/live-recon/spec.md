## ADDED Requirements

### Requirement: Live attack-map entries carry their source

Every `LiveAttackMapEntry` SHALL carry a `source` field distinguishing entries
derived from code analysis (`code_analysis`) from entries discovered by a live
crawler (`crawl`). Code-analysis entries SHALL default to `code_analysis` so
existing producers are unchanged, and merging crawl entries SHALL NOT discard
the code correlation (`code_file` / `code_function`) of a code-analysis entry.

#### Scenario: crawl-derived entries are attributed

- **WHEN** a crawler produces attack-map entries and they are merged with
  code-analysis entries
- **THEN** each entry reports whether it came from `crawl` or `code_analysis`

#### Scenario: merge preserves code correlation

- **WHEN** a crawl entry and a code-analysis entry share a method and path
- **THEN** the merged entry keeps the code-analysis entry's `code_file` and
  `code_function` while recording that a crawl also reached it
