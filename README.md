# auditpulse-core

Lightweight static analysis security scanner for Soroban (Stellar) smart contracts written in Rust. Function structure (names, boundaries, source locations) is derived from Tree-sitter Rust parsing, so findings identify the enclosing function and, where the AST can verify it, the exact `fn`-keyword line and column; the checks themselves are conservative source-text heuristics.

## Checks

* **`missingRequireAuth`** (`AP-AUTH-001`): Flags authorization-sensitive operations (token transfers, balance updates, ledger writes) inside functions that omit `env.require_auth()`.
* **`unwrapUsage`** (`AP-ERROR-001`): Detects explicit `.unwrap()`, `.expect()`, or `panic!()` calls that cause runtime panics; encourages returning `Result<_, ContractError>`.
* **`missingExtendTtl`** (`AP-STORAGE-001`): Identifies persistent or temporary ledger storage access whose own tier is never extended via `.extend_ttl()`, preventing silent data expiry. Access is scoped by storage tier and, where the key is resolvable, by key — so bumping a `temporary` entry no longer hides an unbumped `persistent` one. Ledger access performed inside `macro_rules!` macros is detected too (see *Macro expansions* below).
* **`uncheckedArithmetic`** (`AP-ARITH-001`): Flags add/subtract/multiply/divide on amount-like values (amounts, balances, supplies, fees) with no checked math (`checked_add`, `saturating_sub`, bounds) that can overflow, underflow, or divide by zero.
* **`unvalidatedExternalCall`** (`AP-CALL-001`): Flags cross-contract/token operations (transfers, burns, mints, admin changes) with no `require_auth` and no evidence-backed validation: an explicitly checked id (`assert!`/`require!`/comparison) before the call suppresses the finding, an unchecked user-supplied `*_id` argument is reported (medium confidence — naming alone is not a boundary), and a storage-resolved id target is reported at low confidence.
* **`unprotectedUpgrade`** (`AP-UPG-001`): Flags upgrade/migration/admin-configuration functions (recognized by name) that contain no `require_auth` or admin check.
* **`debugStatements`** (`AP-DEBUG-001`): Flags debug/development-only macros (`log!`, `dbg!`, `println!`, `print!`, `eprint(ln)!`) left in production contract code.

### Severity and confidence

Severity expresses potential impact; confidence expresses how likely the
detected pattern is actually problematic. The two are independent:

| Rule | Severity | Confidence |
|------|----------|------------|
| `AP-AUTH-001` | critical | high |
| `AP-ERROR-001` | high | high |
| `AP-STORAGE-001` | high | medium |
| `AP-ARITH-001` | medium | medium |
| `AP-CALL-001` | high | low–medium (tiered by evidence) |
| `AP-UPG-001` | critical | medium |
| `AP-DEBUG-001` | low | high |

### Fixtures

`fixtures/` holds small Rust examples used by the regression suite
(`tests/fixtures.test.ts`):

```
fixtures/
  vulnerable/    # each file triggers at least one rule
  safe/          # each file must produce zero findings
  edge-cases/    # comments/strings, odd formatting, nested blocks, structural braces, coexisting findings
  workspaces/    # multi-module examples (per-file scanning semantics)
```

### Rust parsing (structural analysis)

AuditPulse parses each Rust file once with Tree-sitter (`tree-sitter-rust`) to
extract function declarations: name, `fn`-keyword line and column, body brace
position, and end line. Rules receive this AST-derived structure, so findings
stay exact even when comments or string literals contain braces, and columns
are reported only when the AST verified them — never invented. The parser is
isolated in `src/parser/rust.ts`: if the native module cannot load, or a file
has syntax errors that prevent reliable extraction, scanning falls back to the
original source-text extraction (line and function only) and continues without
losing findings. This is structural parsing only — AuditPulse does not perform
Rust type analysis, semantic analysis, or cross-file dataflow.

### Limitations

Function structure comes from Tree-sitter parsing (see above); the checks
remain conservative source-text heuristics over those function bodies. There
is **no** Rust semantic or type analysis, no compiler-equivalent analysis, and
never any cross-file dataflow. Known consequences:

* `AP-ARITH-001` evaluates arithmetic line-by-line; checked math in a helper
  called from another line is not connected, and complex expression chains may
  be missed. It prefers silence over noise.
* `AP-AUTH-001` is ordering-aware within a single function: a
  `require_auth` only gates sensitive operations that appear after it, so a
  check placed too late still produces a finding. It does not reason across
  functions — a `require_auth` inside a helper does not gate the caller and
  such a helper-based boundary is reported as unprotected.
* `AP-CALL-001` judges validation positionally within a single function:
  only evidence appearing before the sensitive call can gate it, and only
  explicit checks (`assert!`/`require!` or a comparison on the id) count as
  evidence. It does not verify what a check actually compares, cannot see
  helpers — a target resolved by `Self::token_id(&env)` is invisible — and
  `try_*` results, `.unwrap()`/`panic!`, or a bare rename are never treated
  as validation. This is structural AST reasoning, not semantic or
  interprocedural data flow.
* `AP-UPG-001` recognizes admin/upgrade functions by name, so unusual naming
  can evade it.
* `AP-STORAGE-001` attributes each ledger access to its storage tier and its
  key, and reports an access that no `extend_ttl` accounts for. Key comparison
  is source-text based: a key resolved through a helper (`Self::key(&env)`) or
  read back out of storage is not comparable, so it is treated as covered
  rather than guessed at. Macro invocation is followed one expansion level
  deep (see *Macro expansions*), and instance storage shares one TTL for the
  whole contract, so a single instance bump covers every instance access.
* Directory scans evaluate each Rust file independently; there is no
  cross-file dataflow analysis.

### Macro expansions

Soroban contracts routinely hide ledger access and TTL handling behind
`macro_rules!`. AuditPulse does not expand Rust macros — that needs a compiler
— but it does re-read one expansion level: every `macro_rules!` definition is
located, and each invocation has its metavariables substituted with the
arguments the call site passes. Detection is therefore attributed to the
**call site**, the line a developer can act on. When a body cannot be bound —
a repetition matcher (`$( ... ),*`), a body that invokes another macro, or a
metavariable with no matching argument — the invocation is left unreported
rather than guessed at.

```bash
node dist/index.js scan contracts/MacroVault.rs
```

## Installation

```bash
git clone https://github.com/Emmanuel-Ugochukwu1/auditpulse-core.git
cd auditpulse-core
npm install
npm run build

# Optional: put the `auditpulse` command on your PATH
npm link
```

## Quickstart

One copy-paste example, from install to report:

```bash
npm install && npm run build
node dist/index.js scan examples/vulnerable_vault.rs            # human report, exit 1
node dist/index.js scan examples/safe_vault.rs                  # no findings, exit 0
node dist/index.js scan examples --format json > report.json    # machine-readable
```

The `examples/` directory contains two small Soroban-style demo contracts:

| File | What it shows |
|------|---------------|
| `examples/vulnerable_vault.rs` | Deliberately vulnerable: trips most rules (missing auth, unchecked math, unvalidated external call, unprotected admin, panics, debug macros) |
| `examples/safe_vault.rs` | Clean reference: authorized, checked, TTL-extended — produces zero findings |

## CLI

The package ships a small dependency-free CLI:

```text
auditpulse scan <path>        Scan a Rust file or a directory tree
auditpulse report <path>      Scan and print the human-readable report
auditpulse sarif <path>       Scan and print SARIF 2.1.0 output
auditpulse init               Write a starter auditpulse.toml
auditpulse help               Show help
```

Options:

| Option | Meaning |
|--------|---------|
| `--format human\|json\|sarif` | Output format for `scan` (default: human) |
| `--min-severity <level>` | Drop findings below `low`/`medium`/`high`/`critical` |
| `--config <file>` | Explicit config file (default: nearest `auditpulse.toml`, else defaults) |

### Scanning

Give `scan` a single `.rs` file or a directory. Directories are walked
recursively for Rust files, skipping `node_modules`, `dist`, `target`, `.git`
and similar generated/unrelated directories, plus anything listed under
`exclude` in the configuration. Files are visited in deterministic (sorted)
order and each file is scanned independently; there is no cross-file
dataflow. Each file is parsed once and all rules share that structure.
Findings always identify their file and line; column and function details
appear only when the rule can compute them reliably (with the AST available,
function-anchored findings point at the `fn` keyword's line and column).

### JSON output

```bash
node dist/index.js scan contracts/SampleVault.rs --format json
```

```json
{
  "tool": { "name": "auditpulse", "version": "2.0.0" },
  "summary": {
    "filesScanned": 1,
    "findingCount": 3,
    "bySeverity": { "critical": 1, "high": 2 }
  },
  "findings": [
    {
      "ruleId": "AP-AUTH-001",
      "severity": "critical",
      "message": "Authorization-sensitive operations in function 'withdraw' ...",
      "location": {
        "file": "contracts/SampleVault.rs",
        "line": 23,
        "column": 11,
        "function": "withdraw"
      },
      "confidence": "high",
      "remediation": "Add env.require_auth(&account) ..."
    }
  ]
}
```

Optional fields (`confidence`, `remediation`, `column`, `function`) are
omitted when the rule does not provide them.

### SARIF output

```bash
node dist/index.js sarif contracts/SampleVault.rs > auditpulse.sarif
```

Emits SARIF 2.1.0 with the tool driver, rule metadata (ids, descriptions,
levels) and one result per finding with file URI and start line (plus start
column when the rule verified it), ready for
upload to GitHub Code Scanning.

## Configuration

An optional `auditpulse.toml` is discovered in the scan target's directory or
any parent, or can be given explicitly with `--config`:

```toml
disabled_rules = ["AP-DEBUG-001"]
min_severity = "low"          # low | medium | high | critical
exclude = ["vendor", "generated"]
```

Without a config file, defaults apply: all rules enabled, `min_severity =
"low"`, no extra exclusions. Invalid values are rejected with exit code 2.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above the configured threshold |
| `1` | Findings at or above the threshold |
| `2` | Usage, configuration, or input error |

The same semantics apply in `--format json` and `sarif` modes, so CI pipelines
can rely on the exit code regardless of the chosen output format.

## Web Demo

A minimal local web demo puts a dashboard on top of the same scanner the CLI uses — no new dependencies, just Node's built-in `http` module.

```bash
npm install && npm run build
npm run dev:web          # serves the API + dashboard on http://127.0.0.1:4646
```

Then open **http://127.0.0.1:4646** and:

1. Click **Load safe example** → **Run scan** → "No findings" (clean result state).
2. Click **Load vulnerable example** → **Run scan** → multiple findings, each with rule ID, severity, confidence, message, location and remediation guidance.

The **Run scan** button `POST`s the editor contents to the API and renders the JSON report. You can also paste any Rust source directly into the editor.

### API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Liveness probe: `{"status":"ok"}` |
| `POST /api/scan` | Scan in-memory source: `{"source": "<rust source>"}` → full JSON report (same model as `scan --format json`) |
| `GET /api/examples/safe` | Load `examples/safe_vault.rs` |
| `GET /api/examples/vulnerable` | Load `examples/vulnerable_vault.rs` |

```bash
# Scan a contract through the API
curl -s -X POST http://127.0.0.1:4646/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"source\": \"pub fn f(env: Env) { let x = a + b; }\"}"
```

Notes:

* Submitted source is analyzed **in memory** by the same rules the CLI uses (Tree-sitter function structure plus source-text heuristics) and is never executed or written to disk.
* Request bodies are capped (256 KB) and invalid input returns a JSON error with a 4xx status.
* Function structure comes from Tree-sitter Rust parsing; the checks are source-text heuristics, not semantic analysis, and there is no cross-file dataflow. See [Limitations](#limitations).

## CI / GitHub Actions

The repository ships a minimal workflow at
`.github/workflows/auditpulse.yml`. It installs dependencies, builds the CLI,
scans the configured target, uploads SARIF to GitHub Code Scanning, and fails
the job when findings exist at or above the configured threshold.

To use it in your own repository, copy the workflow and point its target at
your contract sources:

```yaml
env:
  SCAN_TARGET: path/to/contracts   # scanned and uploaded as SARIF
  GATE_TARGET: path/to/contracts   # exit code gates the job (usually the same path)
```

The job needs `security-events: write` permission for the SARIF upload;
results then appear under the repository's **Code scanning** tab.

A minimal non-GitHub CI invocation relies on exit codes alone:

```bash
node dist/index.js scan contracts/ || echo "findings above threshold"
```

## Example Output

```text
============================================================
AuditPulse Security Scanner Report
Target: contracts/SampleVault.rs
Files scanned: 1
============================================================

contracts/SampleVault.rs
  Line 23:11: [AP-AUTH-001] [CRITICAL] [confidence: HIGH]
    Authorization-sensitive operations in function 'withdraw' are not gated by require_auth. ...
    Function: withdraw
    Remediation: Add env.require_auth(&account) for the account authorized to perform the sensitive operation.
  Line 33: [AP-ERROR-001] [HIGH] [confidence: HIGH]
    Direct use of .unwrap() will panic and abort the contract invocation. ...
    Remediation: Replace the panicking call with error propagation, ...

============================================================
Total findings: 3 (1 critical, 2 high)
============================================================

```

## Contributing and roadmap

Planned improvements are tracked as open technical issues, each with a
description of what exists, what is missing, a proposed scope, and concrete
acceptance criteria. These are maintainer-planned items derived from the
codebase itself — new rule candidates, fixture coverage, configuration, and
reporting enhancements.

* Issue tracker: <https://github.com/Emmanuel-Ugochukwu1/auditpulse-core/issues>
* Roadmap overview: `docs/ROADMAP_ISSUES.md`
* Issues labeled `good first issue` are scoped for a first contribution

The issue drafts live in `scripts/issues/` with `scripts/publish-issues.mjs`
to re-check or publish them (`node scripts/publish-issues.mjs` for a dry
run; it skips titles that already exist, so it never creates duplicates).

## Development

Built with TypeScript: Tree-sitter provides function structure, source-text pattern rules perform the checks, and Vitest tests it all.

```bash
# Type check
npx tsc --noEmit

# Run unit tests
npm test

```