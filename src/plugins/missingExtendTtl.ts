import type { Rule, ScannedFunction, Vulnerability } from "../types";
import type { AstAwareRule } from "../engine.js";
import { locateLine, sanitizeKeepLines } from "../utils/rust.js";
import {
  bindMacroBody,
  findMacroInvocations,
  lineStartOffsets,
  methodCalls,
  normalizeKey,
  parseLetBindings,
  storageTier,
  stripMacroBodies,
} from "../utils/macroExpansion.js";

/** The ledger storage tiers Soroban exposes through `env.storage()`. */
type Tier = "persistent" | "temporary" | "instance" | "unknown";

/** Storage operations that touch a ledger entry and are subject to TTL expiry. */
const ACCESS_OPS = ["get", "set", "remove"] as const;
/** Operations that read or extend an entry's time to live. */
const TTL_OPS = ["extend_ttl_to_threshold", "extend_ttl", "get_extended"] as const;

/** A ledger entry access that must be kept alive. */
interface StorageAccess {
  /** 1-based line to report if this access ends up uncovered. */
  line: number;
  tier: Tier;
  /** Resolved key identity, or null when it cannot be compared safely. */
  keyIdentity: string | null;
}

/** A TTL extension found in the file. */
interface TtlBump {
  tier: Tier;
  keyIdentity: string | null;
}

/** Where a piece of analyzed text came from, for line attribution. */
type Origin =
  | { kind: "file"; lineStarts: number[] }
  | { kind: "invocation"; line: number };

/**
 * AP-STORAGE-001, macro-aware.
 *
 * The rule attributes every ledger access to the storage **tier** it uses
 * (`persistent`, `temporary`, `instance`) and every TTL extension to the tier
 * it extends, then reports an access nothing accounts for. This replaces the
 * previous file-level "any `extend_ttl` anywhere silences the whole file"
 * test, which silently passed:
 *
 *  - a `persistent` write that was never bumped because an unrelated
 *    `temporary`/`instance` entry was extended instead;
 *  - an `extend_ttl` aimed at a *different* key than the entry being written;
 *  - a ledger write performed by a macro (e.g. `put!(env, k, v)`), invisible
 *    in the expanded source but visible in the macro definition.
 *
 * Macro handling is deliberately one expansion level deep and
 * call-site-attributed: Rust macros cannot be expanded without a compiler, so
 * the rule re-reads a `macro_rules!` definition positionally — each
 * metavariable bound to the argument its call site passes — and anchors the
 * finding at the invocation, the line a developer can act on. A macro whose
 * body invokes another macro, or whose matcher uses a repetition, is left
 * unreported rather than guessed at.
 */
export class MissingExtendTtlPlugin implements Rule, AstAwareRule {
  id = "AP-STORAGE-001";
  name = "Missing Extend TTL";
  description =
    "Detects persistent/temporary ledger storage access whose own tier is never extended via extend_ttl, including ledger access performed inside macro_rules! macros";

  scan(code: string): Vulnerability[] {
    return this.scanCode(code, null);
  }

  /**
   * Whole-file scan with the shared AST extraction: the finding keeps the
   * offending access line and picks up the enclosing function and fn-keyword
   * column when the extraction is available.
   */
  scanCode(code: string, functions: ScannedFunction[] | null): Vulnerability[] {
    const clean = sanitizeKeepLines(code);
    const { accesses, bumps } = collectStorageEvidence(clean);

    const uncovered = accesses.filter((access) => !isCovered(access, bumps));
    if (uncovered.length === 0) {
      return [];
    }

    // One finding per file, anchored at the first entry left unaccounted for.
    const first = uncovered.reduce((a, b) => (a.line <= b.line ? a : b));
    const tiers = [...new Set(uncovered.map((a) => a.tier))]
      .map((tier) => `\`${tier}\``)
      .join(" and ");

    return [
      {
        id: "AP-STORAGE-001",
        message: `Ledger entries accessed here (${tiers} storage) are never bumped via extend_ttl on their own tier; expired entries read back as None. Add env.storage().${tierCall(first.tier)}.extend_ttl(...) for the keys this code writes.`,
        severity: "high",
        confidence: "medium",
        location: locateLine(functions, first.line),
        remediation:
          "After reading or writing persistent/temporary storage, call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or extend_ttl_to_threshold on the same tier — and for the same key — to keep the entry alive. Instance storage shares one TTL for the whole contract, so a single env.storage().instance().extend_ttl(...) is enough for it.",
      },
    ];
  }
}

function tierCall(tier: Tier): string {
  return tier === "unknown" ? "persistent()" : `${tier}()`;
}

/**
 * Collects every ledger access and TTL extension in the file, both from the
 * executable text and from one level of `macro_rules!` expansion.
 */
function collectStorageEvidence(clean: string): {
  accesses: StorageAccess[];
  bumps: TtlBump[];
} {
  const { blind, macros } = stripMacroBodies(clean);
  const accesses: StorageAccess[] = [];
  const bumps: TtlBump[] = [];

  collectFromText(
    blind,
    { kind: "file", lineStarts: lineStartOffsets(clean) },
    parseLetBindings(blind),
    accesses,
    bumps,
  );

  // A macro definition is invisible to the rules in its original form, so
  // each invocation is bound to the definition's body and analyzed at the
  // invocation site. Nested invocations inside a body are left alone: the
  // outer expansion is dropped rather than reported twice.
  for (const macro of macros) {
    for (const invocation of findMacroInvocations(blind, macro.name)) {
      for (const arm of macro.arms) {
        if (arm.repetitive) continue;
        const expanded = bindMacroBody(arm.body, arm.params, invocation.args);
        if (expanded === null) continue;
        if (findMacroInvocations(expanded, macro.name).length > 0) continue;

        collectFromText(
          expanded,
          { kind: "invocation", line: invocation.line },
          parseLetBindings(expanded),
          accesses,
          bumps,
        );
      }
    }
  }

  return { accesses, bumps };
}

/** Reads ledger evidence out of one text, attributing lines to its origin. */
function collectFromText(
  text: string,
  origin: Origin,
  bindings: Map<string, string>,
  accesses: StorageAccess[],
  bumps: TtlBump[],
): void {
  const lineOf = (offset: number): number =>
    origin.kind === "file" ? lineNumberAt(origin.lineStarts, offset) : origin.line;

  for (const call of methodCalls(text, [...TTL_OPS, ...ACCESS_OPS])) {
    const tier = resolveReceiverTier(call.receiver, bindings);
    const keyText = firstArgumentText(text, call.open);
    const keyIdentity =
      keyText === null ? null : resolveKeyIdentity(keyText, bindings);

    if ((TTL_OPS as readonly string[]).includes(call.op)) {
      bumps.push({ tier, keyIdentity });
      continue;
    }

    accesses.push({ line: lineOf(call.dot), tier, keyIdentity });
  }
}

/**
 * Tier of a call receiver: `env.storage().persistent()` resolves directly, and
 * a receiver that is a plain local (`let tier = env.storage().temporary();`)
 * resolves through the binding it was assigned. Anything else — a helper
 * returning a tier — stays "unknown", which callers treat conservatively.
 */
function resolveReceiverTier(
  receiver: string,
  bindings: Map<string, string>,
): Tier {
  const direct = storageTier(receiver);
  if (direct !== null) return direct;

  const name = /^[A-Za-z_]\w*$/.exec(receiver.trim())?.[0];
  if (name !== undefined) {
    const bound = bindings.get(name);
    if (bound !== undefined) {
      const viaAlias = storageTier(bound);
      if (viaAlias !== null) return viaAlias;
    }
  }

  return "unknown";
}

/** Raw text of the first argument of the call whose `(` is at `openIdx`. */
function firstArgumentText(code: string, openIdx: number): string | null {
  let depth = 0;
  let current = "";
  for (let i = openIdx; i < code.length; i++) {
    const c = code[i]!;
    if (c === "(" || c === "{" || c === "[") {
      depth++;
      if (depth === 1) continue;
    } else if (c === ")" || c === "}" || c === "]") {
      depth--;
      if (depth === 0) return current.trim().length > 0 ? current.trim() : null;
    } else if (c === "," && depth === 1) {
      return current.trim().length > 0 ? current.trim() : null;
    }
    if (depth >= 1) current += c;
  }
  return null;
}

/**
 * Identity of a ledger key as the source text expresses it. Two keys are the
 * same entry only when they resolve to the same text; anything the analyzer
 * cannot follow — a helper call (`Self::key(&env)`), a value read out of
 * storage, an unresolved metavariable — returns null.
 */
function resolveKeyIdentity(
  text: string,
  bindings: Map<string, string>,
): string | null {
  const trimmed = text.trim().replace(/\s+/g, " ");
  if (trimmed.length === 0) return null;
  if (/\bSelf\s*::/.test(trimmed)) return null;
  if (/\$\{?[A-Za-z_]/.test(trimmed)) return null;

  const simple = /^&\s*([A-Za-z_]\w*)\s*$/.exec(trimmed);
  if (simple !== null) {
    const bound = bindings.get(simple[1]!);
    if (bound === undefined) {
      // A parameter or local the file never assigns: its own name is its
      // identity, so `&key` and `&key` match while `&key` and `&other` do not.
      return normalizeKey(trimmed);
    }
    const rhs = bound.trim();
    if (/storage\s*\(/.test(rhs) || /!/.test(rhs) || /\bSelf\s*::/.test(rhs)) {
      return null;
    }
    return normalizeKey(rhs);
  }

  return normalizeKey(trimmed);
}

/**
 * Whether some TTL extension accounts for this access.
 *
 * `persistent` and `temporary` entries each carry their own time to live and
 * expire independently, so a bump only covers an access on the same tier — and,
 * where both keys are resolvable, the same key. Instance storage shares a
 * single TTL for the whole contract instance, so one instance bump covers every
 * instance access in the file.
 *
 * An access is reported unless a bump can positively account for it: a bump on
 * the same tier (or one whose tier could not be resolved) that either targets
 * the same key or carries a key this analyzer cannot resolve. A bump whose own
 * key is unresolvable (`Self::key(&env)`) therefore covers an access instead of
 * being guessed at, while a bump aimed at a clearly different key does not.
 */
function isCovered(access: StorageAccess, bumps: TtlBump[]): boolean {
  // A bump whose receiver this analyzer could not resolve to a tier might be
  // aimed at anything; treat it as covering so the rule stays conservative.
  const coversUnknown = bumps.some((bump) => bump.tier === "unknown");

  if (access.tier === "instance") {
    return coversUnknown || bumps.some((bump) => bump.tier === "instance");
  }

  for (const bump of bumps) {
    if (bump.tier !== access.tier && bump.tier !== "unknown") continue;
    if (bump.keyIdentity === null || access.keyIdentity === null) return true;
    if (bump.keyIdentity === access.keyIdentity) return true;
  }
  return coversUnknown;
}

/** 1-based line containing a 0-based offset in the given text. */
function lineNumberAt(lineStarts: readonly number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (lineStarts[mid]! <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

export default new MissingExtendTtlPlugin();
