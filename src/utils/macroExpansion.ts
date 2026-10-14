/**
 * Macro-aware source helpers.
 *
 * AuditPulse does not expand Rust macros — that needs a compiler, and the
 * project deliberately stays a source-text analyzer (see the README
 * "Limitations" section). What these helpers add is a *macro-aware view* of
 * one file, so rules stop being blind to code that only exists inside a
 * `macro_rules!` definition:
 *
 *  - `stripMacroBodies` blanks the body of every `macro_rules!` definition
 *    (same length, newlines kept) and returns the definitions, so a rule can
 *    scan executable text and macro bodies separately while still reporting
 *    positions from the original file.
 *  - A macro invocation is re-read positionally: each metavariable used in a
 *    macro body is bound to the argument the call site passes, which is the
 *    substitution the compiler performs, one expansion level deep. Detection
 *    is therefore attributed to the *call site*, which is the line a human can
 *    act on, not to the macro definition.
 *
 * Everything here is conservative: an invocation that cannot be bound
 * (repetition pattern, nested macro call, metavariable this module cannot
 * resolve) is reported as unresolved instead of guessed at, and callers treat
 * unresolved evidence as "assume the developer handled it".
 *
 * All helpers expect *sanitized* source: comments and string/char literal
 * contents already blanked by `sanitizeKeepLines`. Braces and parentheses are
 * then trustworthy for delimiter matching.
 */

const CLOSERS: Record<string, string> = { "{": "}", "(": ")", "[": "]" };

/** Index of the delimiter matching the one at `openIdx`, or -1. */
export function matchingDelimiter(code: string, openIdx: number): number {
  const stack: string[] = [];
  for (let i = openIdx; i < code.length; i++) {
    const c = code[i]!;
    const closer = CLOSERS[c];
    if (closer !== undefined) {
      stack.push(closer);
    } else if (c === "}" || c === ")" || c === "]") {
      if (stack.length === 0 || stack[stack.length - 1] !== c) {
        return -1;
      }
      stack.pop();
      if (stack.length === 0) {
        return i;
      }
    }
  }
  return -1;
}

/** One `matcher => body` rule of a `macro_rules!` definition. */
export interface MacroArm {
  /** Metavariable names from the matcher, in declaration order. */
  params: string[];
  /** Raw body text between the body delimiters; keeps its own braces. */
  body: string;
  /** True when the matcher uses a repetition (`$( ... ),*`), which is not bound. */
  repetitive: boolean;
}

/** A `macro_rules!` definition found in a file. */
export interface MacroDefinition {
  name: string;
  arms: MacroArm[];
}

/**
 * Blanks the body of every `macro_rules!` definition, keeping the source
 * length and every newline so 1-based line numbers stay valid.
 *
 * The `macro_rules! name` token survives (only the delimited body is
 * blanked), which is enough to recognize definitions and never enough to
 * confuse them with invocations.
 */
export function stripMacroBodies(code: string): {
  blind: string;
  macros: MacroDefinition[];
} {
  const chars = code.split("");
  const macros: MacroDefinition[] = [];
  const header = /macro_rules\s*!\s*([A-Za-z_]\w*)/g;

  let match: RegExpExecArray | null;
  while ((match = header.exec(code)) !== null) {
    let i = match.index + match[0].length;
    while (i < code.length && /\s/.test(code[i]!)) i++;
    const open = code[i];
    if (open !== "{" && open !== "(" && open !== "[") continue;

    const close = matchingDelimiter(code, i);
    if (close < 0) continue;

    const arms = parseArms(code.slice(i + 1, close));
    macros.push({ name: match[1]!, arms });

    for (let j = i; j <= close; j++) {
      if (chars[j] !== "\n") chars[j] = " ";
    }
    header.lastIndex = close + 1;
  }

  return { blind: chars.join(""), macros };
}

/** Splits a `macro_rules!` body into `matcher => body` arms. */
function parseArms(section: string): MacroArm[] {
  const arms: MacroArm[] = [];
  let cursor = 0;

  while (cursor < section.length) {
    const arrow = findTopLevelArrow(section, cursor);
    if (arrow < 0) break;

    const matcher = section.slice(cursor, arrow);
    let bodyStart = arrow + 2;
    while (bodyStart < section.length && /\s/.test(section[bodyStart]!)) bodyStart++;

    const open = section[bodyStart];
    let close = -1;
    let body = "";
    if (open === "{" || open === "(" || open === "[") {
      close = matchingDelimiter(section, bodyStart);
      body = close < 0 ? section.slice(bodyStart + 1) : section.slice(bodyStart + 1, close);
    } else {
      // No delimiters: take the rest of this arm.
      body = section.slice(bodyStart);
    }

    const params: string[] = [];
    const paramRe = /\$([A-Za-z_]\w*)\s*:/g;
    let p: RegExpExecArray | null;
    while ((p = paramRe.exec(matcher)) !== null) params.push(p[1]!);

    arms.push({
      params,
      body,
      repetitive: /\$\(/.test(matcher),
    });

    cursor = close < 0 ? section.length : close + 1;
  }

  return arms;
}

/** Index of the first `=>` outside any delimiter, or -1. */
function findTopLevelArrow(text: string, from: number): number {
  const stack: string[] = [];
  for (let i = from; i < text.length; i++) {
    const c = text[i]!;
    const closer = CLOSERS[c];
    if (closer !== undefined) {
      stack.push(closer);
    } else if (c === "}" || c === ")" || c === "]") {
      stack.pop();
    } else if (c === "=" && stack.length === 0 && text[i + 1] === ">") {
      return i;
    }
  }
  return -1;
}

/** A macro invocation site: where it is and which arguments it passes. */
export interface MacroInvocation {
  /** 1-based line of the invocation. */
  line: number;
  /** 0-based offset of the invocation's name. */
  offset: number;
  args: string[];
}

/**
 * Finds every invocation of `name` (as `name!(...)`, `name![...]` or
 * `name!{...}`). Macro *definitions* are not invocations: in
 * `macro_rules! name { ... }` the `!` sits before the name, so the
 * `name`-then-`!` shape below cannot match them.
 */
export function findMacroInvocations(code: string, name: string): MacroInvocation[] {
  const out: MacroInvocation[] = [];
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(^|[^A-Za-z0-9_])${escaped}\\s*!`, "g");

  const lineStarts = lineStartOffsets(code);
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    let i = m.index + m[0].length;
    while (i < code.length && /\s/.test(code[i]!)) i++;
    const open = code[i];
    if (open !== "(" && open !== "[" && open !== "{") continue;
    const close = matchingDelimiter(code, i);
    if (close < 0) continue;

    out.push({
      line: lineAt(lineStarts, m.index),
      offset: m.index + m[1]!.length,
      args: splitTopLevel(code.slice(i + 1, close)),
    });
    re.lastIndex = close + 1;
  }

  return out;
}

/**
 * Binds the metavariables used in a macro body to the arguments of one
 * invocation: `$name` and `${name}` are replaced by the argument passed for
 * that parameter, exactly as one expansion step would.
 *
 * Returns null when any metavariable cannot be bound (name not declared in
 * the matcher, or fewer arguments than parameters), so callers can stay
 * conservative instead of inventing a binding.
 */
export function bindMacroBody(
  text: string,
  params: readonly string[],
  args: readonly string[],
): string | null {
  let unresolved = false;
  const bound = text.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (whole: string, name: string) => {
    const index = params.indexOf(name);
    if (index < 0 || index >= args.length) {
      unresolved = true;
      return whole;
    }
    return args[index]!.trim();
  });
  return unresolved ? null : bound;
}

/** A method call site found in source text. */
export interface MethodCall {
  op: string;
  dot: number;
  open: number;
  close: number;
  /** Raw text of the receiver expression before the method name. */
  receiver: string;
  receiverStart: number;
}

/** Finds `.op(` calls for the given operations. */
export function methodCalls(code: string, ops: readonly string[]): MethodCall[] {
  const ordered = [...ops].sort((a, b) => b.length - a.length);
  const re = new RegExp(`\\.\\s*(${ordered.join("|")})\\s*\\(`, "g");
  const out: MethodCall[] = [];

  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchingDelimiter(code, open);
    const receiver = receiverBefore(code, m.index);
    if (close < 0 || receiver === null) continue;
    out.push({
      op: m[1]!,
      dot: m.index,
      open,
      close,
      receiver: receiver.text,
      receiverStart: receiver.start,
    });
  }

  return out;
}

/**
 * Walks left from a `.` and returns the whole receiver expression:
 * `env.storage().persistent()` for `env.storage().persistent().set(...)`,
 * `tier` for `tier.extend_ttl(...)`. Metavariables (`$env`) are kept intact.
 */
function receiverBefore(code: string, dotIdx: number): { text: string; start: number } | null {
  let i = dotIdx;
  let start = -1;

  for (;;) {
    const p = skipWsBack(code, i);
    if (p === 0) break;

    const prev = code[p - 1]!;
    if (prev === ")") {
      const open = openParenFor(code, p - 1);
      if (open < 0) break;
      // The call's callee name sits immediately before the '('.
      const nameEnd = skipWsBack(code, open);
      const name = /(?:[A-Za-z_]\w*|\$\{?[A-Za-z_]\w*\}?)$/.exec(code.slice(0, nameEnd));
      if (name === null) break;
      start = nameEnd - name[0].length;
      const q = skipWsBack(code, start);
      if (q > 0 && code[q - 1] === ".") {
        i = q - 1;
        continue;
      }
      break;
    }

    const atom = /(?:\$\{?[A-Za-z_]\w*\}?|[A-Za-z_]\w*)$/.exec(code.slice(0, p));
    if (atom === null) break;
    start = p - atom[0].length;
    const q = skipWsBack(code, start);
    if (q > 0 && code[q - 1] === ".") {
      i = q - 1;
      continue;
    }
    break;
  }

  return start < 0 ? null : { text: code.slice(start, dotIdx), start };
}

function openParenFor(code: string, closeIdx: number): number {
  let depth = 0;
  for (let i = closeIdx; i >= 0; i--) {
    const c = code[i]!;
    if (c === ")") depth++;
    else if (c === "(") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function skipWsBack(code: string, i: number): number {
  let j = i;
  while (j > 0 && /\s/.test(code[j - 1]!)) j--;
  return j;
}

/** Splits `inner` at top-level commas, ignoring commas inside delimiters. */
export function splitTopLevel(inner: string): string[] {
  const parts: string[] = [];
  const stack: string[] = [];
  let current = "";

  for (const c of inner) {
    if (c === "{" || c === "(" || c === "[") stack.push(c);
    else if (c === "}" || c === ")" || c === "]") stack.pop();

    if (c === "," && stack.length === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += c;
  }
  if (current.trim().length > 0 || parts.length > 0) parts.push(current);

  return parts.map((p) => p.trim()).filter((p) => p.length > 0);
}

/** Offsets of every line start, for 1-based line lookups. */
export function lineStartOffsets(code: string): number[] {
  const starts = [0];
  for (let i = 0; i < code.length; i++) {
    if (code[i] === "\n") starts.push(i + 1);
  }
  return starts;
}

/** 1-based line containing the 0-based offset `offset`. */
export function lineAt(lineStarts: readonly number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if (lineStarts[mid]! <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

/** The storage tier a receiver expression resolves to, or null if not storage. */
export function storageTier(
  text: string,
): "persistent" | "temporary" | "instance" | "unknown" | null {
  if (!/\bstorage\s*\(\s*\)/.test(text)) return null;
  const tiers = text.match(/\.\s*(persistent|temporary|instance)\s*\(\s*\)/g) ?? [];
  if (tiers.length === 0) return "unknown";
  const last = tiers[tiers.length - 1]!;
  const named = /(persistent|temporary|instance)/.exec(last);
  return (named?.[1] as "persistent" | "temporary" | "instance") ?? "unknown";
}

/** Key identity: whitespace- and reference-insensitive. */
export function normalizeKey(text: string): string {
  return text.replace(/\s+/g, "").replace(/^&+/, "");
}

/** `let` bindings in a text: name -> the expression text right of `=`. */
export function parseLetBindings(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /\blet\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=;{}]*?)?\s*=\s*([^;{]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.set(m[1]!, m[2]!);
  return out;
}
