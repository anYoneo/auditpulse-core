import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import MissingExtendTtlPlugin from "../src/plugins/missingExtendTtl";
import { AuditEngine } from "../src/engine";
import { createDefaultRegistry } from "../src/registry";
import { sanitizeKeepLines } from "../src/utils/rust";
import {
  bindMacroBody,
  findMacroInvocations,
  matchingDelimiter,
  methodCalls,
  normalizeKey,
  storageTier,
  stripMacroBodies,
} from "../src/utils/macroExpansion";
import type { Vulnerability } from "../src/types";

/**
 * AP-STORAGE-001 across complex Soroban macro expansions.
 *
 * The rule cannot expand Rust macros (that needs a compiler), so it re-reads
 * one level of `macro_rules!` — binding each metavariable to the argument its
 * call site passes — and attributes findings to the call site. These tests
 * pin that behaviour, the tier/key scoping it enables, and the categories it
 * deliberately stays silent about.
 */

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function scan(code: string): Vulnerability[] {
  return MissingExtendTtlPlugin.scan(code);
}

function engineFindings(code: string, id = "AP-STORAGE-001"): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry())
    .run(code)
    .filter((finding) => finding.id === id);
}

function scanFile(relPath: string): Vulnerability[] {
  return new AuditEngine(createDefaultRegistry()).run(
    fs.readFileSync(path.join(ROOT, relPath), "utf-8"),
  );
}

describe("macroExpansion helpers", () => {
  it("blanks macro bodies while keeping line count and offsets", () => {
    const code = [
      "macro_rules! put {",
      "  ($e:expr, $k:expr, $v:expr) => {",
      "    $e.storage().persistent().set(&$k, &$v);",
      "  };",
      "}",
      "fn real() { }",
    ].join("\n");
    const { blind, macros } = stripMacroBodies(code);

    expect(blind.split("\n")).toHaveLength(code.split("\n").length);
    expect(blind.length).toBe(code.length);
    expect(macros.map((m) => m.name)).toEqual(["put"]);
    // The definition token survives (so definitions are recognizable) but the
    // body is gone: the rule must not read storage out of the definition.
    expect(blind).toContain("macro_rules! put");
    expect(blind).not.toContain("persistent()");
    expect(blind).toContain("fn real() { }");
  });

  it("parses matcher parameters and the body of every arm", () => {
    const { macros } = stripMacroBodies(
      [
        "macro_rules! m {",
        "  ($a:expr, $b:ident) => { f($a, $b) };",
        "  () => { g() };",
        "}",
      ].join("\n"),
    );

    expect(macros[0]?.arms).toHaveLength(2);
    expect(macros[0]?.arms[0]?.params).toEqual(["a", "b"]);
    expect(macros[0]?.arms[0]?.body).toContain("f($a, $b)");
    expect(macros[0]?.arms[1]?.params).toEqual([]);
  });

  it("treats a repetition matcher as unbindable", () => {
    const { macros } = stripMacroBodies(
      "macro_rules! m { ($e:expr, [ $($k:expr),* ]) => { $( put(&$k) )* }; }",
    );

    expect(macros[0]?.arms[0]?.repetitive).toBe(true);
  });

  it("bounds delimiters and ignores braces hidden in strings and comments", () => {
    const code = sanitizeKeepLines('let s = "} {"; // }\nif x { y() }');
    const open = code.indexOf("{");

    expect(matchingDelimiter(code, open)).toBe(code.lastIndexOf("}"));
  });

  it("binds metavariables to the call-site arguments, one expansion deep", () => {
    expect(
      bindMacroBody(
        "$e.storage().persistent().set(&$k, &$v);",
        ["e", "k", "v"],
        ["env", "token_key", "amount"],
      ),
    ).toBe("env.storage().persistent().set(&token_key, &amount);");
  });

  it("supports the ${name} metavariable form", () => {
    expect(bindMacroBody("set(&${k})", ["k"], ["user"])).toBe("set(&user)");
  });

  it("refuses to bind a metavariable with no argument", () => {
    expect(bindMacroBody("set(&$missing);", ["k"], ["user"])).toBeNull();
    expect(bindMacroBody("set(&$k);", ["k"], [])).toBeNull();
  });

  it("finds invocations but not the definition itself", () => {
    const code = [
      "macro_rules! put { ($e:expr, $k:expr) => { $e.set(&$k); }; }",
      "fn f(env: Env) {",
      "  put!(env, key);",
      "}",
    ].join("\n");
    const invocations = findMacroInvocations(code, "put");

    expect(invocations).toHaveLength(1);
    expect(invocations[0]?.line).toBe(3);
    expect(invocations[0]?.args).toEqual(["env", "key"]);
  });

  it("splits invocation arguments at top-level commas only", () => {
    const invocations = findMacroInvocations(
      "call!(env, DataKey { a: 1, b: 2 }, (x, y));",
      "call",
    );

    expect(invocations[0]?.args).toEqual(["env", "DataKey { a: 1, b: 2 }", "(x, y)"]);
  });

  it("reads the storage tier out of a receiver expression", () => {
    const code = sanitizeKeepLines(
      [
        "env.storage().persistent().set(&k, &v);",
        "env.storage()",
        "  .temporary()",
        "  .get(&k);",
      ].join("\n"),
    );
    const receivers = methodCalls(code, ["set", "get"]).map((c) =>
      storageTier(c.receiver),
    );

    expect(receivers).toEqual(["persistent", "temporary"]);
  });

  it("reads the tier of a chained call across newlines", () => {
    const code = sanitizeKeepLines(
      ["env.storage()", "  .instance()", "  .extend_ttl(&k, 1, 2);"].join("\n"),
    );
    const [call] = methodCalls(code, ["extend_ttl"]);

    expect(storageTier(call!.receiver)).toBe("instance");
  });

  it("reports a tier-less env.storage() call as unknown", () => {
    const code = sanitizeKeepLines("env.storage().set(&K, &v);");
    const [call] = methodCalls(code, ["set"]);

    expect(storageTier(call!.receiver)).toBe("unknown");
  });

  it("normalizes keys for comparison", () => {
    expect(normalizeKey("& user")).toBe("user");
    expect(normalizeKey("&&KEY")).toBe("KEY");
    expect(normalizeKey("user")).toBe(normalizeKey("&user"));
  });
});

describe("AP-STORAGE-001: ledger access hidden in macro expansions", () => {
  it("flags a persistent write performed by a macro with no bump anywhere", () => {
    const code = [
      "#[contractimpl]", // 1
      "impl V {", // 2
      "  pub fn save(env: Env, k: Symbol, v: i128) {", // 3
      "    put!(env, k, v);", // 4
      "  }", // 5
      "}", // 6
      "macro_rules! put {", // 7
      "  ($e:expr, $k:expr, $v:expr) => {", // 8
      "    $e.storage().persistent().set(&$k, &$v);", // 9
      "  };", // 10
      "}", // 11
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    // Attributed to the call site — the line a developer can act on — not to
    // the macro body on line 9.
    expect(findings[0]?.location.line).toBe(4);
    expect(findings[0]?.message).toContain("persistent");
  });

  it("names the enclosing function when the shared extraction is available", () => {
    const code = [
      "impl V {", // 1
      "  pub fn save(env: Env, k: Symbol, v: i128) {", // 2
      "    put!(env, k, v);", // 3
      "  }", // 4
      "}", // 5
      "macro_rules! put {", // 6
      "  ($e:expr, $k:expr, $v:expr) => { $e.storage().persistent().set(&$k, &$v); };", // 7
      "}", // 8
    ].join("\n");

    const findings = engineFindings(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.function).toBe("save");
    // Column of the `fn` keyword (`  pub fn` -> 7), the repo's convention for
    // function-anchored findings.
    expect(findings[0]?.location.column).toBe(7);
  });

  it("stays silent when the write and its bump both go through macros", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol, v: i128) {",
      "    put!(env, k, v);",
      "    keep!(env, k);",
      "  }",
      "}",
      "macro_rules! put {",
      "  ($e:expr, $k:expr, $v:expr) => { $e.storage().persistent().set(&$k, &$v); };",
      "}",
      "macro_rules! keep {",
      "  ($e:expr, $k:expr) => { $e.storage().persistent().extend_ttl(&$k, 100, 200); };",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("flags a macro read that is never bumped", () => {
    const code = [
      "fn load(env: Env, k: Symbol) -> i128 {", // 1
      "  read!(env, k)", // 2
      "}", // 3
      "macro_rules! read {", // 4
      "  ($e:expr, $k:expr) => { $e.storage().persistent().get(&$k).unwrap_or(0) };", // 5
      "}", // 6
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(2);
  });

  it("does not report a macro it cannot bind (repetition)", () => {
    const code = [
      "impl V {",
      "  pub fn save_all(env: Env, a: Symbol) {",
      "    put_all!(env, [a, b]);",
      "  }",
      "}",
      "macro_rules! put_all {",
      "  ($e:expr, [ $($k:expr),* ]) => { $( $e.storage().persistent().set(&$k, &1); )* };",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("does not report a macro whose body invokes another macro", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol) {",
      "    outer!(env, k);",
      "  }",
      "}",
      "macro_rules! inner {",
      "  ($e:expr, $k:expr) => { $e.storage().persistent().set(&$k, &1); };",
      "}",
      "macro_rules! outer {",
      "  ($e:expr, $k:expr) => { inner!($e, $k); };",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("does not invent storage access from a comment mentioning a macro", () => {
    const code = [
      "// put!(env, k, v) writes persistent storage with no extend_ttl",
      "fn helper() -> u32 { 1 }",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("does not read storage out of a macro definition that is never invoked", () => {
    const code = [
      "fn helper() -> u32 { 1 }",
      "macro_rules! unused {",
      "  ($e:expr, $k:expr) => { $e.storage().persistent().set(&$k, &1); };",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });
});

describe("AP-STORAGE-001: tier and key scoping", () => {
  it("flags a persistent write bumped only on the temporary tier", () => {
    const code = [
      "impl V {", // 1
      "  pub fn stage(env: Env, k: Symbol, v: i128) {", // 2
      "    env.storage().persistent().set(&k, &v);", // 3
      "    env.storage().temporary().set(&k, &v);", // 4
      "    env.storage().temporary().extend_ttl(&k, 100, 200);", // 5
      "  }", // 6
      "}", // 7
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(3);
    expect(findings[0]?.message).toContain("persistent");
  });

  it("stays silent when each tier is bumped on its own tier", () => {
    const code = [
      "impl V {",
      "  pub fn stage(env: Env, k: Symbol, v: i128) {",
      "    env.storage().persistent().set(&k, &v);",
      "    env.storage().temporary().set(&k, &v);",
      "    env.storage().persistent().extend_ttl(&k, 100, 200);",
      "    env.storage().temporary().extend_ttl(&k, 100, 200);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("flags a write whose bump targets a different key", () => {
    const code = [
      "impl V {", // 1
      "  pub fn save(env: Env, k: Symbol, other: Symbol, v: i128) {", // 2
      "    env.storage().persistent().set(&k, &v);", // 3
      "    env.storage().persistent().extend_ttl(&other, 100, 200);", // 4
      "  }", // 5
      "}", // 6
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(3);
  });

  it("stays silent when the bump targets the same key", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol, v: i128) {",
      "    env.storage().persistent().set(&k, &v);",
      "    env.storage().persistent().extend_ttl(&k, 100, 200);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("follows a key through a local alias", () => {
    const aliased = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol, v: i128) {",
      "    let entry_key = k;",
      "    env.storage().persistent().set(&entry_key, &v);",
      "    env.storage().persistent().extend_ttl(&k, 100, 200);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(aliased)).toHaveLength(0);
  });

  it("follows a tier held in a local binding", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol, v: i128) {",
      "    let tier = env.storage().temporary();",
      "    tier.set(&k, &v);",
      "    env.storage().persistent().extend_ttl(&k, 100, 200);",
      "  }",
      "}",
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain("temporary");
  });

  it("stays silent on a bump whose own key is a helper it cannot follow", () => {
    // `Self::key(&env)` is not comparable by text; the rule accounts for the
    // access rather than guessing that it is a different entry.
    const code = [
      "impl V {",
      "  pub fn save(env: Env, v: i128) {",
      "    env.storage().persistent().set(&KEY, &v);",
      "    env.storage().persistent().extend_ttl(&Self::key(&env), 100, 200);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("covers every instance access from a single instance bump", () => {
    const code = [
      "impl V {",
      "  pub fn set_fee(env: Env, fee: u32) {",
      "    env.storage().instance().set(&KEY_FEE, &fee);",
      "    env.storage().instance().extend_ttl(&KEY_FEE, 100, 200);",
      "  }",
      "  pub fn get_fee(env: Env) -> u32 {",
      "    env.storage().instance().get(&KEY_FEE).unwrap_or(0)",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("flags instance storage that is never bumped", () => {
    const code = [
      "impl V {",
      "  pub fn upgrade(env: Env, hash: BytesN<32>) {",
      "    env.storage().instance().set(&KEY_WASM, &hash);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(1);
  });

  it("treats extend_ttl_to_threshold as a bump", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol, v: i128) {",
      "    env.storage().persistent().set(&k, &v);",
      "    env.storage().persistent().extend_ttl_to_threshold(&k, Threshold::Persistent);",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("counts get_extended as a bump rather than an access", () => {
    const code = [
      "impl V {",
      "  pub fn alive(env: Env, k: Symbol) -> u32 {",
      "    env.storage().persistent().get_extended(&k, 100, 200)",
      "  }",
      "}",
    ].join("\n");

    expect(scan(code)).toHaveLength(0);
  });

  it("reports one finding per file, at the first uncovered entry", () => {
    const code = [
      "impl V {", // 1
      "  pub fn a(env: Env, k: Symbol, v: i128) {", // 2
      "    env.storage().persistent().set(&k, &v);", // 3
      "  }", // 4
      "  pub fn b(env: Env, j: Symbol, v: i128) {", // 5
      "    env.storage().temporary().set(&j, &v);", // 6
      "  }", // 7
      "}", // 8
    ].join("\n");

    const findings = scan(code);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.location.line).toBe(3);
    expect(findings[0]?.message).toContain("persistent");
    expect(findings[0]?.message).toContain("temporary");
  });

  it("produces a well-formed finding", () => {
    const code = [
      "impl V {",
      "  pub fn save(env: Env, k: Symbol) {",
      "    put!(env, k);",
      "  }",
      "}",
      "macro_rules! put { ($e:expr, $k:expr) => { $e.storage().persistent().set(&$k, &1); }; }",
    ].join("\n");

    const [finding] = scan(code);

    expect(finding?.id).toBe("AP-STORAGE-001");
    expect(finding?.severity).toBe("high");
    expect(finding?.confidence).toBe("medium");
    expect(finding?.location.line).toBeGreaterThan(0);
    expect(finding?.message.length).toBeGreaterThan(10);
    expect(finding?.remediation).toContain("extend_ttl");
  });
});

describe("AP-STORAGE-001: changes must not disturb other rules", () => {
  it("keeps a macro-using contract's other findings intact", () => {
    const code = [
      "impl V {",
      "  pub fn payout(env: Env, token: Address, to: Address, amount: i128) {",
      "    let balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);",
      "    let remaining = balance - amount;",
      "    env.storage().persistent().set(&to, &remaining);",
      "    let client = token::Client::new(&env, &token);",
      "    client.transfer(&env.current_contract_address(), &to, &amount);",
      "    log!(env, \"payout\");",
      "  }",
      "}",
    ].join("\n");

    const ids = new AuditEngine(createDefaultRegistry())
      .run(code)
      .map((f) => f.id)
      .sort();

    expect(ids).toEqual([
      "AP-ARITH-001",
      "AP-AUTH-001",
      "AP-CALL-001",
      "AP-DEBUG-001",
      "AP-STORAGE-001",
    ]);
  });
});

describe("AP-STORAGE-001: shipped fixtures and scan targets", () => {
  it("contracts/MacroVault.rs flags the uncovered persistent entry", () => {
    const storage = scanFile("contracts/MacroVault.rs").filter(
      (f) => f.id === "AP-STORAGE-001",
    );

    expect(storage).toHaveLength(1);
    // The near-miss: this contract *does* bump a temporary entry, which the
    // previous file-level check accepted as proof that everything was bumped.
    expect(storage[0]?.location.function).toBe("kept_alive");
  });

  it("fixtures/safe/macro_ttl.rs produces no findings", () => {
    expect(scanFile("fixtures/safe/macro_ttl.rs")).toEqual([]);
  });
});
