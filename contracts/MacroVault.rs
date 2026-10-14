//! Sample Soroban contract used as a scan target for AuditPulse: ledger
//! access and TTL handling hidden behind `macro_rules!` expansions.
//!
//! Scan it with:
//!   node dist/index.js scan contracts/MacroVault.rs
//!
//! Expected finding: AP-STORAGE-001 on `kept_alive`, because the `persistent`
//! entry it writes through a macro is never bumped on its own tier. The
//! `temporary` entry in the same contract *is* bumped, which is exactly the
//! near-miss a file-level "any extend_ttl silences the file" check missed.
//!
//! `indirect` is a documented limit: a macro whose body invokes another macro
//! is not reported, since the analyzer does not expand Rust macros and will
//! not guess at the result.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct MacroVault;

#[contractimpl]
impl MacroVault {
    /// AP-STORAGE-001: `put_entry!` writes a persistent entry, and the only
    /// TTL bump in this contract targets a *temporary* entry, so this key
    /// expires silently.
    pub fn kept_alive(env: Env, admin: Address, key: Symbol, value: i128) {
        admin.require_auth();
        put_entry!(env, key, value);
    }

    /// Fully covered: the write and the bump both go through macros, on the
    /// same tier and the same key.
    pub fn staged(env: Env, admin: Address, key: Symbol, value: i128) {
        admin.require_auth();
        stage_temp!(env, key, value);
        bump_temp!(env, key);
    }

    /// Documented gap: the macro body hides the write behind another macro
    /// invocation, so the drift is not reported.
    pub fn indirect(env: Env, admin: Address, key: Symbol, value: i128) {
        admin.require_auth();
        expand_macro!(env, key, value);
    }
}

macro_rules! put_entry {
    ($env:expr, $key:expr, $value:expr) => {
        $env.storage().persistent().set(&$key, &$value);
    };
}

macro_rules! stage_temp {
    ($env:expr, $key:expr, $value:expr) => {
        $env.storage().temporary().set(&$key, &$value);
    };
}

macro_rules! bump_temp {
    ($env:expr, $key:expr) => {
        $env.storage().temporary().extend_ttl(&$key, 100, 200);
    };
}

macro_rules! inner_write {
    ($env:expr, $key:expr, $value:expr) => {
        $env.storage().persistent().set(&$key, &$value);
    };
}

macro_rules! expand_macro {
    ($env:expr, $key:expr, $value:expr) => {
        inner_write!($env, $key, $value);
    };
}
