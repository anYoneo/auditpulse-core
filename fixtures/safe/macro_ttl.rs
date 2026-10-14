//! Safe fixture: the ledger write and its TTL bump both live inside
//! `macro_rules!` definitions.
//!
//! Expected findings: none.
//!
//! The rule cannot expand Rust macros (no compiler here), so it re-reads one
//! level of `macro_rules!` and binds each metavariable to the argument the
//! call site passes. `put_entry!` writes a persistent entry and `bump_entry!`
//! extends the same key, so the entry is kept alive — before this behavior
//! existed the file was reported even though it does the right thing.

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct MacroVault;

#[contractimpl]
impl MacroVault {
    /// Auth, a macro-driven write, and a macro-driven bump of the same key.
    pub fn deposit(env: Env, user: Address, key: Symbol, value: i128) {
        env.require_auth(&user);
        put_entry!(env, key, value);
        bump_entry!(env, key);
    }
}

macro_rules! put_entry {
    ($env:expr, $key:expr, $value:expr) => {
        $env.storage().persistent().set(&$key, &$value);
    };
}

macro_rules! bump_entry {
    ($env:expr, $key:expr) => {
        $env.storage().persistent().extend_ttl(&$key, 100, 200);
    };
}
