//! Per-issuer registration quotas (#806)
//!
//! A compromised issuer key can otherwise flood the registry with seals that
//! later need individual revocation. The admin may bound one key's
//! registrations per ledger-time window bucket. Rules under test:
//!
//! 1. Unset means unlimited: a deployment that never calls `set_issuer_quota`
//!    registers exactly as it did before this feature existed.
//! 2. The quota is enforced on every issuer-attributed path — direct and
//!    delegated, seal (Tier 3) and source (Tier 2) — charged to the key the
//!    registration is attributed to, never to the delegate.
//! 3. A rejected registration writes no proof record and consumes no quota.
//! 4. A window rollover into the next ledger-time bucket resets the count
//!    with no admin transaction.
//! 5. Quotas are per key: bounding one key never bounds another.
//! 6. Clearing a quota (zero fields) restores unlimited immediately.
//! 7. The quota check stays inside the `register_seal` resource baseline.

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{
    testutils::Address as _, testutils::Events, testutils::Ledger, Address, BytesN, Env, IntoVal,
    Symbol, Vec as SorobanSdkVec,
};

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

#[cfg(test)]
const ONE_HOUR: u64 = 3_600;

/// Returns (env, contract_id, admin, issuer) at `start_ts`.
#[cfg(test)]
fn setup(start_ts: u64) -> (Env, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let issuer = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &issuer, &b32(&env, 0xAA));

    (env, contract_id, admin, issuer)
}

/// Register one seal with caller-chosen byte values so several registrations
/// in one test never collide on `proof_id` / `video_hash`.
#[cfg(test)]
fn seal(client: &HarpocratesRegistryClient, issuer: &Address, v: u8) -> ProofRecord {
    client.register_seal(
        issuer,
        &b32(&client.env, v),
        &b32(&client.env, v + 1),
        &b32(&client.env, v + 2),
    )
}

#[cfg(test)]
fn source_reg(client: &HarpocratesRegistryClient, source: &Address, v: u8) -> ProofRecord {
    client.register_source(
        source,
        &b32(&client.env, v),
        &b32(&client.env, v + 1),
        &b32(&client.env, v + 2),
    )
}

/// Invoke a proof-registering entry point without reverting the caller and
/// return the `RegistryError` discriminant on failure (sentinel `0xffff`
/// for anything that is not a clean contract error).
#[cfg(test)]
fn try_invoke_proof(
    env: &Env,
    contract_id: &Address,
    fn_name: &str,
    args: SorobanSdkVec<Val>,
) -> Result<ProofRecord, u32> {
    let result = env.try_invoke_contract::<ProofRecord, RegistryError>(
        contract_id,
        &Symbol::new(env, fn_name),
        args,
    );
    match result {
        Ok(Ok(record)) => Ok(record),
        Ok(Err(_)) => Err(0xfffe),
        Err(Ok(e)) => Err(e as u32),
        Err(Err(_)) => Err(0xffff),
    }
}

/// Invoke `register_seal` without reverting the caller.
#[cfg(test)]
fn try_seal(env: &Env, contract_id: &Address, issuer: &Address, v: u8) -> Result<ProofRecord, u32> {
    let mut args = SorobanSdkVec::new(env);
    args.push_back(issuer.clone().into_val(env));
    args.push_back(b32(env, v).into_val(env));
    args.push_back(b32(env, v + 1).into_val(env));
    args.push_back(b32(env, v + 2).into_val(env));
    try_invoke_proof(env, contract_id, "register_seal", args)
}

/// Invoke `register_seal_delegated` without reverting the caller.
#[cfg(test)]
fn try_seal_delegated(
    env: &Env,
    contract_id: &Address,
    delegate: &Address,
    issuer: &Address,
    v: u8,
) -> Result<ProofRecord, u32> {
    let mut args = SorobanSdkVec::new(env);
    args.push_back(delegate.clone().into_val(env));
    args.push_back(issuer.clone().into_val(env));
    args.push_back(b32(env, v).into_val(env));
    args.push_back(b32(env, v + 1).into_val(env));
    args.push_back(b32(env, v + 2).into_val(env));
    try_invoke_proof(env, contract_id, "register_seal_delegated", args)
}

/// Invoke `register_source` without reverting the caller.
#[cfg(test)]
fn try_source(
    env: &Env,
    contract_id: &Address,
    source: &Address,
    v: u8,
) -> Result<ProofRecord, u32> {
    let mut args = SorobanSdkVec::new(env);
    args.push_back(source.clone().into_val(env));
    args.push_back(b32(env, v).into_val(env));
    args.push_back(b32(env, v + 1).into_val(env));
    args.push_back(b32(env, v + 2).into_val(env));
    try_invoke_proof(env, contract_id, "register_source", args)
}

/// Invoke `register_source_delegated` without reverting the caller.
#[cfg(test)]
fn try_source_delegated(
    env: &Env,
    contract_id: &Address,
    delegate: &Address,
    source: &Address,
    v: u8,
) -> Result<ProofRecord, u32> {
    let mut args = SorobanSdkVec::new(env);
    args.push_back(delegate.clone().into_val(env));
    args.push_back(source.clone().into_val(env));
    args.push_back(b32(env, v).into_val(env));
    args.push_back(b32(env, v + 1).into_val(env));
    args.push_back(b32(env, v + 2).into_val(env));
    try_invoke_proof(env, contract_id, "register_source_delegated", args)
}

// ---------------------------------------------------------------------------
// Default: unlimited
// ---------------------------------------------------------------------------

#[test]
fn unset_quota_is_unlimited() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    assert!(client.get_issuer_quota(&issuer).is_none());

    for i in 0..5u8 {
        let record = seal(&client, &issuer, 0x10 + i * 3);
        assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    }

    // Still unlimited; no quota was implied by the registrations themselves.
    assert!(client.get_issuer_quota(&issuer).is_none());
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 0);
    // The admin is untouched by any of this.
    assert!(client.get_issuer_quota(&admin).is_none());
}

// ---------------------------------------------------------------------------
// Admin surface
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn setting_a_quota_requires_the_admin() {
    let (env, contract_id, _, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let mallory = Address::generate(&env);

    client.set_issuer_quota(&mallory, &issuer, &10, &ONE_HOUR);
}

#[test]
fn setting_a_quota_round_trips_and_emits_a_privacy_safe_event() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.set_issuer_quota(&admin, &issuer, &7, &ONE_HOUR);

    // Exactly one event, the quota update. `set_issuer_quota` sees only the
    // key, the two bounds, and the admin — never proof material, metadata,
    // witnesses, or media. `events().all()` reflects the most recent
    // invocation, so it is read before any read-only getter follows.
    let events = env.events().all();
    assert_eq!(events.events().len(), 1);

    let quota = client.get_issuer_quota(&issuer).unwrap();
    assert_eq!(quota.max_registrations, 7);
    assert_eq!(quota.window_secs, ONE_HOUR);
}

// ---------------------------------------------------------------------------
// Enforcement on the direct seal path
// ---------------------------------------------------------------------------

#[test]
fn quota_rejects_the_registration_over_the_limit() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &2, &ONE_HOUR);

    seal(&client, &issuer, 0x10);
    seal(&client, &issuer, 0x13);

    let err = try_seal(&env, &contract_id, &issuer, 0x16);
    assert_eq!(err, Err(RegistryError::IssuerQuotaExhausted as u32));
}

#[test]
#[should_panic(expected = "Error(Contract, #88)")] // IssuerQuotaExhausted
fn exceeding_the_seal_quota_reverts_with_the_stable_code() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    seal(&client, &issuer, 0x10);
    seal(&client, &issuer, 0x13);
}

#[test]
fn a_rejected_registration_writes_no_record_and_consumes_no_quota() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    seal(&client, &issuer, 0x10);

    let rejected = try_seal(&env, &contract_id, &issuer, 0x13);
    assert_eq!(rejected, Err(RegistryError::IssuerQuotaExhausted as u32));

    // The revert unwound everything: no proof, no video index, no charge.
    assert!(client.get_proof(&b32(&env, 0x15)).is_none());
    assert!(client.get_by_video(&b32(&env, 0x13)).is_none());
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 1);
}

// ---------------------------------------------------------------------------
// Window rollover
// ---------------------------------------------------------------------------

#[test]
fn window_rollover_resets_the_count() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    seal(&client, &issuer, 0x10);

    // Still inside the bucket that started at t = 0: the second seal is out.
    env.ledger().set_timestamp(ONE_HOUR - 1);
    let err = try_seal(&env, &contract_id, &issuer, 0x13);
    assert_eq!(err, Err(RegistryError::IssuerQuotaExhausted as u32));

    // The next ledger-time bucket starts fresh with no admin transaction.
    env.ledger().set_timestamp(ONE_HOUR);
    let record = seal(&client, &issuer, 0x13);
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 1);
}

#[test]
fn get_issuer_quota_usage_reports_the_current_bucket() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &3, &ONE_HOUR);

    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 0);

    seal(&client, &issuer, 0x10);
    seal(&client, &issuer, 0x13);

    let usage = client.get_issuer_quota_usage(&issuer);
    assert_eq!(usage.bucket, 1_000 / ONE_HOUR);
    assert_eq!(usage.count, 2);

    // Past the rollover the same getter answers a fresh bucket, so callers
    // never have to recompute window arithmetic themselves.
    env.ledger().set_timestamp(ONE_HOUR);
    let usage = client.get_issuer_quota_usage(&issuer);
    assert_eq!(usage.bucket, 1);
    assert_eq!(usage.count, 0);
}

// ---------------------------------------------------------------------------
// Per-key isolation
// ---------------------------------------------------------------------------

#[test]
fn quotas_are_per_key() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let bounded = Address::generate(&env);
    let unbounded = Address::generate(&env);
    let source = Address::generate(&env);
    client.add_issuer(&admin, &bounded, &b32(&env, 0xAB));
    client.add_issuer(&admin, &unbounded, &b32(&env, 0xAC));
    client.set_issuer_quota(&admin, &bounded, &1, &ONE_HOUR);

    seal(&client, &bounded, 0x10);
    let err = try_seal(&env, &contract_id, &bounded, 0x13);
    assert_eq!(err, Err(RegistryError::IssuerQuotaExhausted as u32));

    // A different issuer, and an unregistered source address, are unaffected.
    // Each subject registers under its own byte range: proof and video
    // digests are unique registry-wide, not per key.
    seal(&client, &unbounded, 0x20);
    seal(&client, &unbounded, 0x23);
    source_reg(&client, &source, 0x30);
    // The originally named issuer key carries no quota either.
    seal(&client, &issuer, 0x40);
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

#[test]
fn delegated_seal_registration_charges_the_issuer_not_the_delegate() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let delegate = Address::generate(&env);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);
    client.grant_delegation(
        &issuer,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_HOUR,
    );

    let record = client.register_seal_delegated(
        &delegate,
        &issuer,
        &b32(&env, 0x10),
        &b32(&env, 0x11),
        &b32(&env, 0x12),
    );
    assert_eq!(record.issuer, Some(issuer.clone()));
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 1);

    // The delegate never holds quota of its own; the issuer's bucket is spent.
    let delegated = try_seal_delegated(&env, &contract_id, &delegate, &issuer, 0x13);
    assert_eq!(delegated, Err(RegistryError::IssuerQuotaExhausted as u32));

    // The direct path shares the same bucket as the delegated one.
    let direct = try_seal(&env, &contract_id, &issuer, 0x16);
    assert_eq!(direct, Err(RegistryError::IssuerQuotaExhausted as u32));
}

#[test]
fn delegated_source_registration_charges_the_source() {
    let (env, contract_id, admin, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let delegate = Address::generate(&env);
    client.set_issuer_quota(&admin, &source, &1, &ONE_HOUR);
    client.grant_delegation(
        &source,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SOURCE,
        &ONE_HOUR,
    );

    let record = client.register_source_delegated(
        &delegate,
        &source,
        &b32(&env, 0x10),
        &b32(&env, 0x11),
        &b32(&env, 0x12),
    );
    assert_eq!(record.source, Some(source.clone()));
    assert_eq!(client.get_issuer_quota_usage(&source).count, 1);

    let delegated = try_source_delegated(&env, &contract_id, &delegate, &source, 0x13);
    assert_eq!(delegated, Err(RegistryError::IssuerQuotaExhausted as u32));
}

// ---------------------------------------------------------------------------
// Tier 2 direct path
// ---------------------------------------------------------------------------

#[test]
fn source_registrations_are_charged_too() {
    let (env, contract_id, admin, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    client.set_issuer_quota(&admin, &source, &2, &ONE_HOUR);

    source_reg(&client, &source, 0x10);
    source_reg(&client, &source, 0x13);

    let result = try_source(&env, &contract_id, &source, 0x16);
    assert_eq!(result, Err(RegistryError::IssuerQuotaExhausted as u32));
    assert!(client.get_proof(&b32(&env, 0x18)).is_none());
}

// ---------------------------------------------------------------------------
// Clearing
// ---------------------------------------------------------------------------

#[test]
fn clearing_the_quota_restores_unlimited() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    seal(&client, &issuer, 0x10);
    let err = try_seal(&env, &contract_id, &issuer, 0x13);
    assert_eq!(err, Err(RegistryError::IssuerQuotaExhausted as u32));

    // Zero fields clear the quota and abandon the accrued counter.
    client.set_issuer_quota(&admin, &issuer, &0, &0);
    assert!(client.get_issuer_quota(&issuer).is_none());
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 0);

    seal(&client, &issuer, 0x13);
    seal(&client, &issuer, 0x16);
    assert_eq!(client.get_issuer_quota_usage(&issuer).count, 0);
}

#[test]
fn re_armed_quota_starts_from_a_clean_bucket() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    seal(&client, &issuer, 0x10);
    client.set_issuer_quota(&admin, &issuer, &0, &0);
    client.set_issuer_quota(&admin, &issuer, &1, &ONE_HOUR);

    // The counter spent under the previous quota does not leak into the
    // re-armed one.
    let record = seal(&client, &issuer, 0x13);
    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    let err = try_seal(&env, &contract_id, &issuer, 0x16);
    assert_eq!(err, Err(RegistryError::IssuerQuotaExhausted as u32));
}

// ---------------------------------------------------------------------------
// Resource budget
// ---------------------------------------------------------------------------

#[cfg(test)]
fn measure<T>(env: &Env, f: impl FnOnce() -> T) -> (u64, u64, T) {
    env.cost_estimate().budget().reset_unlimited();
    let result = f();
    let budget = env.cost_estimate().budget();
    (
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost(),
        result,
    )
}

/// The quota check adds one persistent read and at most one persistent write
/// to `register_seal`, so the measured call must stay inside the existing
/// worst-case `register_seal` baseline rather than needing a new ceiling.
#[test]
fn budget_register_seal_with_quota_stays_within_baseline() {
    let (env, contract_id, admin, issuer) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    client.set_issuer_quota(&admin, &issuer, &1_000, &ONE_HOUR);
    client.set_proof_ttl(&admin, &86_400u64);

    let (cpu, mem, _) = measure(&env, || seal(&client, &issuer, 0x10));
    assert!(
        cpu <= 2_000_000,
        "register_seal with quota CPU budget exceeded: {cpu} > 2_000_000"
    );
    assert!(
        mem <= 1_500_000,
        "register_seal with quota memory budget exceeded: {mem} > 1_500_000"
    );
}
