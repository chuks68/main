//! Issuer rotation grace windows (#323)
//!
//! Focused positive, negative, boundary, and regression coverage for rotating a
//! Tier 3 issuer key without invalidating the evidence that key already signed.
//!
//! Rules under test:
//!
//! 1. A rotation retires the previous issuer key immediately — it can no longer
//!    sign new seals, directly or through a delegation — and the replacement
//!    becomes the key that can.
//! 2. Evidence registered before the rotation is untouched: the stored
//!    `ProofRecord` is not rewritten and `get_proof_status` answers exactly as
//!    it did before, while `is_issuer_verifiable` keeps the retired key covered
//!    until its grace window lapses.
//! 3. The window is lazy and fails closed: at `grace_expires_at` (and after)
//!    the retired key is no longer verifiable, with no transaction required.
//! 4. The window is bounded: `grace_secs == 0` selects
//!    [`DEFAULT_ISSUER_ROTATION_GRACE_SECS`], anything above
//!    [`MAX_ISSUER_ROTATION_GRACE_SECS`] or overflowing ledger time is
//!    rejected, and a rotation may not name the same key twice.
//! 5. Revocation and re-addition outrank the window: `revoke_issuer`,
//!    `add_issuer`, and the timelocked `RevokeIssuer` action all clear the
//!    rotation record.
//! 6. Reads never panic and never touch media, metadata preimages, witnesses, or
//!    keys: unknown, revoked, and unsupported issuers simply fail closed.
//!
//! Run: `cargo test -p harpocrates-registry issuer_rotation -- --nocapture`

#[cfg(test)]
use super::*;
#[cfg(test)]
use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Env};

#[cfg(test)]
const ONE_DAY: u64 = 24 * 60 * 60;

#[cfg(test)]
fn b32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

/// Returns (env, contract_id, admin, previous_issuer, replacement_issuer) at
/// `start_ts`, with both issuer keys registered and active.
#[cfg(test)]
fn setup(start_ts: u64) -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(start_ts);

    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let previous = Address::generate(&env);
    let replacement = Address::generate(&env);

    client.init(&admin);
    client.add_issuer(&admin, &previous, &b32(&env, 0x0A));
    client.add_issuer(&admin, &replacement, &b32(&env, 0x0B));

    (env, contract_id, admin, previous, replacement)
}

// ---------------------------------------------------------------------------
// Positive: rotation retires the old key and opens a bounded window
// ---------------------------------------------------------------------------

#[test]
fn rotation_retires_the_previous_key_and_opens_the_default_window() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let grace_expires_at = client.rotate_issuer(&admin, &previous, &replacement, &0);

    assert_eq!(grace_expires_at, 1_000 + DEFAULT_ISSUER_ROTATION_GRACE_SECS);
    assert!(!client.get_issuer(&previous).unwrap().active);
    assert!(client.get_issuer(&replacement).unwrap().active);

    let rotation = client.get_issuer_rotation(&previous).unwrap();
    assert_eq!(rotation.previous_issuer, previous);
    assert_eq!(rotation.replacement_issuer, replacement);
    assert_eq!(rotation.rotated_at, 1_000);
    assert_eq!(rotation.grace_expires_at, grace_expires_at);
    assert_eq!(rotation.grace_secs, DEFAULT_ISSUER_ROTATION_GRACE_SECS);

    // The retired key still covers what it already signed; the replacement is
    // the current key and has no rotation record of its own.
    assert!(client.is_issuer_verifiable(&previous));
    assert!(client.is_issuer_verifiable(&replacement));
    assert!(client.get_issuer_rotation(&replacement).is_none());
}

#[test]
fn rotation_emits_a_rotation_event() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    assert!(event_test_utils::has_event(&env, &["issuer", "rotate"]));
}

#[test]
fn an_explicit_grace_window_is_honoured_exactly() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let grace_expires_at = client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    assert_eq!(grace_expires_at, 1_000 + ONE_DAY);
    let rotation = client.get_issuer_rotation(&previous).unwrap();
    assert_eq!(rotation.grace_secs, ONE_DAY);
    assert_eq!(rotation.grace_expires_at, 1_000 + ONE_DAY);
}

#[test]
fn a_grace_exactly_at_the_cap_is_accepted() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    let grace_expires_at = client.rotate_issuer(
        &admin,
        &previous,
        &replacement,
        &MAX_ISSUER_ROTATION_GRACE_SECS,
    );

    assert_eq!(grace_expires_at, 1_000 + MAX_ISSUER_ROTATION_GRACE_SECS);
}

#[test]
fn the_replacement_can_register_new_seals() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    let record = client.register_seal(&replacement, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));

    assert_eq!(record.tier, TIER_PUBLIC_SEAL);
    assert_eq!(record.issuer, Some(replacement));
}

// ---------------------------------------------------------------------------
// Negative: the retired key stops signing, including through a delegation
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn the_retired_key_cannot_register_new_seals_during_its_grace_window() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // The window covers evidence already signed, never new signatures.
    client.register_seal(&previous, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn a_delegate_cannot_register_for_a_retired_key() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let delegate = Address::generate(&env);

    client.grant_delegation(
        &previous,
        &delegate,
        &DELEGATION_SCOPE_REGISTER_SEAL,
        &ONE_DAY,
    );
    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    client.register_seal_delegated(
        &delegate,
        &previous,
        &b32(&env, 1),
        &b32(&env, 2),
        &b32(&env, 3),
    );
}

// ---------------------------------------------------------------------------
// Regression: evidence issued before the rotation
// ---------------------------------------------------------------------------

#[test]
fn evidence_issued_before_rotation_survives_the_rotation_unchanged() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0x33);

    let before = client.register_seal(&previous, &b32(&env, 0x11), &b32(&env, 0x22), &proof_id);
    assert_eq!(before.issuer, Some(previous.clone()));
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // Rotation changes key standing, never stored evidence: the record is not
    // rewritten, its status does not change, and the retired key is still the
    // key the proof names.
    assert_eq!(client.get_proof(&proof_id).unwrap(), before);
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
    assert!(client.is_issuer_verifiable(&previous));
}

#[test]
fn the_grace_window_lapses_at_its_expiry_without_a_transaction() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let proof_id = b32(&env, 0x33);

    client.register_seal(&previous, &b32(&env, 0x11), &b32(&env, 0x22), &proof_id);
    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // One second before the deadline the retired key still covers its
    // pre-rotation evidence.
    env.ledger().set_timestamp(1_000 + ONE_DAY - 1);
    assert!(client.is_issuer_verifiable(&previous));

    // `grace_expires_at` itself is already outside the window.
    env.ledger().set_timestamp(1_000 + ONE_DAY);
    assert!(!client.is_issuer_verifiable(&previous));

    // The record stays readable so an operator can see and settle it, and the
    // stored evidence keeps its own status either way.
    assert!(client.get_issuer_rotation(&previous).is_some());
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

#[test]
fn a_source_proof_is_unaffected_by_issuer_rotation() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let source = Address::generate(&env);
    let proof_id = b32(&env, 0x44);

    client.register_source(&source, &b32(&env, 0x11), &b32(&env, 0x22), &proof_id);
    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // Rotation is scoped to issuer standing: a Tier 2 record carries no issuer
    // and keeps its status.
    let record = client.get_proof(&proof_id).unwrap();
    assert!(record.issuer.is_none());
    assert_eq!(
        client.get_proof_status(&proof_id),
        ProofVerificationStatus::Valid
    );
}

// ---------------------------------------------------------------------------
// Authorization and input validation
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // Unauthorized
fn a_non_admin_cannot_rotate_an_issuer() {
    let (env, contract_id, _, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let stranger = Address::generate(&env);

    client.rotate_issuer(&stranger, &previous, &replacement, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #84)")] // InvalidIssuerRotation
fn a_rotation_must_name_two_distinct_keys() {
    let (env, contract_id, admin, previous, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &previous, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn an_unknown_previous_key_cannot_rotate() {
    let (env, contract_id, admin, _, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let unknown = Address::generate(&env);

    client.rotate_issuer(&admin, &unknown, &replacement, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn an_unknown_replacement_cannot_be_rotated_to() {
    let (env, contract_id, admin, previous, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let unknown = Address::generate(&env);

    client.rotate_issuer(&admin, &previous, &unknown, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn a_revoked_key_cannot_be_rotated_out() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.revoke_issuer(&admin, &previous);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn an_inactive_replacement_cannot_be_rotated_to() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.revoke_issuer(&admin, &replacement);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // UnknownIssuer
fn a_key_cannot_rotate_twice_without_being_re_added() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // The retired key is inactive, so it is no longer an active issuer to
    // rotate; re-adding it is the explicit way back.
    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #83)")] // InvalidIssuerRotationGrace
fn a_grace_above_the_cap_is_rejected() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(
        &admin,
        &previous,
        &replacement,
        &(MAX_ISSUER_ROTATION_GRACE_SECS + 1),
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #83)")] // InvalidIssuerRotationGrace
fn an_oversized_grace_is_rejected() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &u64::MAX);
}

#[test]
#[should_panic(expected = "Error(Contract, #83)")] // InvalidIssuerRotationGrace
fn a_grace_that_overflows_ledger_time_is_rejected() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    env.ledger().set_timestamp(u64::MAX - 10);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
}

// ---------------------------------------------------------------------------
// Revocation and re-addition outrank the window
// ---------------------------------------------------------------------------

#[test]
fn revoking_a_rotated_out_key_closes_the_window_immediately() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
    assert!(client.is_issuer_verifiable(&previous));

    client.revoke_issuer(&admin, &previous);

    assert!(client.get_issuer_rotation(&previous).is_none());
    assert!(!client.is_issuer_verifiable(&previous));
}

#[test]
fn re_adding_a_rotated_out_key_clears_the_stale_window() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);
    client.add_issuer(&admin, &previous, &b32(&env, 0x0C));

    assert!(client.get_issuer(&previous).unwrap().active);
    assert!(client.get_issuer_rotation(&previous).is_none());
    assert!(client.is_issuer_verifiable(&previous));

    // The re-added key is a full issuer again, so it can sign new seals.
    let record = client.register_seal(&previous, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
    assert_eq!(record.issuer, Some(previous));
}

// ---------------------------------------------------------------------------
// Settlement of a lapsed window
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #86)")] // IssuerRotationGraceStillActive
fn finalizing_before_the_window_lapses_is_rejected() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    env.ledger().set_timestamp(1_000 + ONE_DAY - 1);
    client.finalize_issuer_rotation(&previous);
}

#[test]
#[should_panic(expected = "Error(Contract, #85)")] // IssuerRotationNotFound
fn finalizing_an_unknown_rotation_is_rejected() {
    let (env, contract_id, _, previous, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.finalize_issuer_rotation(&previous);
}

#[test]
fn any_caller_can_settle_a_lapsed_window_exactly_at_the_deadline() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    // The deadline itself is outside the window, so settlement is callable
    // there, and it needs no role: the transition is fully determined by the
    // stored `grace_expires_at`.
    env.ledger().set_timestamp(1_000 + ONE_DAY);
    client.finalize_issuer_rotation(&previous);

    assert!(event_test_utils::has_event(&env, &["issuer", "grace"]));
    assert!(client.get_issuer_rotation(&previous).is_none());
    assert!(!client.is_issuer_verifiable(&previous));
}

#[test]
#[should_panic(expected = "Error(Contract, #85)")] // IssuerRotationNotFound
fn settling_a_settled_rotation_is_rejected() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    env.ledger().set_timestamp(1_000 + ONE_DAY);
    client.finalize_issuer_rotation(&previous);
    client.finalize_issuer_rotation(&previous);
}

// ---------------------------------------------------------------------------
// Compatibility: pre-#323 shapes keep working
// ---------------------------------------------------------------------------

#[test]
fn an_issuer_with_no_rotation_record_reads_as_verifiable() {
    let (env, contract_id, _, previous, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    // Migration fixture: a deployment that never called `rotate_issuer` has no
    // rotation key at all, so standing is exactly the pre-#323 `active` flag and
    // the stored `IssuerRecord` keeps its original shape.
    assert!(client.get_issuer_rotation(&previous).is_none());
    assert!(client.is_issuer_verifiable(&previous));
    assert!(client.get_issuer(&previous).unwrap().active);

    let record = client.register_seal(&previous, &b32(&env, 1), &b32(&env, 2), &b32(&env, 3));
    assert_eq!(record.issuer, Some(previous));
}

#[test]
fn a_revoked_issuer_with_no_rotation_record_is_not_verifiable() {
    let (env, contract_id, admin, previous, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.revoke_issuer(&admin, &previous);

    assert!(client.get_issuer_rotation(&previous).is_none());
    assert!(!client.is_issuer_verifiable(&previous));
}

#[test]
fn reads_fail_closed_for_unknown_issuers() {
    let (env, contract_id, _, _, _) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let unknown = Address::generate(&env);

    // No panic and no trust: an unregistered key is simply not verifiable.
    assert!(client.get_issuer_rotation(&unknown).is_none());
    assert!(!client.is_issuer_verifiable(&unknown));
}

#[test]
fn update_issuer_metadata_preserves_rotation_records() {
    let (env, contract_id, admin, previous, replacement) = setup(1_000);
    let client = HarpocratesRegistryClient::new(&env, &contract_id);

    client.rotate_issuer(&admin, &previous, &replacement, &ONE_DAY);

    let initial_rotation = client.get_issuer_rotation(&previous).unwrap();
    assert_eq!(initial_rotation.previous_issuer, previous);
    assert_eq!(initial_rotation.replacement_issuer, replacement);

    // Update replacement issuer metadata
    let new_metadata = b32(&env, 0xFE);
    client.update_issuer_metadata(&admin, &replacement, &new_metadata);

    // Metadata updated
    assert_eq!(
        client.get_issuer(&replacement).unwrap().metadata_hash,
        new_metadata
    );

    // Previous issuer's rotation record is preserved intact
    let post_update_rotation = client.get_issuer_rotation(&previous).unwrap();
    assert_eq!(post_update_rotation, initial_rotation);

    // Retired issuer is still verifiable within grace window
    assert!(client.is_issuer_verifiable(&previous));
}
