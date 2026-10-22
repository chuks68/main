//! Systematic uninitialized entry point failure tests (#807)
//!
//! Asserts that every state-changing entry point on an uninitialized contract
//! fails with a clean, typed error (primarily `RegistryError::NotInitialized`)
//! rather than an untyped panic or succeeding, and does not mutate persistent storage.

#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    Address, Bytes, BytesN, Env, Symbol,
};

fn bytes32(env: &Env, v: u8) -> BytesN<32> {
    BytesN::from_array(env, &[v; 32])
}

fn uninit_setup() -> (Env, HarpocratesRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(HarpocratesRegistry, ());
    // Leak env reference for test fixture ergonomics with client lifetime
    let env_ref: &'static Env = Box::leak(Box::new(env.clone()));
    let client = HarpocratesRegistryClient::new(env_ref, &contract_id);
    let caller1 = Address::generate(&env);
    let caller2 = Address::generate(&env);

    (env, client, caller1, caller2)
}

fn assert_err_code<T: core::fmt::Debug>(result: Result<T, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>, expected_code: u32) {
    match result {
        Err(Ok(err)) => {
            assert_eq!(
                err,
                soroban_sdk::Error::from_contract_error(expected_code),
                "expected contract error code #{}",
                expected_code
            );
        }
        other => panic!("expected contract error #{}, got {:?}", expected_code, other),
    }
}

// ---------------------------------------------------------------------------
// Administrative Entry Points (must return NotInitialized = 2)
// ---------------------------------------------------------------------------

#[test]
fn uninit_upgrade_storage_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_upgrade_storage(&caller1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::SchemaVersion));
}

#[test]
fn uninit_propose_admin_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_propose_admin(&caller1, &caller2);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::PendingAdmin));
}

#[test]
fn uninit_cancel_admin_transfer_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_cancel_admin_transfer(&caller1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::PendingAdmin));
}

#[test]
fn uninit_accept_admin_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_accept_admin(&caller1);
    assert_err_code(res, RegistryError::NoPendingAdmin as u32);
}

#[test]
fn uninit_add_issuer_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_add_issuer(&caller1, &caller2, &bytes32(&env, 1));
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Issuer(caller2)));
}

#[test]
fn uninit_set_verifier_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_set_verifier(&caller1, &caller2);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Verifier));
}

#[test]
fn uninit_set_verifier_circuit_versions_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_set_verifier_circuit_versions(
        &caller1,
        &MIN_SUPPORTED_CIRCUIT_VERSION,
        &MAX_SUPPORTED_CIRCUIT_VERSION,
    );
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::VerifierCircuitVersions));
}

#[test]
fn uninit_schedule_verifier_rotation_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_schedule_verifier_rotation(&caller1, &caller2, &100, &10, &10);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::VerifierState));
}

#[test]
fn uninit_activate_verifier_rotation_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_activate_verifier_rotation(&caller1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::VerifierState));
}

#[test]
fn uninit_rollback_verifier_rotation_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_rollback_verifier_rotation(&caller1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::VerifierState));
}

#[test]
fn uninit_add_credential_root_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let root = bytes32(&env, 10);
    let meta = bytes32(&env, 11);
    let res = client.try_add_credential_root(&caller1, &root, &meta);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::CredentialRootV2(root)));
}

#[test]
fn uninit_revoke_credential_root_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let root = bytes32(&env, 10);
    let res = client.try_revoke_credential_root(&caller1, &root);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_expire_credential_root_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let root = bytes32(&env, 10);
    let res = client.try_expire_credential_root(&caller1, &root);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_revoke_issuer_fails() {
    let (_env, client, caller1, caller2) = uninit_setup();
    let res = client.try_revoke_issuer(&caller1, &caller2);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_rotate_issuer_fails() {
    let (_env, client, caller1, caller2) = uninit_setup();
    let res = client.try_rotate_issuer(&caller1, &caller1, &caller2, &0);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_finalize_issuer_rotation_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_finalize_issuer_rotation(&caller1);
    assert_err_code(res, RegistryError::IssuerRotationNotFound as u32);
}

#[test]
fn uninit_set_proof_ttl_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_set_proof_ttl(&caller1, &3600);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::ProofTtl));
}

#[test]
fn uninit_propose_timelocked_action_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_propose_timelocked_action(&caller1, &1, &caller2, &bytes32(&env, 1));
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert_eq!(client.get_timelock_proposal_count(), 0);
}

#[test]
fn uninit_cancel_timelocked_proposal_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_cancel_timelocked_proposal(&caller1, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_execute_timelocked_proposal_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_execute_timelocked_proposal(&caller1, &1);
    assert_err_code(res, RegistryError::ProposalNotFound as u32);
}

#[test]
fn uninit_emergency_execute_timelock_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_emergency_execute_timelock(&caller1, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_set_timelock_min_delay_secs_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_set_timelock_min_delay_secs(&caller1, &86400);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::TimelockMinDelay));
}

#[test]
fn uninit_set_scope_epoch_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let scope = bytes32(&env, 1);
    let res = client.try_set_scope_epoch(&caller1, &scope, &5);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::ScopeEpoch(scope)));
}

#[test]
fn uninit_revoke_proof_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let res = client.try_revoke_proof(&caller1, &proof_id);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_verify_proof_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let res = client.try_verify_proof(&caller1, &proof_id, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_expire_proof_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let res = client.try_expire_proof(&caller1, &proof_id, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_correct_proof_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let new_meta = bytes32(&env, 2);
    let res = client.try_correct_proof(&caller1, &proof_id, &new_meta, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_set_revocation_root_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let root = bytes32(&env, 1);
    let res = client.try_set_revocation_root(&caller1, &root);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::RevocationRoot));
}

#[test]
fn uninit_set_guardian_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_set_guardian(&caller1, &caller2);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Guardian));
}

#[test]
fn uninit_unpause_fails() {
    let (_env, client, caller1, _) = uninit_setup();
    let res = client.try_unpause(&caller1, &PAUSE_DOMAIN_TIER1_REGISTRATION);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_add_schema_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let schema_hash = bytes32(&env, 1);
    let res = client.try_add_schema(&caller1, &schema_hash, &bytes32(&env, 2), &1, &4);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Schema(schema_hash)));
}

#[test]
fn uninit_deprecate_schema_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let schema_hash = bytes32(&env, 1);
    let res = client.try_deprecate_schema(&caller1, &schema_hash);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

// ---------------------------------------------------------------------------
// Registration Entry Points
// ---------------------------------------------------------------------------

#[test]
fn uninit_register_source_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let res = client.try_register_source(&caller1, &video, &meta, &proof_id);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
    assert!(!env.storage().persistent().has(&DataKey::Video(video)));
}

#[test]
fn uninit_register_source_batch_root_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let root = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let res = client.try_register_source_batch_root(&caller1, &root, &10, &meta);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::SourceBatch(root)));
}

#[test]
fn uninit_register_seal_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let res = client.try_register_seal(&caller1, &video, &meta, &proof_id);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
    assert!(!env.storage().persistent().has(&DataKey::Video(video)));
}

#[test]
fn uninit_register_anonymous_fails() {
    let (env, client, _, _) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let nullifier = bytes32(&env, 4);
    let root = bytes32(&env, 5);
    let proof = Bytes::from_array(&env, &[1, 2, 3, 4]);
    let res = client.try_register_anonymous(&video, &meta, &proof_id, &nullifier, &root, &proof);
    assert_err_code(res, RegistryError::VerifierNotSet as u32);
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
}

#[test]
fn uninit_register_anonymous_verified_fails() {
    let (env, client, _, _) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let public_inputs = Bytes::from_array(&env, &[0u8; 160]);
    let proof = Bytes::from_array(&env, &[1, 2, 3, 4]);
    let res = client.try_register_anonymous_verified(&video, &meta, &proof_id, &public_inputs, &proof);
    assert!(res.is_err(), "must fail on uninitialized contract");
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
}

#[test]
fn uninit_register_batch_verified_fails() {
    let (env, client, _, _) = uninit_setup();
    let batch_id = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let public_inputs = Bytes::new(&env);
    let proof = Bytes::from_array(&env, &[1, 2, 3]);
    let mut videos = soroban_sdk::Vec::new(&env);
    videos.push_back(bytes32(&env, 10));
    let res = client.try_register_batch_verified(&batch_id, &meta, &public_inputs, &proof, &videos);
    assert!(res.is_err(), "must fail on uninitialized contract");
    assert!(!env.storage().persistent().has(&DataKey::Proof(batch_id)));
}

#[test]
fn uninit_register_source_delegated_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let res = client.try_register_source_delegated(&caller1, &caller2, &video, &meta, &proof_id);
    assert_err_code(res, RegistryError::DelegationNotFound as u32);
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
}

#[test]
fn uninit_register_seal_delegated_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let video = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let res = client.try_register_seal_delegated(&caller1, &caller2, &video, &meta, &proof_id);
    assert_err_code(res, RegistryError::DelegationNotFound as u32);
    assert!(!env.storage().persistent().has(&DataKey::Proof(proof_id)));
}

#[test]
fn uninit_register_lineage_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let mut parents = soroban_sdk::Vec::new(&env);
    parents.push_back(bytes32(&env, 1));
    let manifest = bytes32(&env, 2);
    let op = Symbol::new(&env, "crop");
    let output = bytes32(&env, 3);
    let res = client.try_register_lineage(&caller1, &parents, &manifest, &op, &output, &1);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Lineage(output)));
}

// ---------------------------------------------------------------------------
// Pause, Delegation, Dispute, and Other Transitions
// ---------------------------------------------------------------------------

#[test]
fn uninit_pause_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let res = client.try_pause(&caller1, &PAUSE_DOMAIN_TIER1_REGISTRATION, &3600);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!client.is_paused(&PAUSE_DOMAIN_TIER1_REGISTRATION));
}

#[test]
fn uninit_grant_delegation_fails() {
    let (env, client, caller1, caller2) = uninit_setup();
    let res = client.try_grant_delegation(&caller1, &caller2, &DELEGATION_SCOPE_REGISTER_SOURCE, &3600);
    assert_err_code(res, RegistryError::NotInitialized as u32);
    assert!(!env.storage().persistent().has(&DataKey::Delegation(caller1, caller2)));
}

#[test]
fn uninit_revoke_delegation_fails() {
    let (_env, client, caller1, caller2) = uninit_setup();
    let res = client.try_revoke_delegation(&caller1, &caller1, &caller2);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_open_dispute_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let reporter_hash = bytes32(&env, 1);
    let dispute_id = bytes32(&env, 2);
    let proof_id = bytes32(&env, 3);
    let commitment = bytes32(&env, 4);
    let res = client.try_open_dispute(
        &caller1,
        &reporter_hash,
        &dispute_id,
        &proof_id,
        &DisputeReason::ContentError,
        &commitment,
    );
    assert_err_code(res, RegistryError::DisputeNotFound as u32);
    assert!(!env.storage().persistent().has(&DataKey::Dispute(dispute_id)));
}

#[test]
fn uninit_respond_dispute_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let dispute_id = bytes32(&env, 1);
    let commitment = bytes32(&env, 2);
    let res = client.try_respond_dispute(&caller1, &dispute_id, &commitment);
    assert_err_code(res, RegistryError::DisputeNotFound as u32);
}

#[test]
fn uninit_resolve_dispute_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let dispute_id = bytes32(&env, 1);
    let res = client.try_resolve_dispute(&caller1, &dispute_id);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_dismiss_dispute_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let dispute_id = bytes32(&env, 1);
    let res = client.try_dismiss_dispute(&caller1, &dispute_id);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_supersede_dispute_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let dispute_id = bytes32(&env, 1);
    let new_proof = bytes32(&env, 2);
    let res = client.try_supersede_dispute(&caller1, &dispute_id, &new_proof);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_bind_metadata_envelope_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let meta = bytes32(&env, 2);
    let res = client.try_bind_metadata_envelope(&caller1, &proof_id, &METADATA_ENVELOPE_V1, &meta);
    assert_err_code(res, RegistryError::MetadataEnvelopeNotFound as u32);
}

#[test]
fn uninit_anchor_timestamp_claim_fails() {
    let (env, client, caller1, _) = uninit_setup();
    let proof_id = bytes32(&env, 1);
    let digest = bytes32(&env, 2);
    let rfc = bytes32(&env, 3);
    let res = client.try_anchor_timestamp_claim(&caller1, &proof_id, &digest, &100, &rfc);
    assert_err_code(res, RegistryError::TimestampClaimNotFound as u32);
}

#[test]
fn uninit_check_non_revocation_fails() {
    let (env, client, _, _) = uninit_setup();
    let pi = Bytes::from_array(&env, &[0u8; 128]);
    let proof = Bytes::from_array(&env, &[1, 2, 3]);
    let res = client.try_check_non_revocation(&pi, &proof);
    assert_err_code(res, RegistryError::NotInitialized as u32);
}

#[test]
fn uninit_verify_selective_disclosure_fails() {
    let (env, client, _, _) = uninit_setup();
    let pi = Bytes::new(&env);
    let proof = Bytes::from_array(&env, &[1, 2, 3]);
    let res = client.try_verify_selective_disclosure(&pi, &proof);
    assert!(res.is_err(), "must fail on uninitialized contract");
}
