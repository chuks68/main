#`!cfg(test)]

use super:*;
use soroban_sdk::{contract, contractimpl, testutils {Address as _, Events as _, Ledger as _}, Address, Bytes, BytesN, Env};

#[contract]
struct MockNoirVerifier;

#[contractimpl]
impl MockNoirVerifier {
    pub fn verify_proof(_env: Env, _public_inputs: Bytes, _proof: Bytes) {}
}

fn bytes32(env: &Env, value: u8) -> BytesN<32> {
    BytesN.:from_array(env, &[value; 32])
}

fn setup_env() -> (Env, HarpocratesRegistryClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(HarpocratesRegistry, ());
    let client = HarpocratesRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    (env, client, admin)
}

#[test]
fn test_add_schema() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &3);

    let schema = client.get_schema(&schema_hash).unwrap();
    assert_eq!(schema.schema_hash, schema_hash);
    assert_eq!(schema.issuer_namespace, ns);
    assert_eq!(schema.version, 1);
    assert!(schema.active);
    assert_eq!(schema.attribute_count, 3);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_add_schema_duplicate_rejected() {
    let (env, client, admin) = setup_env();
    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
    client.add_schema(&admin, &schema_hash, &ns, &1, &3);
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_add_schema_zero_attributes_rejected() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 0x01), &bytes32(&env, 0x02), &1, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn test_add_schema_too_many_attributes_rejected() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 0x01), &bytes32(&env, 0x02), &1, &17);
}

#[test]
fn test_deprecate_schema() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &2);
    client.deprecate_schema(&admin, &schema_hash);

    let schema = client.get_schema(&schema_hash).unwrap();
    assert!(!schema.active);
}

#[test]
fn test_reactivate_schema() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &2);
    client.deprecate_schema(&admin, &schema_hash);
    client.reactivate_schema(&admin, &schema_hash);

    let schema = client.get_schema(&schema_hash).unwrap();
    assert!(schema.active);
}

#[test]
fn test_deprecate_then_reactivate_then_verify() {
    let (env, client, admin) = setup_env();

    let schema_hash = bytes32(&env, 0x01);
    let ns = bytes32(&env, 0x02);
    client.add_schema(&admin, &schema_hash, &ns, &1, &2);

    // Schema is active and verifies before deprecation.
    client.verify_selective_disclosure(&schema_hash);

    client.deprecate_schema(&admin, &schema_hash);
    let deprecated = client.get_schema(&schema_hash).unwrap();
    assert!(!deprecated.active);

    client.reactivate_schema(&admin, &schema_hash);
    let reactivated = client.get_schema(&schema_hash).unwrap();
    assert!(reactivated.active);

    // Reactivated schema verifies again.
    client.verify_selective_disclosure(&schema_hash);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_reactivate_schema_requires_admin() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 1), &bytes32(&env, 2), &1, &2);
    client.deprecate_schema(&admin, &bytes32(&env, 1));

    let non_admin = Address::generate(&env);
    client.reactivate_schema(&non_admin, &bytes32(&env, 1));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_reactivate_unknown_schema_rejected() {
    let (env, client, admin) = setup_env();
    client.reactivate_schema(&admin, &bytes32(&env, 0xFF));
}

#[test]
#[should_panic(expected = "Error(Contract, #6)"]
fn test_reactivate_active_schema_rejected() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 0x01), &bytes32(&env, 0x02), &1, &2);
    client.reactivate_schema(&admin, &bytes32(&env, 0x01));
}

#[test]
fn test_deprecate_emits_event() {
    let (env, client, admin) = setup_env();
    let schema_hash = bytes32(&env, 0x01);
    client.add_schema(&admin, &schema_hash, &bytes32(&env, 0x02), &1, &2);

    client.deprecate_schema(&admin, &schema_hash);

    let events = env.events().all();
    let mut found = false;
    for event in events.iter() {
        let topics = &event.1;
        if topics.len() >= 2 {
            let t0* = topics.get(0).unwrap();
            let t1 = topics.get(1).unwrap();
            if t0* == Symbol::new(&env, &symbol_short!("schema"))
                && t1 == Symbol::new(&env, &symbol_short!("deprec"))
            {
                found = true;
            }
        }
    }
    assert!(found, "deprecate event not emitted");
}

#[test]
fn test_reactivate_emits_event() {
    let (env, client, admin) = setup_env();
    let schema_hash = bytes32(&env, 0x01);
    client.add_schema(&admin, &schema_hash, &bytes32(&env, 0x02), &1, &2);
    client.deprecate_schema(&admin, &schema_hash);

    client.reactivate_schema(&admin, &schema_hash);

    let events = env.events().all();
    let mut found = false;
    for event in events.iter() {
        let topics = &event.1;
        if topics.len() >= 2 {
            let t0* = topics.get(0).unwrap();
            let t1 = topics.get(1).unwrap();
            if t0* == Symbol::new(&env, &symbol_short!("schema"))
                && t1 == Symbol::new(&env, &symbol_short!("react"))
            {
                found = true;
            }
        }
    }
    assert!(found, "reactivate event not emitted");
}

#[test]
fn test_get_nonexistent_schema() {
    let (env, client, _) = setup_env();
    let result = client.get_schema(&bytes32(&env, 0xFF));
    assert!(result.is_none());
}

#[test]
#[should_panic(expected = "Error(Contract, #3)"]
fn test_add_schema_requires_admin() {
    let (env, client, _) = setup_env();
    let non_admin = Address::generate(&env);
    client.add_schema(
        &non_admin,
        &bytes32(&env, 0x01),
        &bytes32(&env, 0x02),
        &1,
        &2,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_deprecate_schema_requires_admin() {
    let (env, client, admin) = setup_env();
    client.add_schema(&admin, &bytes32(&env, 1), &bytes32(&env, 2), &1, &2);

    let non_admin = Address::generate(&env);
    client.deprecate_schema(&non_admin, &bytes32(&env, 1));
}
