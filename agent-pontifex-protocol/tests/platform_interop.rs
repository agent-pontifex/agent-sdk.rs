use agent_pontifex_protocol::{
    validate_fencing_token, FIDUCIA_AUTHORITY_EXTENSION_ID, FIDUCIA_FILE_LEASES_EXTENSION_ID,
    MAX_SAFE_FENCING_TOKEN,
};
use serde_json::Value;

const INTEROP: &str = include_str!("../../conformance/platform-interop.json");
const GITIGNORE: &str = include_str!("../../.gitignore");
const ZED_MANIFEST: &str = include_str!("../../.zpkg.toml");

fn contract() -> Value {
    serde_json::from_str(INTEROP).expect("platform interop fixture must be valid JSON")
}

#[test]
fn pins_protocol_and_distributed_authority_boundaries() {
    let contract = contract();
    assert_eq!(
        contract["protocol_authority"],
        "agent-pontifex/agent-sdk.rs"
    );
    assert_eq!(contract["fiducia"]["atomic_path_union"], true);
    assert_eq!(
        contract["fiducia"]["fencing_token_maximum"],
        MAX_SAFE_FENCING_TOKEN
    );
    assert!(validate_fencing_token(1).is_ok());
    assert!(validate_fencing_token(MAX_SAFE_FENCING_TOKEN).is_ok());
    assert!(validate_fencing_token(MAX_SAFE_FENCING_TOKEN + 1).is_err());
    assert_eq!(FIDUCIA_FILE_LEASES_EXTENSION_ID, "fiducia.file-leases");
    assert_eq!(FIDUCIA_AUTHORITY_EXTENSION_ID, "fiducia.authority");
}

#[test]
fn separates_human_identity_from_workload_and_write_authority() {
    let contract = contract();
    assert_eq!(
        contract["shared_auth"]["role"],
        "human operator identity authority"
    );
    assert_eq!(
        contract["shared_auth"]["introspection_service_credential_is_separate"],
        true
    );
    assert_eq!(contract["shared_auth"]["forward_raw_caller_bearer"], false);
    let excluded = contract["shared_auth"]["does_not_authorize"]
        .as_array()
        .expect("does_not_authorize must be an array");
    assert!(excluded
        .iter()
        .any(|value| value == "repository mutation fencing"));
}

#[test]
fn locks_package_and_secret_conventions() {
    let contract = contract();
    assert_eq!(contract["zed"]["manifest"], ".zpkg.toml");
    assert_eq!(
        contract["zed"]["package_identity"],
        "agent-pontifex/agent-sdk"
    );
    assert_eq!(
        contract["secrets"]["tracked_ciphertext"],
        "env/enc/*.env.enc"
    );
    assert_eq!(contract["secrets"]["decrypted_plaintext"], "env/dec/*.env");
    assert_eq!(contract["secrets"]["plaintext_must_be_untracked"], true);
    assert!(GITIGNORE.lines().any(|line| line == "env/dec/"));
    assert!(GITIGNORE.lines().any(|line| line == "env/enc/*"));
    assert!(GITIGNORE.lines().any(|line| line == "!env/enc/*.env.enc"));
    assert!(ZED_MANIFEST.contains("org = \"agent-pontifex\""));
    assert!(ZED_MANIFEST.contains("name = \"agent-sdk\""));
    assert!(ZED_MANIFEST.contains("\"env/**\""));
}
