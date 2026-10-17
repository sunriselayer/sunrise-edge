//! Selected positive-only ignored probe. Public authority is reloaded from the
//! real original selector's retained archives; a manual epoch is never authority.
use super::positive_fee_split_wire::{self as wire, Request};
use super::{config::CustodyConfig, positive_fee_split::PositiveFeeSplitTrust};
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};
use sunrise_edge_client::LocalSigner;

const MAXIMUM: usize = 1024 * 1024;
const SELECTED_UID: u32 = 12001;

fn required(name: &str) -> String {
    std::env::var(name).expect("positive Split fixture requires explicit prerequisites")
}
fn read(path: &Path) -> Vec<u8> {
    super::fsperm::read_private_file(path, 0o600, 0o700, MAXIMUM).unwrap()
}
fn own_uid() -> u32 {
    let mut text: String = String::new();
    std::fs::File::open("/proc/self/status")
        .unwrap()
        .take(8192)
        .read_to_string(&mut text)
        .unwrap();
    text.lines()
        .find_map(|line: &str| {
            line.strip_prefix("Uid:")
                .and_then(|v: &str| v.split_whitespace().nth(1))
                .map(|v: &str| v.parse::<u32>().unwrap())
        })
        .unwrap()
}
fn trust(root: &Path) -> PositiveFeeSplitTrust {
    let bytes: Vec<u8> = read(&root.join("trust.args"));
    let text: String = String::from_utf8(bytes).unwrap();
    assert!(text.len() <= 16384 && text.ends_with('\n'));
    let args: Vec<OsString> = text.lines().map(OsString::from).collect();
    super::positive_fee_split_commands::fixture_trust(args, &root.join("config"))
}
fn request(root: &Path, case: &str, phase: &str) -> Request {
    wire::decode(&read(&root.join(format!("cases/{case}/{phase}.request")))).unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    super::fsperm::write_private_file(path, 0o700, 0o600, bytes, false).unwrap();
}

#[test]
#[ignore = "requires the selected bounded genuine-positive Docker UID/PTY owner"]
fn distinct_uid_positive_fee_split_probe() {
    let mode: String = required("POSITIVE_SPLIT_MODE");
    let root: PathBuf = required("POSITIVE_SPLIT_ROOT").into();
    assert!(root.is_absolute());
    let owner: PositiveFeeSplitTrust = trust(&root);
    match mode.as_str() {
        "provision" => {
            assert_eq!(
                own_uid(),
                SELECTED_UID,
                "only the selected custody UID provisions"
            );
            let config: CustodyConfig = CustodyConfig::load(&root.join("config")).unwrap();
            // Existing deterministic original-selector fixture material, not a
            // production secret or newly enrolled historical claimant.
            let signer: LocalSigner = LocalSigner::from_seed([0xa2; 32]);
            assert_eq!(signer.address(), config.publisher());
            for case in ["A", "B", "C", "D"] {
                for phase in ["leg", "claim"] {
                    owner.prepare(&request(&root, case, phase)).unwrap();
                }
            }
            let key: PathBuf = required("POSITIVE_SPLIT_KEY_DESTINATION").into();
            assert_eq!(key, root.join("keys/historical.seed"));
            write(
                &key,
                format!("{}\n", crate::hex::encode_hex(&[0xa2; 32])).as_bytes(),
            );
            println!("positive_split_provision=verified_disposable_historical_identity");
        }
        "operator-permissions" => {
            assert_eq!(own_uid(), 12002);
            let leg: Request = request(&root, "A", "leg");
            let id: sunrise_edge_client::RequestId =
                sunrise_edge_client::RequestId::new(leg.leg().terms.request_id).unwrap();
            for path in [
                PathBuf::from("/work/custody/keys/historical.seed"),
                PathBuf::from(format!(
                    "/work/custody/approvals/{id}.positive-fee-split.leg"
                )),
            ] {
                let error: std::io::Error = std::fs::File::open(path).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            }
            println!("positive_split_operator_private_access=refused");
        }
        "inspect" => {
            for case in ["A", "B", "C", "D"] {
                let directory: PathBuf = root.join(format!("cases/{case}"));
                for phase in ["leg", "claim"] {
                    let request: Request = request(&root, case, phase);
                    let prepared: super::positive_fee_split::Prepared<'_> =
                        owner.prepare(&request).unwrap();
                    write(&directory.join(format!("{phase}.frame")), prepared.frame());
                    write(
                        &directory.join(format!("{phase}.meaning")),
                        &prepared.content.meaning,
                    );
                }
            }
            println!("positive_split_public_authority_and_meaning=verified");
        }
        "verify" => {
            let case: String = required("POSITIVE_SPLIT_CASE");
            assert!(["A", "B", "C"].contains(&case.as_str()));
            let directory: PathBuf = root.join(format!("cases/{case}"));
            let leg_bytes: Vec<u8> = read(&directory.join("protected.leg"));
            let leg: sunrise_edge_client::local_execution::SignedLocalExecutionIntent =
                sunrise_edge_client::local_execution::decode_signed_local_execution(&leg_bytes)
                    .unwrap();
            assert_eq!(
                owner
                    .prepare(&request(&root, &case, "leg"))
                    .unwrap()
                    .finalize(leg.signature.to_vec())
                    .unwrap(),
                leg_bytes
            );
            assert_eq!(leg_bytes, read(&directory.join("signed-leg.bin")));
            let candidate_bytes: Vec<u8> = read(&directory.join("protected.candidate"));
            let candidate: node_core::ordered_economics::OrderedCandidate =
                node_core::ordered_economics::decode_ordered_candidate(&candidate_bytes).unwrap();
            let signed: node_core::fee_claims::codec::SignedFeeClaimIntent =
                node_core::fee_claims::codec::decode_signed_fee_claim_intent(&candidate.intent)
                    .unwrap();
            let outer: Vec<u8> = owner
                .prepare(&request(&root, &case, "claim"))
                .unwrap()
                .finalize(signed.signature.to_vec())
                .unwrap();
            assert_eq!(outer, candidate.intent);
            assert_eq!(outer, read(&directory.join("signed-outer.bin")));
            let id: sunrise_edge_client::RequestId =
                sunrise_edge_client::RequestId::new(signed.intent.request_id).unwrap();
            assert_eq!(owner.candidate(id, outer, 1_000).unwrap(), candidate_bytes);
            assert_eq!(candidate_bytes, read(&directory.join("candidate.bin")));
            println!("positive_split_protected_pair={case}:verified");
        }
        _ => panic!("unknown positive-only fixture mode"),
    }
}
