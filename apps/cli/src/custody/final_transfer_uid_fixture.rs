//! Disposable primitive probe: genuine original genesis and canonical
//! FinalTransfer leg, but a synthetic successor outer envelope. It cannot
//! establish historical committee, current row, or live-host authority.
use super::{
    fsperm, keyfile, positive_fee_split_approvals as approvals, positive_fee_split_wire as wire,
    revoke,
};
use crate::positive_fee_claim_split::tests::synthetic_final_transfer_material;
use crypto::SignatureSigner;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use sunrise_edge_client::{LocalSigner, RequestId};

const CUSTODY_UID: u32 = 12001;
const OPERATOR_UID: u32 = 12002;

fn uid() -> u32 {
    let text = std::fs::read_to_string("/proc/self/status").unwrap();
    text.lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|value| value.split_whitespace().nth(1))
        })
        .unwrap()
        .parse()
        .unwrap()
}

fn content(phase: wire::Phase) -> (approvals::Content, Vec<u8>) {
    let material = synthetic_final_transfer_material();
    let leg = wire::LegRequest {
        terms: material.terms.clone(),
        object: material.object.clone(),
    };
    let request = match phase {
        wire::Phase::FinalLeg => wire::Request::FinalLeg(leg),
        wire::Phase::FinalClaim => wire::Request::FinalClaim {
            leg,
            signed_leg: material.signed_leg.clone(),
            request: material.request_bytes,
            intent: material.intent_bytes,
        },
        _ => panic!("fixture is FinalTransfer only"),
    };
    let (frame, signed, meaning) = match phase {
        wire::Phase::FinalLeg => (material.leg_frame, material.signed_leg, material.leg_review),
        wire::Phase::FinalClaim => (
            material.outer_frame,
            material.signed_outer,
            material.outer_review,
        ),
        _ => unreachable!(),
    };
    (
        approvals::Content {
            phase,
            request_id: RequestId::new(material.terms.request_id).unwrap(),
            claimant: material.claimant.public_key,
            payload: wire::encode(&request).unwrap(),
            trust: format!(
                "verified_original_genesis={};synthetic_successor=true",
                material.root_digest
            )
            .into_bytes(),
            meaning: meaning.into_bytes(),
            frame,
        },
        signed,
    )
}

fn phase(mode: &str) -> wire::Phase {
    if mode.ends_with("leg") {
        wire::Phase::FinalLeg
    } else {
        wire::Phase::FinalClaim
    }
}

fn run(root: &Path, mode: &str) {
    let approvals_dir = root.join("approvals");
    let key = root.join("keys/historical.seed");
    let (content, expected) = content(phase(mode));
    if mode == "operator-permissions" {
        assert_eq!(uid(), OPERATOR_UID);
        for path in [&key, &approvals_dir] {
            assert_eq!(
                std::fs::File::open(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        for path in [
            Path::new("/work/open/key"),
            Path::new("/work/open/approval"),
        ] {
            assert_eq!(
                std::fs::File::open(path).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        println!("final_uid_mode={mode}:passed");
        return;
    }
    assert_eq!(uid(), CUSTODY_UID);
    match mode {
        "provision-leg" => {
            fsperm::write_private_file(
                &key,
                0o700,
                0o600,
                format!("{}\n", crate::hex::encode_hex(&[0xb1; 32])).as_bytes(),
                false,
            )
            .unwrap();
            assert_eq!(
                keyfile::load_signer(&key).unwrap().address(),
                content.claimant
            );
        }
        "approve-leg" | "approve-claim" => {
            assert!(std::io::stdin().is_terminal() && std::io::stdout().is_terminal());
            let challenge = format!("APPROVE-SYNTHETIC-FINAL:{}:{}", mode, content.request_id);
            println!(
                "{}\n{}",
                String::from_utf8(content.meaning.clone()).unwrap(),
                challenge
            );
            std::io::stdout().flush().unwrap();
            let line = super::approve::read_bounded_confirmation_line(256).unwrap();
            assert_eq!(line, challenge);
            approvals::write(&approvals_dir, &content, 2_000_000_000).unwrap();
        }
        "sign-leg" | "sign-claim" | "recover-leg" | "recover-claim" => {
            let signer: LocalSigner = keyfile::load_signer(&key).unwrap();
            assert_eq!(signer.address(), content.claimant);
            approvals::authorize(&approvals_dir, &content, 1_000_000_000).unwrap();
            let sig = signer.sign_framed(&content.frame).unwrap();
            if mode.ends_with("leg") {
                let signed =
                    sunrise_edge_client::local_execution::decode_signed_local_execution(&expected)
                        .unwrap();
                assert_eq!(sig, signed.signature.to_vec());
            } else {
                let signed =
                    node_core::fee_claims::codec::decode_signed_fee_claim_intent(&expected)
                        .unwrap();
                assert_eq!(sig, signed.signature.to_vec());
            }
            println!(
                "exact_signature={} phase={:?} signed_bytes={}",
                crate::hex::encode_hex(&sig),
                content.phase,
                expected.len()
            );
        }
        "recover-key" => {
            let bytes = fsperm::read_private_file(&key, 0o600, 0o700, 66).unwrap();
            std::fs::rename(&key, root.join("keys/old-historical.seed")).unwrap();
            fsperm::write_private_file(&key, 0o700, 0o600, &bytes, false).unwrap();
            assert_eq!(
                keyfile::load_signer(&key).unwrap().address(),
                content.claimant
            );
        }
        "refuse-changed-leg" | "refuse-changed-claim" => {
            let mut changed = content;
            changed.frame.push(0);
            assert!(approvals::authorize(&approvals_dir, &changed, 1_000_000_000).is_err());
        }
        "revoke-leg" => revoke::revoke(&approvals_dir, &content.request_id).unwrap(),
        "refuse-revoked-leg" | "refuse-revoked-claim" => {
            assert!(approvals::authorize(&approvals_dir, &content, 1_000_000_000).is_err());
        }
        _ => panic!("unsupported fixture mode"),
    }
    println!("final_uid_mode={mode}:passed");
}

#[test]
#[ignore = "requires disposable separate-UID Docker and real PTY"]
fn final_transfer_uid_pty_primitive_probe() {
    let root: PathBuf = std::env::var("FINAL_TRANSFER_UID_ROOT").unwrap().into();
    assert!(root.is_absolute());
    let mode = std::env::var("FINAL_TRANSFER_UID_MODE").unwrap();
    run(&root, &mode);
}
