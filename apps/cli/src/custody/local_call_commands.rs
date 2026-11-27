//! Offline approval and protected signing for a saved canonical local/general
//! Call. The policy comes from custody's own config and explicit local choice;
//! the unsigned file cannot select it. No network or development seed loader.
use super::{approvals, config::CustodyConfig, error::CustodyError, fsperm, keyfile, revoke};
use crate::{
    args::{ParsedArgs, parse_flags, scalar, switch},
    error::CliError,
    parse::parse_u64,
};
use std::{
    ffi::OsString,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use sunrise_edge_client::{
    ExternalSigner, LocalExecutionReview, PublicationContext, RequestId,
    local_execution::{
        LocalExecutionIntent, LocalExecutionPolicy, MAX_LOCAL_EXECUTION_INTENT_BYTES,
        SignedLocalExecutionIntent, authenticate_local_execution, decode_local_execution_intent,
        encode_signed_local_execution,
    },
};

fn failure(error: impl std::error::Error + Send + Sync + 'static) -> CliError {
    CliError::LocalExecution(Box::new(error))
}

fn invalid(message: &'static str) -> CliError {
    failure(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// The command, never the saved file, selects the mode. Each mode has its own
/// approval directory, confirmation text and output markers.
#[derive(Clone, Copy)]
enum Kind {
    Call,
    Instantiate,
}

impl Kind {
    fn dir(self) -> &'static str {
        match self {
            Self::Call => "local-call",
            Self::Instantiate => "local-instantiate",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Call => "APPROVE-LOCAL-CALL",
            Self::Instantiate => "APPROVE-LOCAL-INSTANTIATE",
        }
    }
    fn approved(self) -> &'static str {
        match self {
            Self::Call => "approved_local_call",
            Self::Instantiate => "approved_local_instantiate",
        }
    }
    fn signed(self) -> &'static str {
        match self {
            Self::Call => "signed_local_call",
            Self::Instantiate => "signed_local_instantiate",
        }
    }
}

fn specs(signing: bool) -> Vec<crate::args::FlagSpec> {
    let mut specs = vec![
        switch("--general-calls"),
        scalar("--config"),
        scalar("--unsigned-file"),
        scalar("--approvals-dir"),
    ];
    if signing {
        specs.extend([scalar("--key-file"), scalar("--signed-out")]);
    } else {
        specs.push(scalar("--expires-in-seconds"));
    }
    specs
}

fn policy(
    config: &CustodyConfig,
    general: bool,
) -> Result<(sunrise_edge_client::HashSuiteResolver, LocalExecutionPolicy), CliError> {
    let expected = config.expected_context()?;
    let resolver = sunrise_edge_client::local_publication_resolver(&expected)?;
    let context = PublicationContext::new(
        expected.chain_id().clone(),
        expected.protocol_version(),
        expected.epoch(),
    )
    .map_err(failure)?;
    Ok((
        resolver,
        if general {
            LocalExecutionPolicy::general(context)
        } else {
            LocalExecutionPolicy::new(context)
        },
    ))
}

fn read_review(
    kind: Kind,
    parsed: &ParsedArgs,
    config: &CustodyConfig,
) -> Result<
    (
        LocalExecutionReview,
        LocalExecutionIntent,
        LocalExecutionPolicy,
        sunrise_edge_client::HashSuiteResolver,
    ),
    CliError,
> {
    let (resolver, policy) = policy(config, parsed.is_present("--general-calls"))?;
    let bytes = fsperm::read_private_file(
        Path::new(parsed.require("--unsigned-file")?),
        0o600,
        0o700,
        MAX_LOCAL_EXECUTION_INTENT_BYTES,
    )?;
    let review = match kind {
        Kind::Call => LocalExecutionReview::from_saved_call(&bytes, &resolver, &policy),
        Kind::Instantiate => {
            LocalExecutionReview::from_saved_instantiate(&bytes, &resolver, &policy)
        }
    }
    .map_err(failure)?;
    let intent = decode_local_execution_intent(review.intent_bytes()).map_err(failure)?;
    if intent.call.sender != *config.publisher().as_bytes() {
        return Err(invalid(match kind {
            Kind::Call => "saved local Call sender differs from custody publisher",
            Kind::Instantiate => "saved local Instantiate sender differs from custody publisher",
        }));
    }
    Ok((review, intent, policy, resolver))
}

fn approval_dir(kind: Kind, parsed: &ParsedArgs) -> Result<PathBuf, CliError> {
    let parent = Path::new(parsed.require("--approvals-dir")?);
    fsperm::require_private_dir(parent, 0o700)?;
    let dir = parent.join(kind.dir());
    fsperm::require_private_dir(&dir, 0o700)?;
    Ok(dir)
}

fn now() -> Result<u64, CustodyError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::ClockBeforeEpoch)?
        .as_secs())
}

fn require_custody_uid(config: &CustodyConfig) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(CustodyError::Runtime)?;
    let uid = runtime
        .block_on(super::selfuid::own_uid())
        .map_err(CustodyError::Runtime)?;
    if uid == config.operator_uid() {
        return Err(CustodyError::OperatorUidMatchesCustodyUid { uid }.into());
    }
    Ok(())
}

fn confirmation(
    kind: Kind,
    config: &CustodyConfig,
    id: &RequestId,
    nonce: u64,
    not_after: u64,
) -> String {
    format!(
        "{} sender={} request_id={} nonce={} not_after={not_after}",
        kind.label(),
        config.publisher(),
        id,
        nonce,
    )
}

fn save_approval(
    dir: &Path,
    config: &CustodyConfig,
    review: &LocalExecutionReview,
    id: &RequestId,
    not_after: u64,
    expected_confirmation: &str,
    typed: &str,
) -> Result<(), CliError> {
    if typed != expected_confirmation {
        return Err(CustodyError::ApprovalConfirmationMismatch.into());
    }
    approvals::write_approval(
        dir,
        id,
        &approvals::ApprovalRecord {
            publisher: config.publisher(),
            not_after_unix_seconds: not_after,
            frame: review.signable_frame().to_vec(),
        },
    )?;
    Ok(())
}

pub(super) fn approve<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    approve_kind(Kind::Call, args)
}

pub(super) fn approve_instantiate<I: IntoIterator<Item = OsString>>(
    args: I,
) -> Result<(), CliError> {
    approve_kind(Kind::Instantiate, args)
}

pub(super) fn sign<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    sign_kind(Kind::Call, args)
}

pub(super) fn sign_instantiate<I: IntoIterator<Item = OsString>>(args: I) -> Result<(), CliError> {
    sign_kind(Kind::Instantiate, args)
}

fn approve_kind<I: IntoIterator<Item = OsString>>(kind: Kind, args: I) -> Result<(), CliError> {
    let parsed = parse_flags(args, &specs(false))?;
    let config = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    require_custody_uid(&config)?;
    let (review, intent, _, _) = read_review(kind, &parsed, &config)?;
    let dir = approval_dir(kind, &parsed)?;
    let id = RequestId::new(intent.call.request_id)?;
    if revoke::is_revoked(&dir, &id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CustodyError::ApproveRequiresTerminal.into());
    }
    let expires = parse_u64(
        "--expires-in-seconds",
        parsed.require("--expires-in-seconds")?,
    )?;
    let not_after = now()?
        .checked_add(expires)
        .ok_or(CustodyError::ExpiryOverflow)?;
    print!("{}", review.display());
    let confirmation = confirmation(kind, &config, &id, intent.call.nonce, not_after);
    println!("Type exactly to approve:\n{confirmation}");
    let typed = super::approve::read_bounded_confirmation_line(1024)?;
    save_approval(
        &dir,
        &config,
        &review,
        &id,
        not_after,
        &confirmation,
        &typed,
    )?;
    println!(
        "{}=true\nrequest_id={id}\nnot_after={not_after}",
        kind.approved()
    );
    Ok(())
}

fn sign_kind<I: IntoIterator<Item = OsString>>(kind: Kind, args: I) -> Result<(), CliError> {
    let parsed = parse_flags(args, &specs(true))?;
    let config = CustodyConfig::load(Path::new(parsed.require("--config")?))?;
    require_custody_uid(&config)?;
    let (review, intent, policy, resolver) = read_review(kind, &parsed, &config)?;
    let dir = approval_dir(kind, &parsed)?;
    let id = RequestId::new(intent.call.request_id)?;
    if revoke::is_revoked(&dir, &id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let record = approvals::read_approval(&dir, &id)?.ok_or(CustodyError::ApprovalMissing)?;
    if record.publisher != config.publisher()
        || record.frame != review.signable_frame()
        || approvals::is_expired(&record, now()?)
    {
        return Err(CustodyError::ApprovalMalformed.into());
    }
    let signer = keyfile::load_signer(Path::new(parsed.require("--key-file")?))?;
    if signer.address() != config.publisher() {
        return Err(CustodyError::KeyFileAddressMismatch.into());
    }
    if revoke::is_revoked(&dir, &id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    let signature: [u8; 64] = signer
        .sign_frame(review.signable_frame())
        .map_err(failure)?
        .try_into()
        .map_err(|_| {
            invalid(match kind {
                Kind::Call => "local Call signature length",
                Kind::Instantiate => "local Instantiate signature length",
            })
        })?;
    let signed = SignedLocalExecutionIntent { intent, signature };
    let bytes = encode_signed_local_execution(&signed).map_err(failure)?;
    authenticate_local_execution(&resolver, &policy, &bytes).map_err(failure)?;
    if revoke::is_revoked(&dir, &id)? {
        return Err(CustodyError::ApprovalRevoked.into());
    }
    super::write_review_preimage(Path::new(parsed.require("--signed-out")?), &bytes)?;
    println!(
        "{}=true\nrequest_id={id}\nsigned_bytes={}",
        kind.signed(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::fsperm::test_support::TempDir;
    use sunrise_edge_client::{
        AccessManifest, AtomicityDomainId, ChainId, Digest32, Epoch, ExpectedProtocolContext,
        HashAlgorithmId, HashSuiteId, LocalSigner, PackageOrigin, ProtocolVersion,
        UnverifiedDependencyRef,
        call::{CallIntent, InstanceTarget},
        local_execution::{
            LocalExecutionMode, decode_signed_local_execution, encode_local_execution_intent,
        },
    };

    fn file(path: &Path, bytes: &[u8]) {
        fsperm::write_private_file(path, 0o700, 0o600, bytes, false).unwrap();
    }

    #[test]
    fn approved_saved_call_signs_exact_frame_and_refuses_changed_or_revoked_content() {
        saved_flow(Kind::Call);
    }

    #[test]
    fn approved_saved_instantiate_signs_exact_frame_with_separate_approval_dir() {
        saved_flow(Kind::Instantiate);
    }

    fn saved_flow(kind: Kind) {
        let sign = |args: Vec<OsString>| sign_kind(kind, args);
        let other = match kind {
            Kind::Call => Kind::Instantiate,
            Kind::Instantiate => Kind::Call,
        };
        let root = TempDir::new(0o700);
        let signer = LocalSigner::from_seed([7; 32]);
        let expected = ExpectedProtocolContext::new(
            ChainId::new("saved-local-call-test").unwrap(),
            ProtocolVersion::new(1),
            Epoch::new(0),
            HashSuiteId::new(1),
            2,
            1,
            2,
            AtomicityDomainId::new([1; 32]).unwrap(),
        )
        .unwrap();
        let resolver = sunrise_edge_client::local_publication_resolver(&expected).unwrap();
        let context = PublicationContext::new(
            expected.chain_id().clone(),
            expected.protocol_version(),
            expected.epoch(),
        )
        .unwrap();
        let config = root.0.join("config");
        use std::os::unix::fs::MetadataExt;
        let operator_uid = std::fs::metadata(&root.0)
            .unwrap()
            .uid()
            .checked_add(1)
            .unwrap();
        file(&config, format!(
            "chain_id=saved-local-call-test\nprotocol_version=1\nepoch=0\nhash_suite_id=1\ndomain={}\npublisher_public_key={}\noperator_uid={operator_uid}\n",
            expected.domain(), signer.address(),
        ).as_bytes());
        let key = root.0.join("key");
        file(
            &key,
            format!("{}\n", crate::hex::encode_hex(&[7; 32])).as_bytes(),
        );
        let approvals = root.0.join("approvals");
        std::fs::create_dir(&approvals).unwrap();
        std::fs::create_dir(approvals.join(kind.dir())).unwrap();
        std::fs::create_dir(approvals.join(other.dir())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                &approvals,
                &approvals.join(kind.dir()),
                &approvals.join(other.dir()),
            ] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let origin = PackageOrigin::unverified(
            expected.chain_id().clone(),
            *signer.address().as_bytes(),
            [2; 32],
        )
        .unwrap();
        let code = UnverifiedDependencyRef::new(
            origin,
            1,
            context.clone(),
            Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
        )
        .unwrap();
        let policy = LocalExecutionPolicy::new(context.clone());
        let intent = LocalExecutionIntent {
            mode: match kind {
                Kind::Call => LocalExecutionMode::Call,
                Kind::Instantiate => LocalExecutionMode::Instantiate,
            },
            policy_digest: policy.digest(&resolver).unwrap(),
            call: CallIntent {
                context,
                request_id: [3; 32],
                sender: *signer.address().as_bytes(),
                nonce: 9,
                code,
                instance: InstanceTarget {
                    creator: *signer.address().as_bytes(),
                    seed: [4; 32],
                    revision: 1,
                    record_digest: Digest32::new(HashAlgorithmId::Sha2_256, [6; 32]),
                },
                entrypoint: "run".to_owned(),
                type_arguments: vec![],
                access: AccessManifest::new(),
                arguments: vec![1, 2, 3],
                gas_limit: 1000,
            },
            authorizations: vec![],
        };
        let unsigned = root.0.join("unsigned");
        file(&unsigned, &encode_local_execution_intent(&intent).unwrap());
        let saved = std::fs::read(&unsigned).unwrap();
        let review = match kind {
            Kind::Call => LocalExecutionReview::from_saved_call(&saved, &resolver, &policy),
            Kind::Instantiate => {
                LocalExecutionReview::from_saved_instantiate(&saved, &resolver, &policy)
            }
        }
        .unwrap();
        let loaded_config = CustodyConfig::load(&config).unwrap();
        let id = RequestId::new([3; 32]).unwrap();
        let approval_path = approvals.join(kind.dir());
        let flags = |out: &Path| {
            vec![
                OsString::from("--config"),
                config.clone().into_os_string(),
                OsString::from("--unsigned-file"),
                unsigned.clone().into_os_string(),
                OsString::from("--approvals-dir"),
                approvals.clone().into_os_string(),
                OsString::from("--key-file"),
                key.clone().into_os_string(),
                OsString::from("--signed-out"),
                out.as_os_str().to_os_string(),
            ]
        };
        assert!(
            save_approval(
                &approval_path,
                &loaded_config,
                &review,
                &id,
                u64::MAX,
                &confirmation(kind, &loaded_config, &id, 9, u64::MAX),
                "wrong",
            )
            .is_err()
        );
        assert!(
            approvals::read_approval(&approval_path, &id)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            sign(flags(&root.0.join("missing-out"))),
            Err(CliError::Custody(inner)) if matches!(*inner, CustodyError::ApprovalMissing)
        ));
        save_approval(
            &approval_path,
            &loaded_config,
            &review,
            &id,
            u64::MAX,
            &confirmation(kind, &loaded_config, &id, 9, u64::MAX),
            &confirmation(kind, &loaded_config, &id, 9, u64::MAX),
        )
        .unwrap();
        let signed = root.0.join("signed");
        sign(flags(&signed)).unwrap();
        let signed_intent =
            decode_signed_local_execution(&std::fs::read(&signed).unwrap()).unwrap();
        assert_eq!(signed_intent.intent, intent);
        authenticate_local_execution(&resolver, &policy, &std::fs::read(&signed).unwrap()).unwrap();
        let approved = approvals::read_approval(&approval_path, &id)
            .unwrap()
            .unwrap();
        let mut stale = approved.clone();
        stale.not_after_unix_seconds = 0;
        approvals::write_approval(&approval_path, &id, &stale).unwrap();
        assert!(sign(flags(&root.0.join("expired-out"))).is_err());
        let mut wrong_publisher = approved.clone();
        wrong_publisher.publisher = sunrise_edge_client::Address::new([8; 32]);
        approvals::write_approval(&approval_path, &id, &wrong_publisher).unwrap();
        assert!(sign(flags(&root.0.join("publisher-out"))).is_err());
        approvals::write_approval(&approval_path, &id, &approved).unwrap();
        let other_key = root.0.join("other-key");
        file(
            &other_key,
            format!("{}\n", crate::hex::encode_hex(&[8; 32])).as_bytes(),
        );
        let mut wrong_key_flags = flags(&root.0.join("wrong-key-out"));
        wrong_key_flags[7] = other_key.into_os_string();
        assert!(sign(wrong_key_flags).is_err());
        let mut wrong_policy_flags = flags(&root.0.join("wrong-policy-out"));
        wrong_policy_flags.push(OsString::from("--general-calls"));
        assert!(sign(wrong_policy_flags).is_err());
        let mut changed = intent.clone();
        changed.call.nonce += 1;
        std::fs::write(&unsigned, encode_local_execution_intent(&changed).unwrap()).unwrap();
        assert!(sign(flags(&root.0.join("changed-out"))).is_err());
        changed.call.sender = [8; 32];
        match kind {
            Kind::Call => {
                std::fs::write(&unsigned, encode_local_execution_intent(&changed).unwrap())
                    .unwrap();
                assert!(sign(flags(&root.0.join("sender-out"))).is_err());
            }
            Kind::Instantiate => assert!(encode_local_execution_intent(&changed).is_err()),
        }
        std::fs::write(&unsigned, encode_local_execution_intent(&intent).unwrap()).unwrap();
        // The other mode refuses this file, and neither mode's approval or
        // revocation directory is shared with the other.
        assert!(sign_kind(other, flags(&root.0.join("cross-mode-out"))).is_err());
        assert!(
            approvals::read_approval(&approvals.join(other.dir()), &id)
                .unwrap()
                .is_none()
        );
        assert_ne!(
            confirmation(kind, &loaded_config, &id, 9, 1),
            confirmation(other, &loaded_config, &id, 9, 1)
        );
        revoke::revoke(&approvals.join(kind.dir()), &id).unwrap();
        assert!(sign(flags(&root.0.join("revoked-out"))).is_err());
        assert!(!revoke::is_revoked(&approvals.join(other.dir()), &id).unwrap());
    }
}
