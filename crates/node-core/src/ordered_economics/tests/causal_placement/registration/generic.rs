//! A genuinely signed generic genesis resource with an extra nominal event.
//! The public contract is only a WAT/ABI builder, never a native privilege.
//! Paid `split` creates both amounts. Custody transfer of 20_000 succeeds in
//! the real VM but violates registration's closed no-events effect contract;
//! 10_000 remains a valid subsequent registration from another exact source.
use super::*;
use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationRequest, PublicationSubmission,
    UnverifiedDependencyRef, artifact_commitment, publication_submission_signing_frame,
};

pub(super) fn event_on_collateral(manifest: &mut GenesisManifest) {
    let previous: &CodeArtifact = manifest.publication.request().artifact();
    let mut wat: String = public_standard_asset::contract_wat().unwrap();
    let import: &str =
        "(import \"sunrise\" \"transfer_object\" (func $move_owner (param i32 i32) (result i32)))";
    assert_eq!(wat.matches(import).count(), 1);
    wat = wat.replacen(import, &format!("{import}\n(import \"sunrise\" \"emit_event\" (func $emit (param i32 i32 i32 i32) (result i32)))"), 1);
    let old: &str = "(func (export \"transfer\") (local $list i32)\n (local.set $list (call $arguments (i32.const 1) (i32.const 1)))\n (call $zero (call $move_owner (i32.const 0)\n   (call $bytes (call $item (local.get $list) (i32.const 0)) (i32.const 32)))))";
    assert_eq!(wat.matches(old).count(), 1);
    let new: &str = "(func (export \"transfer\") (local $list i32)\n (local.set $list (call $arguments (i32.const 1) (i32.const 1)))\n (call $zero (call $move_owner (i32.const 0)\n   (call $bytes (call $item (local.get $list) (i32.const 0)) (i32.const 32))))\n (if (i64.eq (call $amount_of (i32.const 0)) (i64.const 20000)) (then\n   (call $zero (call $emit (i32.const 16384)\n     (call $object_type (i32.const 0) (i32.const 16384) (i32.const 1024))\n     (i32.const 12288) (i32.const 32))))))";
    wat = wat.replacen(old, new, 1);
    let artifact: CodeArtifact = CodeArtifact::new(ArtifactParts {
        context: previous.context().clone(),
        origin: previous.origin().clone(),
        revision: previous.revision(),
        wasm_profile: previous.wasm_profile(),
        semantics: *previous.semantics(),
        wasm: wat::parse_str(&wat).unwrap(),
        unverified_abi: previous.unverified_abi().to_vec(),
        exports: previous.exports().to_vec(),
        unverified_dependencies: previous.unverified_dependencies().to_vec(),
    })
    .unwrap();
    let context: PublicationContext = manifest.context().clone();
    let resolver: HashSuiteResolver = fixture::resolver();
    let digest: Digest32 = artifact_commitment(&resolver, &context, &artifact).unwrap();
    let request: [u8; 32] = *manifest.publication.request_id();
    let nonce: u64 = manifest.publication.request().nonce();
    let frame: Vec<u8> =
        publication_submission_signing_frame(&resolver, &context, &artifact, nonce, request)
            .unwrap();
    let code: UnverifiedDependencyRef = UnverifiedDependencyRef::new(
        artifact.origin().clone(),
        artifact.revision(),
        context.clone(),
        digest,
    )
    .unwrap();
    manifest.publication = PublicationSubmission::new(
        request,
        PublicationRequest::new(artifact, nonce, digest, fixture::key().sign(&frame).into()),
    )
    .unwrap();
    let initialization = &mut manifest.initialization;
    initialization.intent.call.code = code.clone();
    let instance: InstanceRecord = InstanceRecord {
        context: context.clone(),
        creator: initialization.intent.call.instance.creator,
        seed: initialization.intent.call.instance.seed,
        code: code.clone(),
        revision: 1,
        initializer: initialization.intent.call.entrypoint.clone(),
    };
    let target: InstanceTarget = instance_target(&resolver, &instance).unwrap();
    initialization.intent.call.instance = target.clone();
    initialization.signature = fixture::key()
        .sign(&local_execution_signing_frame(&context, &initialization.intent).unwrap())
        .into();
    manifest.fee_policy.code = code.clone();
    manifest.fee_policy.instance = target.clone();
    for resource in &mut manifest.economics_policy.resources {
        resource.code = code.clone();
        resource.instance = target.clone();
    }
    for entry in &mut manifest.objects {
        entry.authority.code = code.clone();
        entry.authority.instance = target.clone();
    }
    // The caller signs the complete resulting manifest and installs it through
    // the unmodified owning verifier before any producer or registration.
}
