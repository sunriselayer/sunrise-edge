//! DR-0197 descriptive bounded summary renderer. Ordinary diagnostics only:
//! no signed/canonical protocol artifact, no Standard Asset body decoder, no
//! clock/domain/checkpoint/private byte ever appears in the output.

use std::error::Error;
use std::fmt::Write as _;

use abi::package_types::encode_package_origin;
use execution::call::encode_instance_target;
use execution::local_execution::encode_object_authority;
use execution::paid_execution::encode_paid_fee_policy;
use execution::publication::{encode_dependency_ref, encode_publication_context};
use node_core::economics::encode_fastpath_economics_policy;
use node_core::fast_path::records::encode_fastpath_validator_set_record;
use node_core::genesis::{GenesisManifest, GenesisObjectEntry, VerifiedGenesisRoot};
use node_core::logical_generation::CommitmentProfile;
use objects::{Owner, ProtocolCustodyPurpose};
use protocol_types::SignatureSchemeId;

/// Bound on the complete diagnostic text, enforced before any stdout write.
const MAX_DIAGNOSTIC_BYTES: usize = 4 * node_core::MAX_GENESIS_MANIFEST_BYTES + 32_768;

/// Private bounded accumulator. Excess is remembered without appending more
/// text; `finish` refuses the whole summary before the caller writes stdout.
struct Diagnostic {
    text: String,
    limit: usize,
    exceeded: bool,
}

impl Diagnostic {
    fn new() -> Self {
        Self {
            text: String::new(),
            limit: MAX_DIAGNOSTIC_BYTES,
            exceeded: false,
        }
    }

    fn append(&mut self, value: &str) {
        if self.exceeded {
            return;
        }
        if self
            .text
            .len()
            .checked_add(value.len())
            .is_none_or(|length: usize| length > self.limit)
        {
            self.exceeded = true;
            return;
        }
        self.text.push_str(value);
    }

    /// Appends one `key=value` line; `value` is pushed verbatim and must
    /// already be escaped/hex text, never a raw attacker-controlled string.
    fn kv(&mut self, key: &str, value: &str) {
        self.append(key);
        self.append("=");
        self.append(value);
        self.append("\n");
    }

    fn line(&mut self, exact: &str) {
        self.append(exact);
        self.append("\n");
    }

    fn finish(self) -> Result<String, Box<dyn Error>> {
        if self.exceeded {
            return Err("genesis inspection diagnostic exceeds the bounded output limit".into());
        }
        Ok(self.text)
    }
}

/// Exact byte grammar over UTF-8 bytes (DR-0197): passthrough `0x21..=0x7e`
/// except backslash/equals, backslash doubled, everything else `\xHH`.
fn escaped(value: &str) -> String {
    let mut out: String = String::new();
    for &byte in value.as_bytes() {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'=' => {
                let _ = write!(out, "\\x{byte:02x}");
            }
            0x21..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

/// Plain lowercase hex. Every character this produces is already stable
/// under [`escaped`]'s grammar, so no raw digest/id/key ever needs escaping.
fn hex(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn profile_label(profile: CommitmentProfile) -> &'static str {
    match profile {
        CommitmentProfile::PhysicalCheckpointV1 => "physical_checkpoint_v1",
        CommitmentProfile::LogicalGenerationV2 => "logical_generation_v2",
        CommitmentProfile::CausalAdmission => "causal_admission",
    }
}

fn scheme_label(scheme: SignatureSchemeId) -> &'static str {
    match scheme {
        SignatureSchemeId::Ed25519 => "ed25519",
        SignatureSchemeId::Secp256k1 => "secp256k1",
    }
}

fn owner_label(owner: &Owner) -> &'static str {
    match owner {
        Owner::Address(_) => "address",
        Owner::Shared => "shared",
        Owner::Immutable => "immutable",
        Owner::System => "system",
        Owner::ProtocolCustody(_) => "protocol_custody",
    }
}

fn custody_purpose_label(purpose: ProtocolCustodyPurpose) -> &'static str {
    match purpose {
        ProtocolCustodyPurpose::BondCollateral => "bond_collateral",
        ProtocolCustodyPurpose::FeeEscrow => "fee_escrow",
        ProtocolCustodyPurpose::ForfeitedCollateral => "forfeited_collateral",
        ProtocolCustodyPurpose::SunriseMigration => "sunrise_migration",
    }
}

fn render_header(out: &mut Diagnostic, root: &VerifiedGenesisRoot) -> Result<(), Box<dyn Error>> {
    let manifest: &GenesisManifest = root.manifest();
    out.kv("manifest_digest", &root.digest().to_string());
    out.kv(
        "expected_chain_id",
        &escaped(root.genesis_context().chain_id().as_str()),
    );
    out.kv(
        "expected_protocol_version",
        &root.genesis_context().protocol_version().get().to_string(),
    );
    out.kv(
        "expected_epoch",
        &root.genesis_context().epoch().get().to_string(),
    );
    out.kv(
        "manifest_encoding_version",
        &manifest.encoding_version().to_string(),
    );
    out.kv(
        "signature_family",
        &escaped(manifest.signature_message_type()),
    );
    out.kv(
        "commitment_profile",
        profile_label(manifest.commitment_profile),
    );
    out.kv(
        "minimum_freeze_block_height",
        &manifest.minimum_freeze_block_height.to_string(),
    );
    out.kv("genesis_authority", &hex(&manifest.genesis_authority));

    let artifact = manifest.publication.request().artifact();
    out.kv(
        "published_origin",
        &hex(&encode_package_origin(artifact.origin())?),
    );
    out.kv("published_revision", &artifact.revision().to_string());
    out.kv(
        "published_context",
        &hex(&encode_publication_context(artifact.context())?),
    );
    out.kv(
        "published_artifact_digest",
        &manifest.publication.request().artifact_digest().to_string(),
    );

    let call = &manifest.initialization.intent.call;
    out.kv(
        "initializer_code_reference",
        &hex(&encode_dependency_ref(&call.code)?),
    );
    out.kv(
        "initializer_instance_target",
        &hex(&encode_instance_target(&call.instance)?),
    );
    out.kv("initializer_entrypoint", &escaped(&call.entrypoint));
    Ok(())
}

fn render_committee(out: &mut Diagnostic, root: &VerifiedGenesisRoot) {
    out.kv(
        "committee_member_count",
        &root.genesis_committee().validators().len().to_string(),
    );
    for (index, validator) in root.genesis_committee().validators().iter().enumerate() {
        let prefix = format!("committee_member_{index}");
        out.kv(&format!("{prefix}_id"), &hex(validator.id.as_bytes()));
        out.kv(&format!("{prefix}_public_key"), &hex(&validator.public_key));
        out.kv(
            &format!("{prefix}_signature_scheme"),
            scheme_label(validator.signature_scheme),
        );
        out.kv(
            &format!("{prefix}_voting_power"),
            &validator.voting_power.to_string(),
        );
    }
}

fn render_fee_policy(
    out: &mut Diagnostic,
    manifest: &GenesisManifest,
) -> Result<(), Box<dyn Error>> {
    let fee = &manifest.fee_policy;
    let schedule = &fee.gas_schedule;
    out.kv("fee_base_price", &schedule.base_fee.to_string());
    out.kv("fee_execution_price", &schedule.execution_price.to_string());
    out.kv("fee_read_price", &schedule.read_price.to_string());
    out.kv("fee_write_price", &schedule.write_price.to_string());
    out.kv("fee_storage_price", &schedule.storage_price.to_string());
    out.kv(
        "fee_system_module_price",
        &schedule.system_module_price.to_string(),
    );
    out.kv(
        "fee_conversion_divisor",
        &fee.conversion_divisor.to_string(),
    );
    out.kv("fee_reserve_allowance", &fee.reserve_allowance.to_string());
    out.kv("fee_settle_allowance", &fee.settle_allowance.to_string());
    out.kv(
        "fee_publish_artifact_byte_price",
        &fee.publish_artifact_byte_price.to_string(),
    );
    out.kv(
        "fee_publish_closure_node_price",
        &fee.publish_closure_node_price.to_string(),
    );
    out.kv("fee_recipient", &hex(&fee.fee_recipient));
    out.kv("fee_cap_calls", &fee.calls.to_string());
    out.kv("fee_cap_handles", &fee.handles.to_string());
    out.kv("fee_cap_creations", &fee.creations.to_string());
    out.kv("fee_cap_events", &fee.events.to_string());
    out.kv("fee_cap_memory_bytes", &fee.memory_bytes.to_string());
    out.kv("fee_cap_output_bytes", &fee.output_bytes.to_string());
    out.kv("fee_policy_frame", &hex(&encode_paid_fee_policy(fee)?));
    Ok(())
}

fn render_economics(
    out: &mut Diagnostic,
    manifest: &GenesisManifest,
) -> Result<(), Box<dyn Error>> {
    out.kv(
        "economics_resource_count",
        &manifest.economics_policy.resources.len().to_string(),
    );
    for (index, resource) in manifest.economics_policy.resources.iter().enumerate() {
        let prefix = format!("economics_resource_{index}");
        out.kv(
            &format!("{prefix}_id"),
            &format!(
                "{:04x}:{}",
                resource.resource_id.domain(),
                hex(resource.resource_id.value())
            ),
        );
        out.kv(&format!("{prefix}_schema"), &resource.schema.to_string());
        out.kv(
            &format!("{prefix}_fee_escrow"),
            if resource.fee_escrow { "true" } else { "false" },
        );
        match &resource.bond {
            Some(bond) => {
                out.kv(
                    &format!("{prefix}_bond_enabled"),
                    if bond.enabled { "true" } else { "false" },
                );
                out.kv(
                    &format!("{prefix}_bond_min"),
                    &bond.min_bond.get().to_string(),
                );
                out.kv(
                    &format!("{prefix}_bond_unbonding_epochs"),
                    &bond.unbonding_epochs.to_string(),
                );
                match bond.max_validator_exposure {
                    Some(amount) => out.kv(
                        &format!("{prefix}_bond_max_exposure"),
                        &amount.get().to_string(),
                    ),
                    None => out.kv(&format!("{prefix}_bond_max_exposure"), "none"),
                }
            }
            None => out.kv(&format!("{prefix}_bond_enabled"), "false"),
        }
    }
    out.kv(
        "economics_policy_frame",
        &hex(&encode_fastpath_economics_policy(
            &manifest.economics_policy,
        )?),
    );
    Ok(())
}

fn render_object(
    out: &mut Diagnostic,
    index: usize,
    entry: &GenesisObjectEntry,
) -> Result<(), Box<dyn Error>> {
    let prefix = format!("object_{index}");
    out.kv(&format!("{prefix}_id"), &hex(entry.object.id.as_bytes()));
    out.kv(
        &format!("{prefix}_version"),
        &entry.object.version.to_string(),
    );
    out.kv(
        &format!("{prefix}_schema_version"),
        &entry.object.schema_version.to_string(),
    );
    out.kv(
        &format!("{prefix}_type_digest"),
        &entry.object.type_hash.to_string(),
    );
    out.kv(&format!("{prefix}_owner"), owner_label(&entry.object.owner));
    match &entry.object.owner {
        Owner::Address(address) => {
            out.kv(&format!("{prefix}_owner_address"), &hex(address.as_bytes()));
        }
        Owner::ProtocolCustody(scope) => {
            out.kv(
                &format!("{prefix}_owner_custody_purpose"),
                custody_purpose_label(scope.purpose),
            );
            out.kv(
                &format!("{prefix}_owner_custody_chain_id"),
                &escaped(scope.chain_id.as_str()),
            );
            out.kv(
                &format!("{prefix}_owner_custody_subject"),
                &hex(&scope.subject),
            );
            out.kv(
                &format!("{prefix}_owner_custody_resource"),
                &hex(&scope.resource),
            );
        }
        Owner::Shared | Owner::Immutable | Owner::System => {}
    }
    out.kv(
        &format!("{prefix}_frame"),
        &hex(&objects::encode_object(&entry.object)?),
    );
    out.kv(
        &format!("{prefix}_authority_frame"),
        &hex(&encode_object_authority(&entry.authority)?),
    );
    Ok(())
}

/// Renders the complete bounded descriptive summary (DR-0197). Fails closed
/// if the result would exceed the bounded diagnostic limit; never writes
/// stdout itself.
pub(super) fn render(root: &VerifiedGenesisRoot) -> Result<String, Box<dyn Error>> {
    let manifest: &GenesisManifest = root.manifest();
    let mut out: Diagnostic = Diagnostic::new();
    render_header(&mut out, root)?;
    render_committee(&mut out, root);
    render_fee_policy(&mut out, manifest)?;
    render_economics(&mut out, manifest)?;
    out.kv(
        "validator_set_frame",
        &hex(&encode_fastpath_validator_set_record(
            &manifest.validator_set,
        )?),
    );
    out.kv("object_count", &manifest.objects.len().to_string());
    for (index, entry) in manifest.objects.iter().enumerate() {
        render_object(&mut out, index, entry)?;
    }
    out.line("complete=true mode=inspect evidence=none");
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_text_uses_exact_utf8_byte_escape_grammar() {
        assert_eq!(
            escaped("!\"#$%&'()*+,-./0123:;<>?@AZ[]^_`az{|}~"),
            "!\"#$%&'()*+,-./0123:;<>?@AZ[]^_`az{|}~"
        );
        assert_eq!(
            escaped("\\ =\n\r\t\0\u{7f}"),
            "\\\\\\x20\\x3d\\x0a\\x0d\\x09\\x00\\x7f"
        );
        assert_eq!(escaped("é日"), "\\xc3\\xa9\\xe6\\x97\\xa5");
        assert_eq!(escaped("\u{009b}\u{202e}"), "\\xc2\\x9b\\xe2\\x80\\xae");
        assert_eq!(
            escaped("complete=true\nmode=inspect"),
            "complete\\x3dtrue\\x0amode\\x3dinspect"
        );
        assert_eq!(escaped(&hex(&[0, 15, 255])), "000fff");
    }

    fn bounded(limit: usize) -> Diagnostic {
        Diagnostic {
            text: String::new(),
            limit,
            exceeded: false,
        }
    }

    #[test]
    fn exact_limit_and_empty_values_are_admitted_but_excess_is_refused() {
        let mut exact: Diagnostic = bounded(4);
        exact.kv("k", "v");
        assert_eq!(exact.finish().unwrap(), "k=v\n");
        let mut empty: Diagnostic = bounded(3);
        empty.kv("k", "");
        assert_eq!(empty.finish().unwrap(), "k=\n");
        let mut excess: Diagnostic = bounded(3);
        excess.kv("k", "v");
        let retained_length: usize = excess.text.len();
        excess.line("complete=true mode=inspect evidence=none");
        assert_eq!(excess.text.len(), retained_length);
        assert!(excess.finish().is_err());
    }

    #[test]
    fn completion_line_itself_counts_toward_the_bound() {
        let completion: &str = "complete=true mode=inspect evidence=none";
        let mut exact: Diagnostic = bounded(completion.len() + 1);
        exact.line(completion);
        assert_eq!(exact.finish().unwrap(), format!("{completion}\n"));
        let mut short: Diagnostic = bounded(completion.len());
        short.line(completion);
        assert!(short.finish().is_err());
        assert_eq!(
            Diagnostic::new().limit,
            4 * node_core::MAX_GENESIS_MANIFEST_BYTES + 32_768
        );
    }
}
