//! Builds the ProtocolConfig a host passes into its native-http router
//! composition from its actual trusted hash-suite resolver and resolved
//! serving domain, instead of an unresolved ProtocolConfig::genesis
//! default that only ever advertises suite id 1.
//!
//! This value is scaffolding for the read-only query route, never signing
//! authority: real signing and durable-write verification keep using the
//! resolver and committed state directly, never this value.
//! native_http::invoke_query_context and successor::query_context both
//! re-resolve the actually advertised hash_suite_id fresh from the
//! resolver at the authoritative committed/warrant epoch on every request
//! (DR-0082/DR-0189), so this builder carries the resolver own full
//! schedule -- including a non-default genesis suite -- plus a
//! schedule-consistent starting hash_suite_id; it is never responsible for
//! predicting which suite is active for the life of the process.
#![forbid(unsafe_code)]

use hashing::HashSuiteResolver;
use protocol_config::{
    DomainPlacementManifest, ProtocolConfig, ProtocolConfigError, TransactionAuthProfile,
};
use protocol_types::{AtomicityDomainId, Epoch, HashSuite};
use protocol_upgrades::{HashSuiteScheduleConfig, ProtocolUpgradeError};
use std::fmt;

/// Refuses to compose a host query configuration that disagrees with the
/// actual trusted resolver, instead of silently reporting a default suite
/// or an incomplete schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostProtocolContextError {
    /// The resolver has no active suite at the resolved serving epoch.
    NoActiveSuite(hashing::HashingError),
    /// The resolver own schedule could not be represented as a committed
    /// HashSuiteScheduleConfig (for example a duplicate suite id, a
    /// non-monotonic activation epoch, or an oversized schedule).
    Schedule(ProtocolUpgradeError),
    /// The assembled query configuration itself failed validation.
    Config(ProtocolConfigError),
}

impl fmt::Display for HostProtocolContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoActiveSuite(error) => write!(
                f,
                "no active hash suite at the resolved serving epoch: {error}"
            ),
            Self::Schedule(error) => write!(
                f,
                "resolver schedule cannot be committed to the host query configuration: {error}"
            ),
            Self::Config(error) => {
                write!(f, "host query protocol configuration is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for HostProtocolContextError {}

/// Builds the exact ProtocolConfig a host advertises over its read-only
/// query route from resolver -- the same independently pinned, already
/// trusted resolver the host signs and verifies writes with -- and the
/// domain it actually serves. Carries the resolver own complete hash-suite
/// schedule (including a non-default genesis suite), and a
/// schedule-consistent starting hash_suite_id resolved at serving_epoch.
/// Returns an explicit error instead of silently advertising a schedule
/// that disagrees with the resolver backing this host real signing and
/// verification authority.
pub fn host_query_protocol_config(
    resolver: &HashSuiteResolver,
    domain: AtomicityDomainId,
    serving_epoch: Epoch,
) -> Result<ProtocolConfig, HostProtocolContextError> {
    let schedule: HashSuiteScheduleConfig =
        HashSuiteScheduleConfig::new(resolver.schedules().to_vec())
            .map_err(HostProtocolContextError::Schedule)?;
    let active_suite: &HashSuite = resolver
        .suite_for_epoch(serving_epoch)
        .map_err(HostProtocolContextError::NoActiveSuite)?;

    let mut config: ProtocolConfig = ProtocolConfig::genesis();
    config.protocol_version = resolver.protocol_version();
    config.hash_suite_schedule = schedule;
    config.hash_suite_id = active_suite.id;
    config.domain_placement = Some(
        DomainPlacementManifest::single_domain(1, domain, Epoch::new(0))
            .map_err(HostProtocolContextError::Config)?,
    );
    config.transaction_auth_profile =
        Some(TransactionAuthProfile::ed25519_canonical_prime_order_address_is_public_key());
    config
        .validate()
        .map_err(HostProtocolContextError::Config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_types::{ChainId, HashAlgorithmId, HashSuiteSchedule, ProtocolVersion};

    fn domain(byte: u8) -> AtomicityDomainId {
        AtomicityDomainId::new([byte; 32]).unwrap()
    }

    fn resolver(schedules: Vec<HashSuiteSchedule>) -> HashSuiteResolver {
        HashSuiteResolver::new(
            ChainId::new("host-protocol-context-test").unwrap(),
            ProtocolVersion::new(3),
            schedules,
        )
        .unwrap()
    }

    fn non_default_suite(id: u16) -> HashSuite {
        HashSuite::uniform(
            protocol_types::HashSuiteId::new(id),
            HashAlgorithmId::Sha3_256,
        )
    }

    #[test]
    fn default_resolver_preserves_the_existing_genesis_host_query_behavior() {
        let schedules = vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: HashSuite::genesis(),
        }];
        let resolver = resolver(schedules.clone());
        let config = host_query_protocol_config(&resolver, domain(1), Epoch::new(0)).unwrap();
        assert_eq!(config.hash_suite_id, protocol_types::HashSuiteId::new(1));
        assert_eq!(config.hash_suite_schedule.entries(), schedules.as_slice());
    }

    #[test]
    fn a_non_default_genesis_epoch_suite_is_represented_and_selected() {
        let schedules = vec![HashSuiteSchedule {
            activation_epoch: Epoch::new(0),
            suite: non_default_suite(9),
        }];
        let resolver = resolver(schedules.clone());
        let config = host_query_protocol_config(&resolver, domain(2), Epoch::new(0)).unwrap();
        assert_eq!(config.hash_suite_id, protocol_types::HashSuiteId::new(9));
        assert_eq!(config.hash_suite_schedule.entries(), schedules.as_slice());
        // The real wire bytes a host would carry into its router, not only
        // the in-memory field, represent the non-default suite.
        let bytes = config.canonical_bytes().unwrap();
        let default_bytes = ProtocolConfig::genesis().canonical_bytes().unwrap();
        assert_ne!(bytes, default_bytes);
    }

    #[test]
    fn scheduled_epoch_selection_picks_the_active_suite_at_the_resolved_epoch() {
        let schedules = vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(5),
                suite: non_default_suite(7),
            },
        ];
        let resolver = resolver(schedules.clone());

        let before = host_query_protocol_config(&resolver, domain(3), Epoch::new(3)).unwrap();
        assert_eq!(before.hash_suite_id, protocol_types::HashSuiteId::new(1));
        assert_eq!(before.hash_suite_schedule.entries(), schedules.as_slice());

        let after = host_query_protocol_config(&resolver, domain(3), Epoch::new(10)).unwrap();
        assert_eq!(after.hash_suite_id, protocol_types::HashSuiteId::new(7));
        assert_eq!(after.hash_suite_schedule.entries(), schedules.as_slice());
    }

    #[test]
    fn a_duplicate_suite_id_across_schedule_entries_is_refused_before_any_signing() {
        let schedules = vec![
            HashSuiteSchedule {
                activation_epoch: Epoch::new(0),
                suite: HashSuite::genesis(),
            },
            HashSuiteSchedule {
                activation_epoch: Epoch::new(5),
                suite: HashSuite::genesis(),
            },
        ];
        let resolver = resolver(schedules);
        let result = host_query_protocol_config(&resolver, domain(4), Epoch::new(10));
        assert!(matches!(result, Err(HostProtocolContextError::Schedule(_))));
    }
}
