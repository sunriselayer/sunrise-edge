//! Well-formed object signatures over an exact authenticated candidate closure.
//! This is neither durable dependency provenance nor host object authority.

use std::collections::{BTreeMap, BTreeSet};

use abi::package_types::PackageOrigin;
use abi::public_abi::{
    ArgumentKind, PackageAbi, PatternArgument, PublicAbiError, TypePattern, decode_package_abi,
};

use super::AuthenticatedPublicationCandidate;

/// Maximum candidate nodes, including the root, in one interface verification.
pub const MAX_INTERFACE_NODES: usize = 33;
/// Maximum dependency path length, including the root and leaf.
pub const MAX_INTERFACE_DEPTH: usize = 8;
/// Maximum total ABI bytes across all supplied candidates, before decoding.
pub const MAX_INTERFACE_ABI_BYTES: usize = 256 * 1024;

/// Errors at the candidate interface boundary. No failure has side effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceError {
    /// A public ABI frame is malformed or exceeds its structural bounds.
    Abi(PublicAbiError),
    /// Aggregate resource bounds were exceeded.
    Limit(&'static str),
    /// A second candidate for the same origin was supplied, including the root.
    DuplicateOrigin,
    /// The closure contains a different chain.
    ChainMismatch,
    /// An exact signed dependency has no supplied candidate.
    MissingDependency,
    /// A supplied candidate differs from the signed revision/context/digest.
    DependencyMismatch,
    /// A supplied candidate is not reachable from the root.
    ExtraDependency,
    /// The declared graph contains a cycle.
    DependencyCycle,
    /// ABI origin does not match the authenticated artifact origin.
    OriginMismatch,
    /// ABI entrypoint names differ from structurally validated WASM exports.
    ExportMismatch,
    /// A type references neither self nor a directly declared dependency.
    UndeclaredOrigin,
    /// The defining ABI does not declare the requested constructor.
    UnknownConstructor,
    /// A type argument count differs from its defining constructor.
    ArityMismatch,
    /// A nominal/opaque kind, opaque domain, or parameter kind differs.
    KindMismatch,
    /// The object's schema equality token differs from its declaration.
    SchemaMismatch,
}

impl std::fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abi(error) => error.fmt(f),
            Self::Limit(bound) => write!(f, "interface verification exceeds {bound}"),
            other => write!(f, "invalid publication interface: {other:?}"),
        }
    }
}
impl std::error::Error for InterfaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Abi(error) => Some(error),
            _ => None,
        }
    }
}
impl From<PublicAbiError> for InterfaceError {
    fn from(error: PublicAbiError) -> Self {
        Self::Abi(error)
    }
}

/// Witness of well-formed object signatures and an exact signed candidate graph.
///
/// Private construction prevents substituting an unchecked ABI. The graph is
/// NOT a durable published registry: freshness, origin reservation, authorized
/// upgrades, value layouts, runtime type substitution, ownership, and host
/// authority remain unverified. No execution or persistence API accepts this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPublicationInterface {
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
    abi: PackageAbi,
}

impl VerifiedPublicationInterface {
    /// Returns the exact signed root, without granting execution authority.
    pub fn candidate(&self) -> &AuthenticatedPublicationCandidate {
        &self.candidate
    }
    /// Returns checked declaration data, not an object-authority policy.
    pub fn abi(&self) -> &PackageAbi {
        &self.abi
    }
    /// Returns the exact supplied candidate closure (excluding the root).
    pub fn dependencies(&self) -> &[AuthenticatedPublicationCandidate] {
        &self.dependencies
    }
}

/// Verifies every ABI and signed edge in the exact transitive dependency closure.
///
/// Inputs must already have been authenticated against their own trusted original
/// contexts. One candidate per origin is permitted; input order is irrelevant.
/// An ABI may refer only to its own constructors or directly signed dependencies,
/// even if another origin happens to occur transitively. Parameter binders are
/// entrypoint-local; nesting never introduces a new binder.
pub fn verify_publication_interface(
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
) -> Result<VerifiedPublicationInterface, InterfaceError> {
    let count: usize = dependencies
        .len()
        .checked_add(1)
        .ok_or(InterfaceError::Limit("nodes"))?;
    if count > MAX_INTERFACE_NODES {
        return Err(InterfaceError::Limit("nodes"));
    }
    let nodes: Vec<&AuthenticatedPublicationCandidate> = std::iter::once(&candidate)
        .chain(dependencies.iter())
        .collect();
    let mut total: usize = 0;
    let mut indices: BTreeMap<&PackageOrigin, usize> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        let artifact = node.request().artifact();
        total = total
            .checked_add(artifact.unverified_abi().len())
            .ok_or(InterfaceError::Limit("ABI bytes"))?;
        if total > MAX_INTERFACE_ABI_BYTES {
            return Err(InterfaceError::Limit("ABI bytes"));
        }
        if artifact.origin().chain_id() != candidate.request().artifact().origin().chain_id() {
            return Err(InterfaceError::ChainMismatch);
        }
        if indices.insert(artifact.origin(), index).is_some() {
            return Err(InterfaceError::DuplicateOrigin);
        }
    }
    // Resolve every exact signed edge before decoding any ABI.
    let mut graph: Vec<Vec<usize>> = Vec::with_capacity(count);
    for node in &nodes {
        let mut edges: Vec<usize> = Vec::new();
        for reference in node.request().artifact().unverified_dependencies() {
            let target: usize = *indices
                .get(reference.origin())
                .ok_or(InterfaceError::MissingDependency)?;
            let request = nodes[target].request();
            let artifact = request.artifact();
            if reference.revision() != artifact.revision()
                || reference.context() != artifact.context()
                || reference.artifact_digest() != request.artifact_digest()
            {
                return Err(InterfaceError::DependencyMismatch);
            }
            edges.push(target);
        }
        graph.push(edges);
    }
    validate_graph(&graph)?;
    let mut abis: Vec<PackageAbi> = Vec::with_capacity(count);
    for node in &nodes {
        let artifact = node.request().artifact();
        let abi: PackageAbi = decode_package_abi(artifact.unverified_abi())?;
        if &abi.origin != artifact.origin() {
            return Err(InterfaceError::OriginMismatch);
        }
        if abi.entrypoints.len() != artifact.exports().len()
            || !abi
                .entrypoints
                .iter()
                .zip(artifact.exports())
                .all(|(entry, export)| &entry.name == export)
        {
            return Err(InterfaceError::ExportMismatch);
        }
        abis.push(abi);
    }
    for (index, abi) in abis.iter().enumerate() {
        let allowed: BTreeSet<&PackageOrigin> = std::iter::once(&abi.origin)
            .chain(graph[index].iter().map(|target| &abis[*target].origin))
            .collect();
        for entry in &abi.entrypoints {
            for object in &entry.objects {
                let schema: u32 = verify_pattern(
                    &object.ty,
                    &entry.type_parameters,
                    &allowed,
                    &indices,
                    &abis,
                )?;
                if schema != object.schema {
                    return Err(InterfaceError::SchemaMismatch);
                }
            }
        }
    }
    // No root/ABI cloning of large code blobs; the witness retains exact inputs.
    let abi: PackageAbi = abis
        .into_iter()
        .next()
        .ok_or(InterfaceError::MissingDependency)?;
    Ok(VerifiedPublicationInterface {
        candidate,
        dependencies,
        abi,
    })
}

fn verify_pattern(
    pattern: &TypePattern,
    parameters: &[ArgumentKind],
    allowed: &BTreeSet<&PackageOrigin>,
    indices: &BTreeMap<&PackageOrigin, usize>,
    abis: &[PackageAbi],
) -> Result<u32, InterfaceError> {
    if !allowed.contains(&pattern.origin) {
        return Err(InterfaceError::UndeclaredOrigin);
    }
    let index: usize = *indices
        .get(&pattern.origin)
        .ok_or(InterfaceError::UndeclaredOrigin)?;
    let declaration = abis[index]
        .constructors
        .iter()
        .find(|item| item.local_id == pattern.constructor)
        .ok_or(InterfaceError::UnknownConstructor)?;
    if pattern.arguments.len() != declaration.arguments.len() {
        return Err(InterfaceError::ArityMismatch);
    }
    for (argument, expected) in pattern.arguments.iter().zip(&declaration.arguments) {
        match (argument, expected) {
            (PatternArgument::Nominal(nested), ArgumentKind::Nominal) => {
                verify_pattern(nested, parameters, allowed, indices, abis)?;
            }
            (PatternArgument::Opaque { domain, .. }, ArgumentKind::Opaque(expected_domain))
                if domain == expected_domain => {}
            (PatternArgument::Parameter(parameter), _) => {
                if parameters.get(usize::from(*parameter)) != Some(expected) {
                    return Err(InterfaceError::KindMismatch);
                }
            }
            _ => return Err(InterfaceError::KindMismatch),
        }
    }
    Ok(declaration.schema)
}

fn validate_graph(graph: &[Vec<usize>]) -> Result<(), InterfaceError> {
    fn visit(
        node: usize,
        depth: usize,
        graph: &[Vec<usize>],
        active: &mut BTreeSet<usize>,
        heights: &mut BTreeMap<usize, usize>,
    ) -> Result<usize, InterfaceError> {
        if depth > MAX_INTERFACE_DEPTH {
            return Err(InterfaceError::Limit("dependency depth"));
        }
        if active.contains(&node) {
            return Err(InterfaceError::DependencyCycle);
        }
        if let Some(height) = heights.get(&node) {
            if depth
                .checked_add(*height)
                .and_then(|n| n.checked_sub(1))
                .is_none_or(|n| n > MAX_INTERFACE_DEPTH)
            {
                return Err(InterfaceError::Limit("dependency depth"));
            }
            return Ok(*height);
        }
        active.insert(node);
        let mut height: usize = 1;
        let edges: &[usize] = graph.get(node).ok_or(InterfaceError::MissingDependency)?;
        for target in edges {
            let child: usize = visit(
                *target,
                depth
                    .checked_add(1)
                    .ok_or(InterfaceError::Limit("dependency depth"))?,
                graph,
                active,
                heights,
            )?;
            height = height.max(
                child
                    .checked_add(1)
                    .ok_or(InterfaceError::Limit("dependency depth"))?,
            );
        }
        active.remove(&node);
        heights.insert(node, height);
        Ok(height)
    }
    let mut active: BTreeSet<usize> = BTreeSet::new();
    let mut heights: BTreeMap<usize, usize> = BTreeMap::new();
    visit(0, 1, graph, &mut active, &mut heights)?;
    if heights.len() != graph.len() {
        return Err(InterfaceError::ExtraDependency);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_cycles_and_longest_diamond_path_are_bounded() {
        assert_eq!(
            validate_graph(&[vec![1], vec![0]]),
            Err(InterfaceError::DependencyCycle)
        );
        assert_eq!(
            validate_graph(&[vec![], vec![]]),
            Err(InterfaceError::ExtraDependency)
        );
        // Node 7 was memoized at depth 2 but also occurs at depth 8. Its child
        // would make the latter path depth 9, so cached heights must not bypass bounds.
        let graph: Vec<Vec<usize>> = vec![
            vec![7, 1],
            vec![2],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
            vec![8],
            vec![],
        ];
        assert_eq!(
            validate_graph(&graph),
            Err(InterfaceError::Limit("dependency depth"))
        );
        let valid: Vec<Vec<usize>> = (0..8)
            .map(|i| if i == 7 { vec![] } else { vec![i + 1] })
            .collect();
        assert_eq!(validate_graph(&valid), Ok(()));
    }
}
