//! Well-formed object signatures over an exact authenticated candidate closure.
//! This is neither durable dependency provenance nor host object authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use abi::call_values::{CallAbi, ValueError, ValueLayout, decode_call_abi};
use abi::executable_abi::{ExecutableAbi, decode_executable_abi};
use abi::package_types::PackageOrigin;
use abi::public_abi::{ArgumentKind, PackageAbi, PatternArgument, TypePattern};

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
    Abi(ValueError),
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
impl From<ValueError> for InterfaceError {
    fn from(error: ValueError) -> Self {
        Self::Abi(error)
    }
}

/// Witness of well-formed object signatures and an exact signed candidate graph.
///
/// Private construction prevents substituting an unchecked ABI. The graph is
/// NOT a durable published registry: freshness, origin reservation, authorized
/// upgrades, ownership, and host authority remain unverified. Representation
/// declarations and substitution exist, but are still not runtime authority.
/// No execution or persistence API accepts this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPublicationInterface {
    candidate: AuthenticatedPublicationCandidate,
    dependencies: Vec<AuthenticatedPublicationCandidate>,
    abi: Arc<CallAbi>,
    dependency_abis: BTreeMap<PackageOrigin, Arc<CallAbi>>,
    executable_abis: BTreeMap<PackageOrigin, Arc<ExecutableAbi>>,
}

impl VerifiedPublicationInterface {
    /// Returns verified executable metadata for an exact defining origin.
    pub fn executable_abi(&self, origin: &PackageOrigin) -> Option<&ExecutableAbi> {
        self.executable_abis.get(origin).map(Arc::as_ref)
    }

    /// Re-roots this authenticated closure at one included library origin.
    /// Immutable code and layouts are shared; no parsing, copying module bodies or
    /// graph verification is repeated. The bounded graph walk grants no host rights.
    pub fn for_origin(&self, origin: &PackageOrigin) -> Result<Self, InterfaceError> {
        if origin == &self.abi().origin {
            return Ok(self.clone());
        }
        let root: AuthenticatedPublicationCandidate = self
            .dependencies
            .iter()
            .find(|candidate| candidate.artifact().origin() == origin)
            .ok_or(InterfaceError::MissingDependency)?
            .clone();
        let mut required: BTreeSet<PackageOrigin> = BTreeSet::new();
        let mut pending: Vec<PackageOrigin> = root
            .artifact()
            .unverified_dependencies()
            .iter()
            .map(|reference| reference.origin().clone())
            .collect();
        let mut dependencies: Vec<AuthenticatedPublicationCandidate> = Vec::new();
        while let Some(origin) = pending.pop() {
            if !required.insert(origin.clone()) {
                continue;
            }
            let candidate: AuthenticatedPublicationCandidate = self
                .dependencies
                .iter()
                .find(|candidate| candidate.artifact().origin() == &origin)
                .ok_or(InterfaceError::MissingDependency)?
                .clone();
            pending.extend(
                candidate
                    .artifact()
                    .unverified_dependencies()
                    .iter()
                    .map(|reference| reference.origin().clone()),
            );
            dependencies.push(candidate);
        }
        let abi: Arc<CallAbi> = self
            .dependency_abis
            .get(origin)
            .ok_or(InterfaceError::MissingDependency)?
            .clone();
        let dependency_abis: BTreeMap<PackageOrigin, Arc<CallAbi>> = self
            .dependency_abis
            .iter()
            .filter(|(origin, _)| required.contains(*origin))
            .map(|(origin, abi)| (origin.clone(), Arc::clone(abi)))
            .collect();
        required.insert(origin.clone());
        let executable_abis: BTreeMap<PackageOrigin, Arc<ExecutableAbi>> = self
            .executable_abis
            .iter()
            .filter(|(origin, _)| required.contains(*origin))
            .map(|(origin, abi)| (origin.clone(), Arc::clone(abi)))
            .collect();
        Ok(Self {
            candidate: root,
            dependencies,
            abi,
            dependency_abis,
            executable_abis,
        })
    }
    // Retain verified declarations for binding; never decode caller-supplied ABI here.
    pub(super) fn defining_abi(&self, origin: &PackageOrigin) -> Option<&PackageAbi> {
        if origin == &self.abi.objects.origin {
            Some(&self.abi.objects)
        } else {
            self.dependency_abis.get(origin).map(|abi| &abi.objects)
        }
    }
    pub(super) fn body_layout(
        &self,
        origin: &PackageOrigin,
        constructor: u16,
    ) -> Option<&ValueLayout> {
        let call_abi: &CallAbi = if origin == &self.abi.objects.origin {
            &self.abi
        } else {
            self.dependency_abis.get(origin)?
        };
        let index: usize = call_abi
            .objects
            .constructors
            .iter()
            .position(|item| item.local_id == constructor)?;
        call_abi.bodies.get(index)
    }
    pub(super) fn permits_type_origin(&self, origin: &PackageOrigin) -> bool {
        origin == &self.abi.objects.origin
            || self
                .candidate
                .artifact()
                .unverified_dependencies()
                .iter()
                .any(|reference| reference.origin() == origin)
    }
    /// Returns the exact signed root, without granting execution authority.
    pub fn candidate(&self) -> &AuthenticatedPublicationCandidate {
        &self.candidate
    }
    /// Returns checked declaration data, not an object-authority policy.
    pub fn abi(&self) -> &PackageAbi {
        &self.abi.objects
    }
    /// Returns the exact signed argument layout, never a caller-provided schema.
    pub fn argument_layout(&self, entrypoint: &str) -> Option<&ValueLayout> {
        let index: usize = self
            .abi
            .objects
            .entrypoints
            .iter()
            .position(|entry| entry.name == entrypoint)?;
        self.abi.arguments.get(index)
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
        let artifact = node.artifact();
        total = total
            .checked_add(artifact.unverified_abi().len())
            .ok_or(InterfaceError::Limit("ABI bytes"))?;
        if total > MAX_INTERFACE_ABI_BYTES {
            return Err(InterfaceError::Limit("ABI bytes"));
        }
        if artifact.origin().chain_id() != candidate.artifact().origin().chain_id() {
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
        for reference in node.artifact().unverified_dependencies() {
            let target: usize = *indices
                .get(reference.origin())
                .ok_or(InterfaceError::MissingDependency)?;
            let artifact = nodes[target].artifact();
            if reference.revision() != artifact.revision()
                || reference.context() != artifact.context()
                || reference.artifact_digest() != nodes[target].digest()
            {
                return Err(InterfaceError::DependencyMismatch);
            }
            edges.push(target);
        }
        graph.push(edges);
    }
    validate_graph(&graph)?;
    let mut abis: Vec<CallAbi> = Vec::with_capacity(count);
    let mut executable_abis: BTreeMap<PackageOrigin, Arc<ExecutableAbi>> = BTreeMap::new();
    for node in &nodes {
        let artifact = node.artifact();
        if (candidate.artifact().wasm_profile() == 2 && artifact.wasm_profile() != 2)
            || (candidate.artifact().wasm_profile() == 3
                && !matches!(artifact.wasm_profile(), 2 | 3))
            || (candidate.artifact().wasm_profile() == 4
                && !matches!(artifact.wasm_profile(), 2..=4))
        {
            return Err(InterfaceError::Abi(ValueError::Invalid(
                "typed executable depends on nonexecutable profile",
            )));
        }
        let abi: CallAbi = if matches!(artifact.wasm_profile(), 2..=4) {
            let executable: ExecutableAbi = decode_executable_abi(artifact.unverified_abi())?;
            if artifact.wasm_profile() != 4 && executable.results.iter().any(|r| !r.is_empty()) {
                return Err(InterfaceError::Abi(ValueError::Invalid(
                    "object result declarations require wasm profile four",
                )));
            }
            let call: CallAbi = executable.call.clone();
            executable_abis.insert(artifact.origin().clone(), Arc::new(executable));
            call
        } else {
            decode_call_abi(artifact.unverified_abi())?
        };
        if &abi.objects.origin != artifact.origin() {
            return Err(InterfaceError::OriginMismatch);
        }
        if abi.objects.entrypoints.len() != artifact.exports().len()
            || !abi
                .objects
                .entrypoints
                .iter()
                .zip(artifact.exports())
                .all(|(entry, export)| &entry.name == export)
        {
            return Err(InterfaceError::ExportMismatch);
        }
        abis.push(abi);
    }
    for (index, call_abi) in abis.iter().enumerate() {
        let abi: &PackageAbi = &call_abi.objects;
        let allowed: BTreeSet<&PackageOrigin> = std::iter::once(&abi.origin)
            .chain(
                graph[index]
                    .iter()
                    .map(|target| &abis[*target].objects.origin),
            )
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
        if let Some(executable) = executable_abis.get(&abi.origin) {
            if executable.results.len() != abi.entrypoints.len() {
                return Err(InterfaceError::Abi(ValueError::Invalid(
                    "object result entrypoint count mismatch",
                )));
            }
            for (entry, results) in abi.entrypoints.iter().zip(&executable.results) {
                for result in results {
                    let schema: u32 = verify_pattern(
                        &result.ty,
                        &entry.type_parameters,
                        &allowed,
                        &indices,
                        &abis,
                    )?;
                    if schema != result.schema {
                        return Err(InterfaceError::SchemaMismatch);
                    }
                }
            }
        }
    }
    // No root/ABI cloning of large code blobs; the witness retains exact inputs.
    let mut verified_abis: std::vec::IntoIter<CallAbi> = abis.into_iter();
    let abi: CallAbi = verified_abis
        .next()
        .ok_or(InterfaceError::MissingDependency)?;
    let dependency_abis: BTreeMap<PackageOrigin, Arc<CallAbi>> = verified_abis
        .map(|abi| (abi.objects.origin.clone(), Arc::new(abi)))
        .collect();
    Ok(VerifiedPublicationInterface {
        candidate,
        dependencies,
        abi: Arc::new(abi),
        dependency_abis,
        executable_abis,
    })
}

fn verify_pattern(
    pattern: &TypePattern,
    parameters: &[ArgumentKind],
    allowed: &BTreeSet<&PackageOrigin>,
    indices: &BTreeMap<&PackageOrigin, usize>,
    abis: &[CallAbi],
) -> Result<u32, InterfaceError> {
    if !allowed.contains(&pattern.origin) {
        return Err(InterfaceError::UndeclaredOrigin);
    }
    let index: usize = *indices
        .get(&pattern.origin)
        .ok_or(InterfaceError::UndeclaredOrigin)?;
    let declaration = abis[index]
        .objects
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
