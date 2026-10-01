//! Heap-backed dependency traversal: fixed authenticated history may be deep
//! without consuming one native stack frame per predecessor or imposing a
//! protocol-wide history ceiling. The caller owns producer authentication.

use std::collections::BTreeSet;

use super::{BusinessReconstructionError, invalid};

enum Step {
    Enter(usize),
    Leave(usize),
}

pub(super) fn closure<'graph, F>(
    roots: &BTreeSet<usize>,
    dependencies: F,
) -> Result<BTreeSet<usize>, BusinessReconstructionError>
where
    F: Fn(usize) -> Result<&'graph [usize], BusinessReconstructionError>,
{
    let mut visiting: BTreeSet<usize> = BTreeSet::new();
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    let mut stack: Vec<Step> = Vec::new();
    for root in roots {
        stack.push(Step::Enter(*root));
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(index) => {
                    if visited.contains(&index) {
                        continue;
                    }
                    if !visiting.insert(index) {
                        return Err(invalid("owned producer dependency cycle"));
                    }
                    let edges: &[usize] = dependencies(index)?;
                    stack.push(Step::Leave(index));
                    // Preserve the former DFS's edge order, while keeping its
                    // activation records on the heap instead of native stack.
                    for child in edges.iter().rev() {
                        stack.push(Step::Enter(*child));
                    }
                }
                Step::Leave(index) => {
                    visiting.remove(&index);
                    visited.insert(index);
                }
            }
        }
    }
    Ok(visited)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(graph: &[Vec<usize>], index: usize) -> Result<&[usize], BusinessReconstructionError> {
        graph
            .get(index)
            .map(Vec::as_slice)
            .ok_or(invalid("owned dependency index is outside the catalog"))
    }

    #[test]
    fn long_nonce_shaped_chain_uses_heap_not_native_recursion() {
        let worker: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                const NODES: usize = 100_000;
                let mut graph: Vec<Vec<usize>> = Vec::with_capacity(NODES);
                graph.push(Vec::new());
                for index in 1..NODES {
                    graph.push(vec![index - 1]);
                }
                let roots: BTreeSet<usize> = BTreeSet::from([NODES - 1]);
                let actual: BTreeSet<usize> =
                    closure(&roots, |index: usize| edges(&graph, index)).unwrap();
                assert_eq!(actual.len(), NODES);
                assert_eq!(actual.first(), Some(&0));
                assert_eq!(actual.last(), Some(&(NODES - 1)));
            })
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn shared_producers_and_duplicate_edges_are_not_cycles() {
        let graph: Vec<Vec<usize>> = vec![vec![1, 2, 1], vec![3], vec![3], Vec::new()];
        let roots: BTreeSet<usize> = BTreeSet::from([0, 1, 2]);
        assert_eq!(
            closure(&roots, |index: usize| edges(&graph, index)).unwrap(),
            BTreeSet::from([0, 1, 2, 3])
        );
    }

    #[test]
    fn cycles_and_missing_producers_return_typed_refusals() {
        for graph in [vec![vec![0]], vec![vec![1], vec![2], vec![0]]] {
            assert!(matches!(
                closure(&BTreeSet::from([0]), |index: usize| edges(&graph, index)),
                Err(BusinessReconstructionError::Invalid(
                    "owned producer dependency cycle"
                ))
            ));
        }
        let graph: Vec<Vec<usize>> = vec![vec![2], Vec::new()];
        for root in [0, 2] {
            assert!(matches!(
                closure(&BTreeSet::from([root]), |index: usize| edges(&graph, index)),
                Err(BusinessReconstructionError::Invalid(
                    "owned dependency index is outside the catalog"
                ))
            ));
        }
        assert!(
            closure(&BTreeSet::new(), |index: usize| edges(&graph, index))
                .unwrap()
                .is_empty()
        );
    }
}
