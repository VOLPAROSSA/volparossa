//! An explicitly enrolled public task graph, not model-generated execution authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use volparossa_local_control::compute::PublicTask;

const MAX_PLAN_BYTES: u64 = 64 * 1024;
const MAX_NODES: usize = 16;
const MAX_ID_BYTES: usize = 48;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub(super) version: u32,
    /// Explicit order breaks ties between simultaneously ready nodes.
    pub(super) nodes: Vec<Node>,
    pub(super) output: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Node {
    pub(super) id: String,
    pub(super) question: String,
    /// An empty list reads the original source; otherwise the node consumes these parents.
    pub(super) depends_on: Vec<String>,
}

impl Plan {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let bytes = crate::compute::read_file(path, MAX_PLAN_BYTES)?;
        let plan: Self = serde_json::from_slice(&bytes)?;
        plan.validate()?;
        Ok(plan)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.topological().map(|_| ())
    }

    /// Validate all work and return a stable order using original indices as ready-node ties.
    pub(super) fn topological(&self) -> Result<Vec<usize>> {
        ensure!(
            self.version == 1 && (2..=MAX_NODES).contains(&self.nodes.len()),
            "compute_graph_plan_version_or_node_bound"
        );
        let mut indices = BTreeMap::new();
        for (index, node) in self.nodes.iter().enumerate() {
            ensure!(valid_id(&node.id), "compute_graph_node_id");
            ensure!(
                indices.insert(node.id.as_str(), index).is_none(),
                "compute_graph_duplicate_node"
            );
            PublicTask::AnswerPublicQuestionV1 {
                question: node.question.clone(),
            }
            .question()?;
            ensure!(
                node.depends_on.len() < self.nodes.len(),
                "compute_graph_dependency_bound"
            );
        }
        let output = *indices
            .get(self.output.as_str())
            .context("compute_graph_output_missing")?;
        let mut predecessors = Vec::with_capacity(self.nodes.len());
        for (index, node) in self.nodes.iter().enumerate() {
            let mut seen = BTreeSet::new();
            let mut dependencies = Vec::with_capacity(node.depends_on.len());
            for parent in &node.depends_on {
                let parent = *indices
                    .get(parent.as_str())
                    .context("compute_graph_dependency_missing")?;
                ensure!(parent != index, "compute_graph_self_dependency");
                ensure!(seen.insert(parent), "compute_graph_duplicate_dependency");
                dependencies.push(parent);
            }
            predecessors.push(dependencies);
        }

        let mut finished = vec![false; self.nodes.len()];
        let mut order = Vec::with_capacity(self.nodes.len());
        while order.len() < self.nodes.len() {
            let next = (0..self.nodes.len())
                .find(|&index| {
                    !finished[index] && predecessors[index].iter().all(|&parent| finished[parent])
                })
                .context("compute_graph_dependency_cycle")?;
            finished[next] = true;
            order.push(next);
        }

        let mut contributes = vec![false; self.nodes.len()];
        contributes[output] = true;
        for &index in order.iter().rev() {
            if contributes[index] {
                for &parent in &predecessors[index] {
                    contributes[parent] = true;
                }
            }
        }
        ensure!(
            contributes.into_iter().all(|included| included),
            "compute_graph_node_does_not_contribute_to_output"
        );
        Ok(order)
    }

    /// Hash canonical struct serialization; explicit node and parent order remain significant.
    pub(super) fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub(super) fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

fn valid_id(id: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests;
