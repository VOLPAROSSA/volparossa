use std::fs;

use super::*;

fn node(id: &str, depends_on: &[&str]) -> Node {
    Node {
        id: id.into(),
        question: format!("Explain the public context for {id}."),
        depends_on: depends_on.iter().map(|id| (*id).into()).collect(),
    }
}

fn fork_join() -> Plan {
    Plan {
        version: 1,
        nodes: vec![
            node("compare", &["requirements", "conflicts"]),
            node("requirements", &[]),
            node("conflicts", &[]),
        ],
        output: "compare".into(),
    }
}

#[test]
fn fork_join_orders_ready_work_by_explicit_node_order_and_binds_exact_plan() {
    let plan = fork_join();
    assert_eq!(plan.topological().unwrap(), [1, 2, 0]);
    assert_eq!(plan.node("compare"), Some(&plan.nodes[0]));
    assert_eq!(plan.node("missing"), None);
    let bytes = serde_json::to_vec(&plan).unwrap();
    let loaded: Plan = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(loaded, plan);
    assert_eq!(
        plan.fingerprint().unwrap(),
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(loaded.fingerprint().unwrap(), plan.fingerprint().unwrap());
    let mut reordered = plan.clone();
    reordered.nodes.swap(1, 2);
    assert_eq!(reordered.topological().unwrap(), [1, 2, 0]);
    assert_ne!(
        reordered.fingerprint().unwrap(),
        plan.fingerprint().unwrap()
    );
    let mut different_question = plan.clone();
    different_question.nodes[1].question = "List the public requirements.".into();
    assert_ne!(
        different_question.fingerprint().unwrap(),
        plan.fingerprint().unwrap()
    );
}

#[test]
fn newly_ready_nodes_use_the_same_stable_index_tiebreak() {
    let plan = Plan {
        version: 1,
        nodes: vec![
            node("output", &["middle", "right"]),
            node("middle", &["left"]),
            node("left", &[]),
            node("right", &[]),
        ],
        output: "output".into(),
    };
    assert_eq!(plan.topological().unwrap(), [2, 1, 3, 0]);
}

#[test]
fn unresolved_duplicate_self_and_cyclic_dependencies_are_rejected() {
    let original = fork_join();
    let mut missing = original.clone();
    missing.nodes[0].depends_on[0] = "absent".into();
    assert!(missing.validate().is_err());
    let mut duplicate = original.clone();
    duplicate.nodes[0].depends_on[1] = "requirements".into();
    assert!(duplicate.validate().is_err());
    let mut self_dependency = original.clone();
    self_dependency.nodes[1]
        .depends_on
        .push("requirements".into());
    assert!(self_dependency.validate().is_err());
    let mut cycle = original;
    cycle.nodes[1].depends_on.push("compare".into());
    assert!(cycle.validate().is_err());
}

#[test]
fn every_unique_node_must_contribute_to_the_resolved_output() {
    let original = fork_join();
    let mut hidden = original.clone();
    hidden.nodes.push(node("unrelated", &[]));
    assert!(hidden.validate().is_err());
    let mut duplicate = original.clone();
    duplicate.nodes[2].id = "requirements".into();
    assert!(duplicate.validate().is_err());
    let mut missing_output = original.clone();
    missing_output.output = "absent".into();
    assert!(missing_output.validate().is_err());
    let mut output_before_other_work = original;
    output_before_other_work.output = "requirements".into();
    assert!(output_before_other_work.validate().is_err());
}

#[test]
fn bounds_identifiers_and_questions_use_the_existing_public_task_contract() {
    let original = fork_join();
    for id in ["", ".", "..", "../path", "/path", "has space", "é", "-flag"] {
        let mut invalid = original.clone();
        invalid.nodes[0].id = id.into();
        invalid.output = id.into();
        assert!(invalid.validate().is_err(), "{id}");
    }
    for length in [48, 49] {
        let mut plan = original.clone();
        plan.nodes[0].id = "n".repeat(length);
        plan.output.clone_from(&plan.nodes[0].id);
        assert_eq!(plan.validate().is_ok(), length == 48);
    }
    for question in [
        String::new(),
        " \n\t".into(),
        "bad\0question".into(),
        "x".repeat(513),
    ] {
        let mut invalid = original.clone();
        invalid.nodes[0].question = question;
        assert!(invalid.validate().is_err());
    }
    let mut valid = original.clone();
    valid.nodes[0].question = "é".repeat(256);
    valid.nodes[1].question = "\nA public question?\t".into();
    valid.validate().unwrap();
    let mut version = original;
    version.version = 2;
    assert!(version.validate().is_err());
    for count in [1_usize, 2, 16, 17] {
        let nodes = (0..count)
            .map(|index| {
                let previous = format!("n{}", index.saturating_sub(1));
                if index == 0 {
                    node("n0", &[])
                } else {
                    node(&format!("n{index}"), &[&previous])
                }
            })
            .collect();
        let plan = Plan {
            version: 1,
            nodes,
            output: format!("n{}", count - 1),
        };
        assert_eq!(plan.validate().is_ok(), (2..=16).contains(&count));
    }
}

#[test]
fn file_loading_is_bounded_and_rejects_unknown_plan_or_node_fields() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("plan.json");
    let plan = fork_join();
    fs::write(&path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    assert_eq!(Plan::load(&path).unwrap(), plan);
    for field in ["plan", "node"] {
        let mut value = serde_json::to_value(&plan).unwrap();
        if field == "plan" {
            value["execute_shell"] = true.into();
        } else {
            value["nodes"][0]["extra_source"] = "unselected".into();
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(Plan::load(&path).is_err());
    }
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_PLAN_BYTES + 1)
        .unwrap();
    assert!(Plan::load(&path).is_err());
}
