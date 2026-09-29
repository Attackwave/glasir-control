//! Four-eyes policy proposals. Active rights remain one atomic TSV source.
//!
//! A tenant administrator proposes and reviews only the lines inside their
//! tenants' trees: the server composes their edit with the rest of the
//! active policy, and they see neither the other lines nor proposals that
//! reach beyond their trees.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::rights::AdminScope;

/// The trees a proposal reaches, or `None` for a global one.
fn proposal_trees(value: &serde_json::Value) -> Option<BTreeSet<String>> {
    value["scope"].as_array().map(|trees| {
        trees
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect()
    })
}

fn covers(scope: &AdminScope, value: &serde_json::Value) -> bool {
    match (scope, proposal_trees(value)) {
        (AdminScope::Global, _) => true,
        (AdminScope::Trees(_), None) => false,
        (scope, Some(trees)) => scope.covers(&trees),
    }
}

pub fn proposal_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

pub fn create(
    dir: &Path,
    id: &str,
    author: &str,
    rights: &str,
    active: &Path,
    scope: &AdminScope,
) -> Result<(), String> {
    let current = std::fs::read_to_string(active).map_err(|e| e.to_string())?;
    let (rights, scope_value) = match scope {
        AdminScope::Global => (rights.to_string(), serde_json::json!("global")),
        AdminScope::Trees(trees) => (
            crate::rights::compose(&current, rights, trees)?,
            serde_json::json!(trees),
        ),
    };
    let validation = crate::rights::validate_text(&rights);
    if !validation.is_valid() {
        return Err(validation.errors.join("; "));
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let value = serde_json::json!({"schema":"glasir.policy-proposal.v1","id":id,"author":author,"created_at":crate::auth::now(),"rights":rights,"rights_sha256":crate::auth::sha256_hex(rights.as_bytes()),"base_sha256":crate::auth::sha256_hex(current.as_bytes()),"scope":scope_value,"state":"pending"});
    let path = proposal_path(dir, id);
    if path.exists() {
        return Err("proposal already exists".into());
    }
    std::fs::write(path, serde_json::to_vec(&value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn approve(
    dir: &Path,
    id: &str,
    approver: &str,
    active: &Path,
    scope: &AdminScope,
) -> Result<(), String> {
    let path = proposal_path(dir, id);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let author = value["author"].as_str().ok_or("invalid proposal")?;
    if author == approver {
        return Err("author may not approve own proposal".into());
    }
    if value["state"] != "pending" {
        return Err("proposal is not pending".into());
    }
    if !covers(scope, &value) {
        return Err("proposal reaches beyond the approver's trees".into());
    }
    // Approving writes the whole file, so a proposal made against an older
    // policy would silently undo whatever was approved since.
    let current = std::fs::read_to_string(active).map_err(|e| e.to_string())?;
    if value["base_sha256"].as_str() != Some(&crate::auth::sha256_hex(current.as_bytes())) {
        return Err("the active policy changed since this proposal was made".into());
    }
    let rights = value["rights"].as_str().ok_or("invalid proposal")?;
    if !crate::rights::validate_text(rights).is_valid() {
        return Err("proposal no longer valid".into());
    }
    let tmp = active.with_extension("pending");
    std::fs::write(&tmp, rights).map_err(|e| e.to_string())?;
    std::fs::rename(tmp, active).map_err(|e| e.to_string())?;
    value["state"] = serde_json::json!("approved");
    value["approver"] = serde_json::json!(approver);
    value["approved_at"] = serde_json::json!(crate::auth::now());
    std::fs::write(path, serde_json::to_vec(&value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn read(
    dir: &Path,
    id: &str,
    active: &Path,
    scope: &AdminScope,
) -> Result<serde_json::Value, String> {
    let mut proposal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proposal_path(dir, id)).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if !covers(scope, &proposal) {
        return Err("not found".into());
    }
    let current = std::fs::read_to_string(active).map_err(|e| e.to_string())?;
    let current = active_view(&current, scope);
    if let Some(rights) = proposal["rights"].as_str() {
        proposal["rights"] = serde_json::json!(active_view(rights, scope));
    }
    Ok(serde_json::json!({"proposal":proposal,"active_rights":current}))
}

/// A rights text as the given administrator may see it.
pub fn active_view(text: &str, scope: &AdminScope) -> String {
    match scope {
        AdminScope::Global => text.to_string(),
        AdminScope::Trees(trees) => crate::rights::scoped_text(text, trees),
    }
}

/// Every proposal's metadata, newest first, without the proposed text.
pub fn list(dir: &Path, scope: &AdminScope) -> Result<Vec<serde_json::Value>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(value) = std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())
            })
        else {
            continue;
        };
        if !covers(scope, &value) {
            continue;
        }
        out.push(serde_json::json!({
            "id": value["id"], "author": value["author"], "created_at": value["created_at"],
            "scope": value["scope"],
            "state": value["state"], "approver": value["approver"], "approved_at": value["approved_at"],
        }));
    }
    out.sort_by(|a, b| {
        b["created_at"]
            .as_u64()
            .cmp(&a["created_at"].as_u64())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVE: &str = "\
tree\talpha\t127.0.0.1:7001\tsecret-a
tree\tbeta\t127.0.0.1:7002\tsecret-b
role\tadmin\talpha,beta
role\tpay-dev\talpha
role\tshop-dev\tbeta
member\troot\tadmin
member\tanna\tpay-dev
tenant\tpayments\talpha
tenant\tshop\tbeta
tenant-admin\tpaula\tpayments
tenant-admin\tpeter\tpayments
tenant-admin\tsven\tshop
";

    fn setup(name: &str) -> (PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("glasir-policy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let active = root.join("rights.tsv");
        std::fs::write(&active, ACTIVE).unwrap();
        (active, root.join("proposals"))
    }

    fn scope_of(user: &str, active: &Path) -> AdminScope {
        crate::rights::parse(&std::fs::read_to_string(active).unwrap())
            .admin_scope(user, &[])
            .unwrap()
    }

    #[test]
    fn a_tenant_proposal_is_seen_and_approved_only_inside_the_tenant() {
        let (active, dir) = setup("tenant");
        let paula = scope_of("paula", &active);
        create(
            &dir,
            "p1",
            "paula",
            "role\tpay-dev\talpha\nmember\tdora\tpay-dev\n",
            &active,
            &paula,
        )
        .unwrap();

        let sven = scope_of("sven", &active);
        assert!(list(&dir, &sven).unwrap().is_empty());
        assert!(read(&dir, "p1", &active, &sven).is_err());
        assert!(approve(&dir, "p1", "sven", &active, &sven).is_err());

        let peter = scope_of("peter", &active);
        let seen = read(&dir, "p1", &active, &peter).unwrap();
        assert!(!seen.to_string().contains("secret"));
        assert!(!seen["active_rights"].as_str().unwrap().contains("shop-dev"));
        assert!(approve(&dir, "p1", "paula", &active, &paula).is_err());
        approve(&dir, "p1", "peter", &active, &peter).unwrap();

        let now = std::fs::read_to_string(&active).unwrap();
        assert!(now.contains("member\tdora\tpay-dev"));
        assert!(now.contains("secret-b") && now.contains("tenant-admin\tsven"));
    }

    #[test]
    fn a_global_proposal_needs_a_global_approver() {
        let (active, dir) = setup("global");
        let text = format!("{ACTIVE}member\tdora\tpay-dev\n");
        create(&dir, "g1", "root", &text, &active, &AdminScope::Global).unwrap();
        let paula = scope_of("paula", &active);
        assert!(list(&dir, &paula).unwrap().is_empty());
        assert!(approve(&dir, "g1", "paula", &active, &paula).is_err());
    }

    #[test]
    fn approval_refuses_a_proposal_made_against_an_older_policy() {
        let (active, dir) = setup("stale");
        let paula = scope_of("paula", &active);
        create(
            &dir,
            "p1",
            "paula",
            "role\tpay-dev\talpha\n",
            &active,
            &paula,
        )
        .unwrap();
        std::fs::write(&active, format!("{ACTIVE}member\tbruno\tshop-dev\n")).unwrap();
        let peter = scope_of("peter", &active);
        let err = approve(&dir, "p1", "peter", &active, &peter).unwrap_err();
        assert!(err.contains("changed"), "{err}");
        assert!(
            std::fs::read_to_string(&active)
                .unwrap()
                .contains("member\tbruno")
        );
    }
}
