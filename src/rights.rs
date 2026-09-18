//! Who may reach which tree, and where each tree is served.
//!
//! One versioned file, re-read when it changes. That is deliberate for stage 2
//! and not a placeholder for a database: git already records who changed a
//! right and when, which is the audit trail an admin view would otherwise have
//! to build. When rights are mirrored from a code host (stage 5) this becomes
//! the cache that mirroring writes into, not something to migrate away from.
//!
//! ```text
//! tree    <name>  <backend-addr>  <shared-token>
//! grant   <user>  <tree>[,<tree>…]
//! role    <role>  <tree>[,<tree>…]
//! member  <user>  <role>[,<role>…]
//! role-tool <role> <tree> <tool>[,<tool>…]
//! group   <idp-group> <role>[,<role>…]
//! workspace <name> <tree>[,<tree>…]
//! workspace-package <workspace> <package@version>[,<package@version>…]
//! ```
//!
//! Tab-separated, `#` comments, blank lines ignored — the same shape as
//! `.glasir-tokens` in the core, for the same reason: greppable, and editable
//! by someone who has to fix access at three in the morning.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// One served tree: where it is, and the credential this service uses to reach
/// it.
///
/// The backend token is *ours*, never the caller's. Passing a client's
/// credential through would make the backend trust something it did not issue —
/// the token-passthrough problem the MCP security guidance names explicitly.
#[derive(Clone, Debug, PartialEq)]
pub struct Tree {
    pub name: String,
    pub addr: String,
    pub token: String,
}

#[derive(Default, Debug, PartialEq)]
pub struct Rights {
    pub trees: Vec<Tree>,
    /// user -> the trees they may reach.
    pub grants: HashMap<String, Vec<String>>,
    /// role -> the trees its members may reach. Roles are additive to direct
    /// grants; there is deliberately no deny rule whose ordering could widen
    /// access after a configuration edit.
    pub roles: HashMap<String, Vec<String>>,
    /// user -> assigned roles.
    pub members: HashMap<String, Vec<String>>,
    /// Optional role/tree MCP tool allowlists. A role without one retains the
    /// legacy all-tools grant; once present, this is an allowlist, never a
    /// blacklist.
    pub role_tools: HashMap<(String, String), Vec<String>>,
    /// Explicit IdP group -> local roles mapping. A raw external group never
    /// grants access without this local policy declaration.
    pub groups: HashMap<String, Vec<String>>,
    /// Explicit repository sets for an authorized cross-repository review.
    /// A workspace never grants access: callers must already reach every tree.
    pub workspaces: HashMap<String, Vec<String>>,
    pub workspace_packages: HashMap<String, Vec<String>>,
}

impl Rights {
    pub fn tree(&self, name: &str) -> Option<&Tree> {
        self.trees.iter().find(|t| t.name == name)
    }

    /// Whether this user may reach this tree.
    ///
    /// Unknown user, unknown tree and ungranted tree are one answer on purpose:
    /// the caller must not be able to tell them apart. See `route`.
    pub fn may(&self, user: &str, tree: &str) -> bool {
        self.may_with_groups(user, &[], tree)
    }

    pub fn may_with_groups(&self, user: &str, groups: &[String], tree: &str) -> bool {
        self.grants
            .get(user)
            .is_some_and(|ts| ts.iter().any(|t| t == tree))
            || self.roles_for(user, groups).iter().any(|role| {
                self.roles
                    .get(role)
                    .is_some_and(|trees| trees.iter().any(|candidate| candidate == tree))
            })
    }

    fn roles_for(&self, user: &str, groups: &[String]) -> Vec<String> {
        let mut roles = self.members.get(user).cloned().unwrap_or_default();
        for group in groups {
            if let Some(mapped) = self.groups.get(group) {
                roles.extend(mapped.iter().cloned());
            }
        }
        roles.sort();
        roles.dedup();
        roles
    }

    pub fn is_admin_with_groups(&self, user: &str, groups: &[String]) -> bool {
        self.roles_for(user, groups)
            .iter()
            .any(|role| role == "admin")
    }

    pub fn visible_workspaces(&self, user: &str, groups: &[String]) -> Vec<(String, Vec<String>)> {
        let mut result: Vec<_> = self
            .workspaces
            .iter()
            .filter(|(_, trees)| {
                !trees.is_empty()
                    && trees
                        .iter()
                        .all(|tree| self.may_with_groups(user, groups, tree))
            })
            .map(|(name, trees)| (name.clone(), trees.clone()))
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    pub fn unique_workspace_for_tree(&self, tree: &str) -> Option<String> {
        let mut matches: Vec<String> = self
            .workspaces
            .iter()
            .filter(|(_, trees)| trees.iter().any(|candidate| candidate == tree))
            .map(|(name, _)| name.clone())
            .collect();
        matches.sort();
        matches.dedup();
        (matches.len() == 1).then(|| matches.remove(0))
    }

    #[cfg(test)]
    pub fn visible(&self, user: &str) -> Vec<&Tree> {
        self.trees
            .iter()
            .filter(|tree| self.may(user, &tree.name))
            .collect()
    }

    pub fn may_tool_with_groups(
        &self,
        user: &str,
        groups: &[String],
        tree: &str,
        tool: &str,
    ) -> bool {
        if self
            .grants
            .get(user)
            .is_some_and(|trees| trees.iter().any(|candidate| candidate == tree))
        {
            return true;
        }
        self.roles_for(user, groups).iter().any(|role| {
            if !self
                .roles
                .get(role)
                .is_some_and(|trees| trees.iter().any(|candidate| candidate == tree))
            {
                return false;
            }
            self.role_tools
                .get(&(role.clone(), tree.to_string()))
                .is_none_or(|tools| tools.iter().any(|candidate| candidate == tool))
        })
    }
}

/// Parses the rights file. A malformed line is skipped, never widened into a
/// grant that matches everything.
pub fn parse(text: &str) -> Rights {
    let mut r = Rights::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line
            .split('\t')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        match f.as_slice() {
            ["tree", name, addr, token] => {
                if !name.is_empty() && !addr.is_empty() && !token.is_empty() {
                    r.trees.push(Tree {
                        name: (*name).to_string(),
                        addr: (*addr).to_string(),
                        token: (*token).to_string(),
                    });
                }
            }
            ["grant", user, trees] => {
                let list = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.grants
                    .entry((*user).to_string())
                    .or_default()
                    .extend(list);
            }
            ["role", role, trees] => {
                let list = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.roles.entry((*role).to_string()).or_default().extend(list);
            }
            ["member", user, roles] => {
                let list = roles
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.members
                    .entry((*user).to_string())
                    .or_default()
                    .extend(list);
            }
            ["role-tool", role, tree, tools] => {
                let list = tools
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.role_tools
                    .entry(((*role).to_string(), (*tree).to_string()))
                    .or_default()
                    .extend(list);
            }
            ["group", group, roles] => {
                let list = roles
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.groups
                    .entry((*group).to_string())
                    .or_default()
                    .extend(list);
            }
            ["workspace", name, trees] => {
                let list = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                r.workspaces
                    .entry((*name).to_string())
                    .or_default()
                    .extend(list);
            }
            ["workspace-package", name, packages] => {
                r.workspace_packages
                    .entry((*name).to_string())
                    .or_default()
                    .extend(
                        packages
                            .split(',')
                            .map(str::trim)
                            .filter(|s| s.contains('@'))
                            .map(str::to_string),
                    );
            }
            _ => eprintln!("rights: ignoring malformed line: {line}"),
        }
    }
    r
}

/// Produces a deterministic, secret-free access-review document. It includes
/// policy declarations rather than inferred per-user permissions: an IdP group
/// can change outside this service, so pretending that a local snapshot is an
/// authoritative effective-membership list would be misleading to an auditor.
pub fn access_review(rights: &Rights) -> serde_json::Value {
    use serde_json::json;

    let mut trees: Vec<String> = rights.trees.iter().map(|tree| tree.name.clone()).collect();
    trees.sort();

    let mut direct_grants: Vec<serde_json::Value> = rights
        .grants
        .iter()
        .map(|(user, trees)| {
            let mut trees = trees.clone();
            trees.sort();
            trees.dedup();
            json!({"user": user, "trees": trees, "tool_access": "all"})
        })
        .collect();
    direct_grants.sort_by(|a, b| a["user"].as_str().cmp(&b["user"].as_str()));

    let mut role_names: Vec<String> = rights.roles.keys().cloned().collect();
    role_names.sort();
    let roles: Vec<serde_json::Value> = role_names
        .into_iter()
        .map(|role| {
            let mut trees = rights.roles.get(&role).cloned().unwrap_or_default();
            trees.sort();
            trees.dedup();
            let mut members: Vec<String> = rights
                .members
                .iter()
                .filter(|(_, roles)| roles.iter().any(|candidate| candidate == &role))
                .map(|(user, _)| user.clone())
                .collect();
            members.sort();
            let mut idp_groups: Vec<String> = rights
                .groups
                .iter()
                .filter(|(_, roles)| roles.iter().any(|candidate| candidate == &role))
                .map(|(group, _)| group.clone())
                .collect();
            idp_groups.sort();
            let tool_access: Vec<serde_json::Value> = trees
                .iter()
                .map(
                    |tree| match rights.role_tools.get(&(role.clone(), tree.clone())) {
                        Some(tools) => {
                            let mut tools = tools.clone();
                            tools.sort();
                            tools.dedup();
                            json!({"tree": tree, "mode": "allowlist", "tools": tools})
                        }
                        None => json!({"tree": tree, "mode": "all", "tools": []}),
                    },
                )
                .collect();
            json!({
                "role": role,
                "trees": trees,
                "local_members": members,
                "mapped_idp_groups": idp_groups,
                "tool_access": tool_access,
            })
        })
        .collect();

    json!({
        "schema": "glasir.access-review.v1",
        "trees": trees,
        "direct_grants": direct_grants,
        "roles": roles,
    })
}

/// Validation result for enterprise configuration audits and pre-flight checks.
#[derive(Debug, Default)]
pub struct RightsReport {
    pub tree_count: usize,
    pub user_count: usize,
    pub role_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl RightsReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validates a rights file thoroughly, checking line syntax, duplicates, and dangling grants.
pub fn validate_file(path: &Path) -> std::io::Result<RightsReport> {
    let text = std::fs::read_to_string(path)?;
    Ok(validate_text(&text))
}

pub fn validate_text(text: &str) -> RightsReport {
    let mut report = RightsReport::default();
    let mut tree_names = HashSet::new();
    let mut declared_grants: Vec<(usize, String, Vec<String>)> = Vec::new();
    let mut declared_roles: Vec<(usize, String, Vec<String>)> = Vec::new();
    let mut declared_members: Vec<(usize, String, Vec<String>)> = Vec::new();
    let mut declared_role_tools: Vec<(usize, String, String, Vec<String>)> = Vec::new();
    let mut declared_groups: Vec<(usize, String, Vec<String>)> = Vec::new();
    let mut declared_workspaces: Vec<(usize, String, Vec<String>)> = Vec::new();
    let mut declared_workspace_packages: Vec<(usize, String, Vec<String>)> = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        let line_num = idx + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let f: Vec<&str> = line
            .split('\t')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        match f.as_slice() {
            ["tree", name, addr, token] => {
                if name.contains('/') || name.contains('\\') || name.contains("..") {
                    report.errors.push(format!(
                        "line {line_num}: invalid tree name '{name}' (must not contain paths or '..')"
                    ));
                }
                if !addr.contains(':') {
                    report.errors.push(format!(
                        "line {line_num}: tree '{name}' address '{addr}' must be 'host:port'"
                    ));
                }
                if token.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: tree '{name}' has empty backend token"
                    ));
                }
                if !tree_names.insert((*name).to_string()) {
                    report.warnings.push(format!(
                        "line {line_num}: duplicate tree declaration for '{name}'"
                    ));
                }
            }
            ["grant", user, trees] => {
                let targets: Vec<String> = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();

                if targets.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: grant for user '{user}' has no target trees"
                    ));
                } else {
                    declared_grants.push((line_num, (*user).to_string(), targets));
                }
            }
            ["role", role, trees] => {
                let targets: Vec<String> = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if targets.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: role '{role}' has no target trees"
                    ));
                } else {
                    declared_roles.push((line_num, (*role).to_string(), targets));
                }
            }
            ["member", user, roles] => {
                let targets: Vec<String> = roles
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if targets.is_empty() {
                    report
                        .errors
                        .push(format!("line {line_num}: member '{user}' has no roles"));
                } else {
                    declared_members.push((line_num, (*user).to_string(), targets));
                }
            }
            ["role-tool", role, tree, tools] => {
                let targets: Vec<String> = tools
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if targets.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: role-tool policy for role '{role}' and tree '{tree}' has no tools"
                    ));
                } else {
                    declared_role_tools.push((
                        line_num,
                        (*role).to_string(),
                        (*tree).to_string(),
                        targets,
                    ));
                }
            }
            ["group", group, roles] => {
                let targets: Vec<String> = roles
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if targets.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: group '{group}' has no mapped roles"
                    ));
                } else {
                    declared_groups.push((line_num, (*group).to_string(), targets));
                }
            }
            ["workspace", name, trees] => {
                let targets: Vec<String> = trees
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if !crate::security::is_valid_identifier(name) || targets.is_empty() {
                    report.errors.push(format!(
                        "line {line_num}: workspace '{name}' is invalid or empty"
                    ));
                } else {
                    declared_workspaces.push((line_num, (*name).to_string(), targets));
                }
            }
            ["workspace-package", workspace, packages] => {
                let targets: Vec<String> = packages
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if !crate::security::is_valid_identifier(workspace)
                    || targets.is_empty()
                    || targets.iter().any(|p| p.split_once('@').is_none())
                {
                    report
                        .errors
                        .push(format!("line {line_num}: workspace-package is invalid"));
                } else {
                    declared_workspace_packages.push((line_num, (*workspace).to_string(), targets));
                }
            }
            _ => {
                report.errors.push(format!(
                    "line {line_num}: malformed directive (expected tree, grant, role, member, role-tool, group or workspace directive): {line}"
                ));
            }
        }
    }

    report.tree_count = tree_names.len();
    let mut users = HashSet::new();

    for (line_num, user, targets) in declared_grants {
        users.insert(user.clone());
        for target in targets {
            if !tree_names.contains(&target) {
                report.warnings.push(format!(
                    "line {line_num}: user '{user}' granted access to undefined tree '{target}'"
                ));
            }
        }
    }

    let role_names: HashSet<String> = declared_roles
        .iter()
        .map(|(_, role, _)| role.clone())
        .collect();
    report.role_count = role_names.len();
    for (line_num, role, targets) in declared_roles {
        for target in targets {
            if !tree_names.contains(&target) {
                report.warnings.push(format!(
                    "line {line_num}: role '{role}' grants undefined tree '{target}'"
                ));
            }
        }
    }
    for (line_num, user, roles) in declared_members {
        users.insert(user.clone());
        for role in roles {
            if !role_names.contains(&role) {
                report.errors.push(format!(
                    "line {line_num}: user '{user}' is assigned undefined role '{role}'"
                ));
            }
        }
    }
    for (line_num, role, tree, tools) in declared_role_tools {
        if !role_names.contains(&role) {
            report.errors.push(format!(
                "line {line_num}: tool policy references undefined role '{role}'"
            ));
        }
        if !tree_names.contains(&tree) {
            report.errors.push(format!(
                "line {line_num}: tool policy for role '{role}' references undefined tree '{tree}'"
            ));
        }
        for tool in tools {
            if !crate::security::is_valid_identifier(&tool) {
                report.errors.push(format!(
                    "line {line_num}: invalid MCP tool identifier '{tool}'"
                ));
            }
        }
    }
    let workspace_names: HashSet<String> = declared_workspaces
        .iter()
        .map(|(_, name, _)| name.clone())
        .collect();
    for (line_num, workspace, trees) in declared_workspaces {
        for tree in trees {
            if !tree_names.contains(&tree) {
                report.errors.push(format!(
                    "line {line_num}: workspace '{workspace}' references undefined tree '{tree}'"
                ));
            }
        }
    }
    for (line_num, workspace, _) in declared_workspace_packages {
        if !workspace_names.contains(&workspace) {
            report.errors.push(format!(
                "line {line_num}: workspace-package references undefined workspace '{workspace}'"
            ));
        }
    }
    for (line_num, group, roles) in declared_groups {
        for role in roles {
            if !role_names.contains(&role) {
                report.errors.push(format!(
                    "line {line_num}: group '{group}' maps to undefined role '{role}'"
                ));
            }
        }
    }

    report.user_count = users.len();
    report
}

/// The rights file, re-read when its mtime moves.
///
/// Same mechanism as `auth::Tokens` in the core, and for the same acceptance
/// criterion: revoking access must take effect without a restart. Stat per
/// request costs microseconds; parsing per request would cost more for nothing.
pub struct Watched {
    path: PathBuf,
    cache: Mutex<(Option<SystemTime>, std::sync::Arc<Rights>)>,
}

impl Watched {
    pub fn new(path: PathBuf) -> Watched {
        Watched {
            path,
            cache: Mutex::new((None, std::sync::Arc::new(Rights::default()))),
        }
    }

    pub fn current(&self) -> std::sync::Arc<Rights> {
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != mtime {
            let text = std::fs::read_to_string(&self.path).unwrap_or_default();
            let parsed = parse(&text);
            *cache = (mtime, std::sync::Arc::new(parsed));
        }
        cache.1.clone()
    }

    /// A control plane configured for mirrored permissions must deny rather
    /// than continue serving a stale mirror. The synchronizer refreshes the
    /// rights file atomically; its mtime is therefore the freshness lease.
    pub fn is_fresh(&self, max_age: std::time::Duration) -> bool {
        std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .and_then(|m| m.elapsed().map_err(std::io::Error::other))
            .map(|age| age <= max_age)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_valid_rights() {
        let text = "\
tree\talpha\t127.0.0.1:7001\tsecret-a
tree\tbeta\t127.0.0.1:7002\tsecret-b
grant\tanna\talpha
grant\tbruno\talpha,beta
";
        let rep = validate_text(text);
        assert!(rep.is_valid());
        assert_eq!(rep.tree_count, 2);
        assert_eq!(rep.user_count, 2);
        assert!(rep.warnings.is_empty());
    }

    #[test]
    fn roles_are_additive_and_unknown_roles_never_grant() {
        let rights = parse(
            "tree\talpha\t127.0.0.1:7001\tsecret\nrole\tdeveloper\talpha\nmember\tanna\tdeveloper\nmember\tbruno\tmissing\n",
        );
        assert!(rights.may("anna", "alpha"));
        assert!(!rights.may("bruno", "alpha"));
        let report = validate_text(
            "tree\talpha\t127.0.0.1:7001\tsecret\nrole\tdeveloper\talpha\nmember\tanna\tmissing\n",
        );
        assert!(!report.is_valid());
    }

    #[test]
    fn role_tool_allowlist_is_fail_closed_without_changing_direct_grants() {
        let rights = parse(
            "tree\talpha\t127.0.0.1:7001\tsecret\nrole\treader\talpha\nrole-tool\treader\talpha\tquery_graph,overview\nmember\tanna\treader\ngrant\tbruno\talpha\n",
        );
        assert!(rights.may_tool_with_groups("anna", &[], "alpha", "query_graph"));
        assert!(!rights.may_tool_with_groups("anna", &[], "alpha", "impact"));
        assert!(rights.may_tool_with_groups("bruno", &[], "alpha", "impact"));
    }

    #[test]
    fn idp_groups_need_an_explicit_local_role_mapping() {
        let rights = parse(
            "tree\talpha\t127.0.0.1:7001\tsecret\nrole\tdeveloper\talpha\ngroup\tengineering\tdeveloper\n",
        );
        assert!(rights.may_with_groups("oidc-user", &["engineering".into()], "alpha"));
        assert!(!rights.may_with_groups("oidc-user", &["unmapped".into()], "alpha"));
    }

    #[test]
    fn validate_checks_group_and_tool_policy_references() {
        let report = validate_text(
            "tree\talpha\t127.0.0.1:7001\tsecret\nrole\treader\talpha\nrole-tool\tmissing\tghost\tquery_graph,bad tool\ngroup\tengineering\tmissing\n",
        );
        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("undefined role 'missing'"))
        );
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("undefined tree 'ghost'"))
        );
        assert!(report.errors.iter().any(|e| e.contains("invalid MCP tool")));
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("group 'engineering'"))
        );
    }

    #[test]
    fn access_review_is_deterministic_and_never_exports_tree_tokens() {
        let rights = parse(
            "tree\tbeta\t127.0.0.1:7002\tsecret-b\ntree\talpha\t127.0.0.1:7001\tsecret-a\ngrant\tzara\tbeta,alpha\nrole\tdeveloper\talpha\nmember\tanna\tdeveloper\ngroup\tengineering\tdeveloper\nrole-tool\tdeveloper\talpha\tquery_graph,get_node\n",
        );
        let report = access_review(&rights).to_string();
        assert!(report.contains("glasir.access-review.v1"));
        assert!(report.contains("mapped_idp_groups"));
        assert!(report.contains("query_graph"));
        assert!(report.contains("allowlist"));
        assert!(!report.contains("secret-a"));
        assert!(report.find("alpha").unwrap() < report.find("beta").unwrap());
    }

    #[test]
    fn validate_detects_errors_and_dangling_grants() {
        let text = "\
tree\tinvalid/name\t127.0.0.1:7001\tsec
tree\talpha\tbad_addr_no_port\tsec
grant\tanna\tghost_tree
malformed line
";
        let rep = validate_text(text);
        assert!(!rep.is_valid());
        assert!(rep.errors.iter().any(|e| e.contains("invalid tree name")));
        assert!(rep.errors.iter().any(|e| e.contains("must be 'host:port'")));
        assert!(rep.errors.iter().any(|e| e.contains("malformed directive")));
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("undefined tree 'ghost_tree'"))
        );
    }
}
