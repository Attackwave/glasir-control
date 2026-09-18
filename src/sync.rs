//! Code-Host Permission Synchronization & Webhook Receiver.
//!
//! Mirrors repository collaborator permissions from code hosts (GitHub, GitLab)
//! into `rights.tsv`.
//!
//! **Architectural Principles (Stage 5):**
//! - **Mirrored, not created:** Permissions originate from the code host.
//! - **Fail-closed:** Stale or unverified permissions must not grant access.
//! - **Atomic live-updates:** Permissions are written to a temp file and renamed
//!   atomically, causing `rights::Watched` to hot-reload immediately without restarts.
//! - **Cryptographic webhook validation:** Uses constant-time HMAC-SHA256 (RFC 2104).
//! - **Zero external dependencies:** Self-contained JSON extraction and crypto.

use crate::auth;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Computes HMAC-SHA256 per RFC 2104.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hash = auth::sha256(key);
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = auth::sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    auth::sha256(&outer)
}

pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let h = hmac_sha256(key, msg);
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time comparison to prevent timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verifies GitHub webhook signature (X-Hub-Signature-256: sha256=<hex>).
pub fn verify_github_signature(secret: &str, body: &[u8], header: Option<&str>) -> bool {
    let Some(header) = header else { return false };
    let Some(expected_hex) = header.strip_prefix("sha256=") else {
        return false;
    };
    let computed_hex = hmac_sha256_hex(secret.as_bytes(), body);
    constant_time_eq(computed_hex.as_bytes(), expected_hex.as_bytes())
}

/// Verifies GitLab webhook secret token (X-Gitlab-Token: <secret>).
pub fn verify_gitlab_token(secret: &str, header: Option<&str>) -> bool {
    let Some(header) = header else { return false };
    constant_time_eq(secret.as_bytes(), header.trim().as_bytes())
}

/// Sync action to apply to the rights database.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum SyncAction {
    Grant { user: String, tree: String },
    Revoke { user: String, tree: String },
    SetTreeGrants { tree: String, users: Vec<String> },
}

/// Configuration for code-host repository-to-tree mappings and secrets.
#[derive(Clone, Debug, Default)]
pub struct SyncConfig {
    /// Maps "provider:owner/repo" or "repo_name" to internal tree name.
    pub repo_mapping: HashMap<String, String>,
    pub github_secret: Option<String>,
    pub gitlab_secret: Option<String>,
    pub github_token: Option<String>,
    pub gitlab_token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReviewEvent {
    pub provider: &'static str,
    pub repository: String,
    pub number: u64,
    pub revision: String,
}

pub fn github_review_event(payload: &str) -> Result<Option<ReviewEvent>, String> {
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| "malformed github pull request payload".to_string())?;
    let action = value["action"].as_str().unwrap_or("");
    if !matches!(action, "opened" | "synchronize" | "reopened") {
        return Ok(None);
    }
    Ok(Some(ReviewEvent {
        provider: "github",
        repository: value["repository"]["full_name"]
            .as_str()
            .ok_or("missing repository.full_name")?
            .to_string(),
        number: value["number"]
            .as_u64()
            .ok_or("missing pull request number")?,
        revision: value["pull_request"]["head"]["sha"]
            .as_str()
            .ok_or("missing head sha")?
            .to_string(),
    }))
}

pub fn gitlab_review_event(payload: &str) -> Result<Option<ReviewEvent>, String> {
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| "malformed gitlab merge request payload".to_string())?;
    let attrs = &value["object_attributes"];
    let action = attrs["action"].as_str().unwrap_or("");
    if !matches!(action, "open" | "reopen" | "update") {
        return Ok(None);
    }
    Ok(Some(ReviewEvent {
        provider: "gitlab",
        repository: value["project"]["path_with_namespace"]
            .as_str()
            .ok_or("missing project.path_with_namespace")?
            .to_string(),
        number: attrs["iid"].as_u64().ok_or("missing merge request iid")?,
        revision: attrs["last_commit"]["id"]
            .as_str()
            .ok_or("missing last commit id")?
            .to_string(),
    }))
}

/// Publishes one completed check for a PR head SHA. The caller supplies only a
/// bounded summary; source, identities and service tokens never leave Glasir.
pub fn github_check(repo: &str, sha: &str, summary: &str, token: &str) -> Result<(), String> {
    if repo.is_empty() || sha.len() > 128 || summary.len() > 60_000 {
        return Err("invalid check payload".into());
    }
    let body = serde_json::json!({"name":"Glasir impact","head_sha":sha,"status":"completed","conclusion":"success","output":{"title":"Glasir cross-repository impact","summary":summary}});
    ureq::post(&format!("https://api.github.com/repos/{repo}/check-runs"))
        .set("Accept", "application/vnd.github+json")
        .set("User-Agent", "glasir-control")
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(body)
        .map_err(|e| format!("GitHub check run for {repo}: {e}"))?;
    Ok(())
}

pub fn gitlab_commit_status(
    project: &str,
    sha: &str,
    summary: &str,
    token: &str,
) -> Result<(), String> {
    if project.is_empty() || sha.len() > 128 || summary.len() > 4_000 {
        return Err("invalid status payload".into());
    }
    let project = percent_encode(project);
    ureq::post(&format!(
        "https://gitlab.com/api/v4/projects/{project}/statuses/{sha}"
    ))
    .set("PRIVATE-TOKEN", token)
    .send_form(&[
        ("state", "success"),
        ("name", "glasir-impact"),
        ("description", summary),
    ])
    .map_err(|e| format!("GitLab status for {project}: {e}"))?;
    Ok(())
}

impl SyncConfig {
    /// An unmapped webhook is deliberately ignored. Falling back to a bare
    /// repository name makes `acme/api` and `other/api` indistinguishable and
    /// can grant access to the wrong tree.
    pub fn resolve_tree(&self, repo: &str) -> Option<String> {
        self.repo_mapping.get(repo).cloned()
    }
}

/// Reads explicit mappings of `github:owner/repo` or `gitlab:group/path` to a
/// Glasir tree. Webhook signatures prove who sent a payload, not which local
/// tree that payload is allowed to administer, so this mapping is mandatory.
pub fn load_repo_mapping(path: &Path) -> std::io::Result<HashMap<String, String>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((repo, tree)) = line.split_once('\t') else {
            return Err(std::io::Error::other(format!(
                "{}:{}: expected <provider:namespace/repository> TAB <tree>",
                path.display(),
                line_no + 1
            )));
        };
        if !repo.starts_with("github:") && !repo.starts_with("gitlab:") {
            return Err(std::io::Error::other(format!(
                "{}:{}: provider must be github: or gitlab:",
                path.display(),
                line_no + 1
            )));
        }
        if !crate::security::is_valid_identifier(tree.trim()) {
            return Err(std::io::Error::other(format!(
                "{}:{}: invalid tree name",
                path.display(),
                line_no + 1
            )));
        }
        if out
            .insert(repo.trim().to_string(), tree.trim().to_string())
            .is_some()
        {
            return Err(std::io::Error::other(format!(
                "{}:{}: duplicate repository mapping",
                path.display(),
                line_no + 1
            )));
        }
    }
    Ok(out)
}

/// Processes a GitHub Webhook JSON payload.
pub fn handle_github_webhook(
    event: &str,
    payload: &str,
    cfg: &SyncConfig,
) -> Result<Option<SyncAction>, String> {
    match event {
        "member" => {
            let action = extract_json_field(payload, "action")
                .ok_or_else(|| "missing action in member event".to_string())?;
            let user = extract_nested_field(payload, &["member", "login"])
                .ok_or_else(|| "missing member.login in webhook".to_string())?;
            let repo = extract_nested_field(payload, &["repository", "full_name"])
                .ok_or_else(|| "missing repository.full_name in webhook".to_string())?;
            let Some(tree) = cfg.resolve_tree(&format!("github:{repo}")) else {
                return Ok(None);
            };

            if !crate::security::is_valid_identifier(&user)
                || !crate::security::is_valid_identifier(&tree)
            {
                return Err(format!(
                    "invalid identifier in github webhook: user '{user}', tree '{tree}'"
                ));
            }

            if action == "added" {
                Ok(Some(SyncAction::Grant { user, tree }))
            } else if action == "removed" || action == "deleted" {
                Ok(Some(SyncAction::Revoke { user, tree }))
            } else {
                Ok(None)
            }
        }
        "ping" => Ok(None),
        _ => Ok(None),
    }
}

/// Processes a GitLab Webhook JSON payload.
pub fn handle_gitlab_webhook(
    _event: &str,
    payload: &str,
    cfg: &SyncConfig,
) -> Result<Option<SyncAction>, String> {
    let event_name = extract_json_field(payload, "event_name")
        .or_else(|| extract_json_field(payload, "object_kind"))
        .unwrap_or_default();

    if event_name == "user_add_to_team" || event_name == "user_add_to_group" {
        let user = extract_json_field(payload, "user_username")
            .or_else(|| extract_json_field(payload, "username"))
            .ok_or_else(|| "missing username in gitlab event".to_string())?;
        let group = extract_json_field(payload, "group_path")
            .ok_or_else(|| "missing group_path in gitlab member webhook".to_string())?;
        let Some(tree) = cfg.resolve_tree(&format!("gitlab:{group}")) else {
            return Ok(None);
        };
        if !crate::security::is_valid_identifier(&user)
            || !crate::security::is_valid_identifier(&tree)
        {
            return Err(format!(
                "invalid identifier in gitlab webhook: user '{user}', tree '{tree}'"
            ));
        }
        Ok(Some(SyncAction::Grant { user, tree }))
    } else if event_name == "user_remove_from_team" || event_name == "user_remove_from_group" {
        let user = extract_json_field(payload, "user_username")
            .or_else(|| extract_json_field(payload, "username"))
            .ok_or_else(|| "missing username in gitlab event".to_string())?;
        let group = extract_json_field(payload, "group_path")
            .ok_or_else(|| "missing group_path in gitlab member webhook".to_string())?;
        let Some(tree) = cfg.resolve_tree(&format!("gitlab:{group}")) else {
            return Ok(None);
        };
        if !crate::security::is_valid_identifier(&user)
            || !crate::security::is_valid_identifier(&tree)
        {
            return Err(format!(
                "invalid identifier in gitlab webhook: user '{user}', tree '{tree}'"
            ));
        }
        Ok(Some(SyncAction::Revoke { user, tree }))
    } else {
        Ok(None)
    }
}

/// Atomically modifies the `rights.tsv` file, preserving existing trees and comments.
pub fn apply_sync_action(rights_path: &Path, action: &SyncAction) -> std::io::Result<()> {
    apply_sync_actions(rights_path, std::slice::from_ref(action))
}

/// Replaces a complete set of tree grants in one atomic write. A partial
/// code-host reconciliation is worse than a failed one: it can preserve
/// access that the source of truth has already revoked.
pub fn apply_sync_actions(rights_path: &Path, actions: &[SyncAction]) -> std::io::Result<()> {
    for action in actions {
        match action {
            SyncAction::Grant { user, tree } | SyncAction::Revoke { user, tree } => {
                if !crate::security::is_valid_identifier(user)
                    || !crate::security::is_valid_identifier(tree)
                {
                    return Err(std::io::Error::other("invalid identifier in sync action"));
                }
            }
            SyncAction::SetTreeGrants { tree, users } => {
                if !crate::security::is_valid_identifier(tree)
                    || users
                        .iter()
                        .any(|u| !crate::security::is_valid_identifier(u))
                {
                    return Err(std::io::Error::other(
                        "invalid identifier in set-tree-grants",
                    ));
                }
            }
        }
    }

    let content = std::fs::read_to_string(rights_path).unwrap_or_default();
    let updated = actions.iter().fold(content, |current, action| {
        mutate_rights_content(&current, action)
    });

    let tmp_path = PathBuf::from(format!(
        "{}.tmp.{}",
        rights_path.display(),
        std::process::id()
    ));

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&tmp_path)?;
    file.write_all(updated.as_bytes())?;
    file.flush()?;
    drop(file);

    std::fs::rename(tmp_path, rights_path)
}

/// Full source-of-truth reconciliation. Tokens arrive only through the
/// process environment; neither configuration nor audit logs contain them.
pub fn reconcile_remote(
    rights_path: &Path,
    mapping: &HashMap<String, String>,
    github_token: Option<&str>,
    gitlab_token: Option<&str>,
) -> Result<usize, String> {
    let mut desired: HashMap<String, HashSet<String>> = HashMap::new();
    for (source, tree) in mapping {
        let users = if let Some(repo) = source.strip_prefix("github:") {
            let token =
                github_token.ok_or("GitHub mapping configured but no GitHub token available")?;
            github_members(repo, token)?
        } else if let Some(group) = source.strip_prefix("gitlab:") {
            let token =
                gitlab_token.ok_or("GitLab mapping configured but no GitLab token available")?;
            gitlab_members(group, token)?
        } else {
            return Err(format!("unsupported repository mapping: {source}"));
        };
        desired.entry(tree.clone()).or_default().extend(users);
    }
    let actions: Vec<_> = desired
        .into_iter()
        .map(|(tree, users)| SyncAction::SetTreeGrants {
            tree,
            users: users.into_iter().collect(),
        })
        .collect();
    apply_sync_actions(rights_path, &actions).map_err(|e| e.to_string())?;
    Ok(actions.len())
}

fn github_members(repo: &str, token: &str) -> Result<Vec<String>, String> {
    let mut users = Vec::new();
    for page in 1..=1000 {
        let url = format!(
            "https://api.github.com/repos/{repo}/collaborators?affiliation=direct&per_page=100&page={page}"
        );
        let response = ureq::get(&url)
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "glasir-control")
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|e| format!("GitHub collaborators request for {repo}: {e}"))?;
        let page_users: Vec<serde_json::Value> = response
            .into_json()
            .map_err(|e| format!("GitHub collaborators response for {repo}: {e}"))?;
        let count = page_users.len();
        for user in page_users {
            let login = user["login"]
                .as_str()
                .ok_or("GitHub collaborator without login")?;
            if crate::security::is_valid_identifier(login) {
                users.push(login.to_string());
            }
        }
        if count < 100 {
            users.sort();
            users.dedup();
            return Ok(users);
        }
    }
    Err(format!(
        "GitHub collaborators pagination for {repo} exceeded limit"
    ))
}

fn gitlab_members(group: &str, token: &str) -> Result<Vec<String>, String> {
    let group = percent_encode(group);
    let mut users = Vec::new();
    for page in 1..=1000 {
        let url = format!(
            "https://gitlab.com/api/v4/groups/{group}/members/all?per_page=100&page={page}"
        );
        let response = ureq::get(&url)
            .set("PRIVATE-TOKEN", token)
            .call()
            .map_err(|e| format!("GitLab members request: {e}"))?;
        let page_users: Vec<serde_json::Value> = response
            .into_json()
            .map_err(|e| format!("GitLab members response: {e}"))?;
        let count = page_users.len();
        for user in page_users {
            let name = user["username"]
                .as_str()
                .ok_or("GitLab member without username")?;
            if crate::security::is_valid_identifier(name) {
                users.push(name.to_string());
            }
        }
        if count < 100 {
            users.sort();
            users.dedup();
            return Ok(users);
        }
    }
    Err("GitLab members pagination exceeded limit".into())
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

/// Modifies text representation of `rights.tsv`.
pub fn mutate_rights_content(text: &str, action: &SyncAction) -> String {
    let mut tree_lines = Vec::new();
    let mut comments = Vec::new();
    let mut user_grants: HashMap<String, HashSet<String>> = HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            comments.push(line.to_string());
            continue;
        }

        let parts: Vec<&str> = trimmed
            .split('\t')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        match parts.as_slice() {
            ["tree", ..] => tree_lines.push(line.to_string()),
            ["grant", user, trees] => {
                let entry = user_grants.entry((*user).to_string()).or_default();
                for t in trees.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    entry.insert(t.to_string());
                }
            }
            _ => comments.push(line.to_string()),
        }
    }

    match action {
        SyncAction::Grant { user, tree } => {
            user_grants
                .entry(user.clone())
                .or_default()
                .insert(tree.clone());
        }
        SyncAction::Revoke { user, tree } => {
            if let Some(set) = user_grants.get_mut(user) {
                set.remove(tree);
            }
        }
        SyncAction::SetTreeGrants { tree, users } => {
            let allowed_users: HashSet<&str> = users.iter().map(|s| s.as_str()).collect();
            // Remove tree from all users
            for (u, set) in user_grants.iter_mut() {
                if !allowed_users.contains(u.as_str()) {
                    set.remove(tree);
                }
            }
            // Add tree to specified users
            for u in users {
                user_grants
                    .entry(u.clone())
                    .or_default()
                    .insert(tree.clone());
            }
        }
    }

    let mut out = String::new();
    for c in comments {
        out.push_str(&c);
        out.push('\n');
    }
    for t in tree_lines {
        out.push_str(&t);
        out.push('\n');
    }

    let mut sorted_users: Vec<_> = user_grants.into_iter().collect();
    sorted_users.sort_by(|a, b| a.0.cmp(&b.0));

    for (user, trees) in sorted_users {
        let mut tree_list: Vec<_> = trees.into_iter().collect();
        tree_list.sort();
        if !tree_list.is_empty() {
            out.push_str(&format!("grant\t{}\t{}\n", user, tree_list.join(",")));
        }
    }

    out
}

/// Lightweight JSON key-value extraction without third-party crates.
pub fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let mut search_from = 0;
    while let Some(rel_idx) = json[search_from..].find(&needle) {
        let idx = search_from + rel_idx;
        let rest = &json[idx + needle.len()..];
        if let Some(colon_idx) = rest.find(':') {
            if !rest[..colon_idx].trim().is_empty() {
                search_from = idx + needle.len();
                continue;
            }
            let val_part = rest[colon_idx + 1..].trim_start();
            if let Some(after_quote) = val_part.strip_prefix('"') {
                let mut end_quote = 0;
                let mut escaped = false;
                for (i, c) in after_quote.char_indices() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if c == '\\' {
                        escaped = true;
                        continue;
                    }
                    if c == '"' {
                        end_quote = i;
                        break;
                    }
                }
                return Some(after_quote[..end_quote].to_string());
            } else {
                let end = val_part
                    .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
                    .unwrap_or(val_part.len());
                return Some(val_part[..end].trim().to_string());
            }
        }
        search_from = idx + needle.len();
    }
    None
}

/// Extracts a nested field value by walking path components.
pub fn extract_nested_field(json: &str, path: &[&str]) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let mut current_slice = json;
    for &key in &path[..path.len() - 1] {
        let needle = format!("\"{}\"", key);
        let idx = current_slice.find(&needle)?;
        let rest = &current_slice[idx + needle.len()..];
        let obj_start = rest.find('{')?;
        current_slice = &rest[obj_start..];
    }
    extract_json_field(current_slice, path.last()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_matches_rfc4231_vector() {
        // RFC 4231 Test Case 2 (Key = "Jefe", Data = "what do ya want for nothing?")
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hmac_sha256_hex(key, data), expected);
    }

    #[test]
    fn test_github_webhook_verification() {
        let secret = "test-webhook-secret";
        let body = b"{\"action\":\"added\",\"member\":{\"login\":\"anna\"},\"repository\":{\"name\":\"alpha\"}}";
        let sig = format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), body));

        assert!(verify_github_signature(secret, body, Some(&sig)));
        assert!(!verify_github_signature("wrong-secret", body, Some(&sig)));
        assert!(!verify_github_signature(
            secret,
            body,
            Some("sha256=invalidhex")
        ));
        assert!(!verify_github_signature(secret, body, None));
    }

    #[test]
    fn github_pull_request_event_is_bounded_and_explicit() {
        let payload = r#"{"action":"synchronize","number":7,"repository":{"full_name":"acme/payments"},"pull_request":{"head":{"sha":"abc123"}}}"#;
        let event = github_review_event(payload).unwrap().unwrap();
        assert_eq!(event.repository, "acme/payments");
        assert_eq!(event.number, 7);
        assert_eq!(event.revision, "abc123");
        assert!(
            github_review_event(r#"{"action":"closed"}"#)
                .unwrap()
                .is_none()
        );
        assert!(github_review_event(r#"{"action":"opened"}"#).is_err());
    }

    #[test]
    fn gitlab_merge_request_event_is_bounded_and_explicit() {
        let payload = r#"{"object_attributes":{"action":"update","iid":8,"last_commit":{"id":"def456"}},"project":{"path_with_namespace":"acme/payments"}}"#;
        let event = gitlab_review_event(payload).unwrap().unwrap();
        assert_eq!(event.provider, "gitlab");
        assert_eq!(event.number, 8);
        assert!(
            gitlab_review_event(r#"{"object_attributes":{"action":"close"}}"#)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_gitlab_webhook_verification() {
        let secret = "gitlab-token-123";
        assert!(verify_gitlab_token(secret, Some("gitlab-token-123")));
        assert!(!verify_gitlab_token(secret, Some("wrong-token")));
        assert!(!verify_gitlab_token(secret, None));
    }

    #[test]
    fn test_github_member_added_and_removed() {
        let cfg = SyncConfig {
            repo_mapping: [("github:acme/alpha".into(), "alpha".into())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let payload_add = r#"{"action":"added","member":{"login":"clara"},"repository":{"full_name":"acme/alpha"}}"#;
        let action = handle_github_webhook("member", payload_add, &cfg).unwrap();
        assert_eq!(
            action,
            Some(SyncAction::Grant {
                user: "clara".into(),
                tree: "alpha".into(),
            })
        );

        let payload_rem = r#"{"action":"removed","member":{"login":"clara"},"repository":{"full_name":"acme/alpha"}}"#;
        let action_rem = handle_github_webhook("member", payload_rem, &cfg).unwrap();
        assert_eq!(
            action_rem,
            Some(SyncAction::Revoke {
                user: "clara".into(),
                tree: "alpha".into(),
            })
        );
    }

    #[test]
    fn test_mutate_rights_content() {
        let initial = "\
# rights file
tree\talpha\t127.0.0.1:7001\tsecret-a
grant\tanna\talpha
";
        let updated = mutate_rights_content(
            initial,
            &SyncAction::Grant {
                user: "bruno".into(),
                tree: "alpha".into(),
            },
        );
        assert!(updated.contains("grant\tanna\talpha"));
        assert!(updated.contains("grant\tbruno\talpha"));

        let revoked = mutate_rights_content(
            &updated,
            &SyncAction::Revoke {
                user: "anna".into(),
                tree: "alpha".into(),
            },
        );
        assert!(!revoked.contains("grant\tanna"));
        assert!(revoked.contains("grant\tbruno\talpha"));

        let set_full = mutate_rights_content(
            &revoked,
            &SyncAction::SetTreeGrants {
                tree: "alpha".into(),
                users: vec!["doris".into(), "elena".into()],
            },
        );
        assert!(!set_full.contains("grant\tbruno\talpha"));
        assert!(set_full.contains("grant\tdoris\talpha"));
        assert!(set_full.contains("grant\telena\talpha"));
    }
}
