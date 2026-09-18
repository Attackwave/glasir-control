//! Four-eyes policy proposals. Active rights remain one atomic TSV source.
use std::path::{Path, PathBuf};

pub fn proposal_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

pub fn create(
    dir: &Path,
    id: &str,
    author: &str,
    rights: &str,
    active: &Path,
) -> Result<(), String> {
    let validation = crate::rights::validate_text(rights);
    if !validation.is_valid() {
        return Err(validation.errors.join("; "));
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let current = std::fs::read_to_string(active).map_err(|e| e.to_string())?;
    let value = serde_json::json!({"schema":"glasir.policy-proposal.v1","id":id,"author":author,"created_at":crate::auth::now(),"rights":rights,"rights_sha256":crate::auth::sha256_hex(rights.as_bytes()),"base_sha256":crate::auth::sha256_hex(current.as_bytes()),"state":"pending"});
    let path = proposal_path(dir, id);
    if path.exists() {
        return Err("proposal already exists".into());
    }
    std::fs::write(path, serde_json::to_vec(&value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn approve(dir: &Path, id: &str, approver: &str, active: &Path) -> Result<(), String> {
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

pub fn read(dir: &Path, id: &str, active: &Path) -> Result<serde_json::Value, String> {
    let proposal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proposal_path(dir, id)).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let current = std::fs::read_to_string(active).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"proposal":proposal,"active_rights":current}))
}
