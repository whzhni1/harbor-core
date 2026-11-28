//! Path handling and safety, mirroring the ucode implementation's semantics.

pub const SYSTEM_FOLDER_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/proc",
    "/dev",
    "/etc",
    "/usr",
    "/sys",
    "/lib64",
    "/overlay",
    "/rom",
    "/www/cgi-bin",
];

static TMP_JOURNAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn init_tmp_journal(state_dir: &str) {
    let _ = TMP_JOURNAL.set(format!("{state_dir}/tmp-journal"));
}

pub fn journal_tmp(path: &str) {
    if let Some(journal) = TMP_JOURNAL.get() {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal)
        {
            let _ = writeln!(file, "{path}");
        }
    }
}

pub fn cleanup_tmp_journal() {
    let Some(journal) = TMP_JOURNAL.get() else {
        return;
    };
    let Ok(content) = std::fs::read_to_string(journal) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.ends_with(".harbor-stage") {
            continue;
        }
        let name = std::path::Path::new(line)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.contains(".harbor-") {
            continue;
        }
        if std::path::Path::new(line).is_dir() {
            let _ = std::fs::remove_dir_all(line);
        } else {
            let _ = std::fs::remove_file(line);
        }
    }
    let _ = std::fs::remove_file(journal);
}

pub fn normalize_path(path: &str) -> Option<String> {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

pub fn join_path(base: &str, name: &str) -> String {
    if base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Join an upload-relative path below a base after normalizing separators and
/// rejecting attempts to traverse above that base.
pub fn safe_join_relative(dir: &str, relative: &str) -> Option<String> {
    let cleaned = relative.replace('\\', "/");
    let normalized = normalize_path(&format!("/{cleaned}"))?;
    if normalized == "/" {
        return None;
    }
    let parts: Vec<&str> = normalized.trim_start_matches('/').split('/').collect();
    if parts.iter().any(|part| !valid_rename_name(part)) {
        return None;
    }
    Some(
        parts
            .iter()
            .fold(dir.to_string(), |base, part| join_path(&base, part)),
    )
}

pub fn parent_path(path: &str) -> Option<String> {
    let n = normalize_path(path)?;
    if n == "/" {
        return None;
    }
    let idx = n.rfind('/').unwrap_or(0);
    if idx == 0 {
        Some("/".to_string())
    } else {
        Some(n[..idx].to_string())
    }
}

pub fn path_name(path: &str) -> String {
    match normalize_path(path) {
        None => "/".to_string(),
        Some(n) if n == "/" => "/".to_string(),
        Some(n) => n.rsplit('/').next().unwrap_or("").to_string(),
    }
}

pub fn file_extension(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or("");
    match name.rfind('.') {
        Some(idx) if idx + 1 < name.len() => {
            let ext = &name[idx + 1..];
            if ext.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                ext.to_ascii_lowercase()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

pub fn system_path_scope(path: &str) -> Option<String> {
    let normalized = normalize_path(path)?;
    SYSTEM_FOLDER_ROOTS
        .iter()
        .filter(|root| {
            let root_path = **root;
            normalized.as_str() == root_path
                || (normalized.len() > root_path.len()
                    && normalized.starts_with(root_path)
                    && normalized.as_bytes()[root_path.len()] == b'/')
        })
        .max_by_key(|root| root.len())
        .map(|root| (*root).to_string())
}

pub fn is_system_path(path: &str) -> bool {
    system_path_scope(path).is_some()
}

pub fn valid_component(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.contains('/') || name.contains('\0') {
        return false;
    }
    name.len() <= 255
}

pub fn valid_rename_name(name: &str) -> bool {
    if !valid_component(name) || name.contains('\\') {
        return false;
    }
    !name.chars().any(|c| (c as u32) < 32 || (c as u32) == 127)
}

pub fn is_descendant(root: &str, path: &str) -> bool {
    if root == "/" {
        return path.starts_with('/');
    }
    path == root
        || (path.len() > root.len()
            && path.starts_with(root)
            && path.as_bytes()[root.len()] == b'/')
}

pub fn canonical(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Resolve an existing path fully, or resolve its nearest existing ancestor
/// and append the not-yet-created suffix. This makes root/system policy checks
/// account for symlinked parents of new files and directories.
pub fn canonical_for_policy(path: &str) -> Option<String> {
    let normalized = normalize_path(path)?;
    if let Some(resolved) = canonical(&normalized) {
        return normalize_path(&resolved);
    }

    let mut cursor = std::path::PathBuf::from(&normalized);
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(&cursor) {
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return normalize_path(resolved.to_string_lossy().as_ref());
        }
        let component = cursor.file_name()?.to_os_string();
        suffix.push(component);
        if !cursor.pop() {
            return None;
        }
    }
}

pub fn root_policy_error(policy: crate::state::RootPolicy) -> &'static str {
    match policy {
        crate::state::RootPolicy::Allowlist => "Path is outside the configured root whitelist",
        crate::state::RootPolicy::Denylist => "Path is inside a configured blocked directory",
        crate::state::RootPolicy::Unrestricted => "Path access is blocked",
    }
}

pub fn path_allowed_by_policy(
    policy: crate::state::RootPolicy,
    roots: &[String],
    excluded_roots: &[String],
    path: &str,
) -> bool {
    match policy {
        crate::state::RootPolicy::Unrestricted => true,
        crate::state::RootPolicy::Allowlist => !roots.is_empty() && within_roots(roots, path),
        crate::state::RootPolicy::Denylist => !within_roots(excluded_roots, path),
    }
}

pub fn is_valid_upload_base(st: &crate::state::AppState, dir: &str, system_access: bool) -> bool {
    let actual = canonical(dir).unwrap_or_else(|| dir.to_string());
    let policy = st.root_policy_config();
    if !path_allowed_by_policy(
        policy.policy,
        &policy.roots,
        &policy.excluded_roots,
        &actual,
    ) {
        return false;
    }
    let meta = crate::meta::stat(&actual);
    let is_dir = meta
        .map(|m| m.kind == crate::meta::Kind::Directory)
        .unwrap_or(false);
    if !is_dir {
        return false;
    }
    system_access || (!is_system_path(dir) && !is_system_path(&actual))
}

pub fn within_roots(roots: &[String], resolved: &str) -> bool {
    if roots.is_empty() {
        return true;
    }
    roots.iter().any(|r| is_descendant(r, resolved))
}

pub fn encode_rfc5987(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "-._~".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn quote_header_filename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c == '"' || c == '\\' || (c as u32) < 32 || (c as u32) > 126 {
                '_'
            } else {
                c
            }
        })
        .collect();
    format!(
        "filename=\"{sanitized}\"; filename*=UTF-8''{}",
        encode_rfc5987(name)
    )
}

pub fn basename_checked(path: &str) -> String {
    path_name(path)
}

#[cfg(test)]
mod root_policy_tests {
    use super::{canonical_for_policy, path_allowed_by_policy};
    use crate::state::RootPolicy;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn root_policy_modes_apply_to_exact_paths_and_descendants() {
        let allowed = vec!["/srv/files".to_string()];
        let blocked = vec!["/srv/private".to_string()];
        assert!(path_allowed_by_policy(
            RootPolicy::Unrestricted,
            &[],
            &[],
            "/etc/passwd"
        ));
        assert!(path_allowed_by_policy(
            RootPolicy::Allowlist,
            &allowed,
            &[],
            "/srv/files/sub/file"
        ));
        assert!(!path_allowed_by_policy(
            RootPolicy::Allowlist,
            &allowed,
            &[],
            "/srv/other/file"
        ));
        assert!(!path_allowed_by_policy(
            RootPolicy::Allowlist,
            &[],
            &[],
            "/srv/files"
        ));
        assert!(!path_allowed_by_policy(
            RootPolicy::Denylist,
            &[],
            &blocked,
            "/srv/private"
        ));
        assert!(!path_allowed_by_policy(
            RootPolicy::Denylist,
            &[],
            &blocked,
            "/srv/private/secret"
        ));
        assert!(path_allowed_by_policy(
            RootPolicy::Denylist,
            &[],
            &blocked,
            "/srv/public"
        ));
    }

    #[test]
    fn prospective_path_policy_resolution_follows_existing_symlink_parents() {
        let base = std::env::temp_dir().join(format!("harbor-path-policy-{}", std::process::id()));
        let inside = base.join("inside");
        let outside = base.join("outside");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, inside.join("alias")).unwrap();

        let candidate = inside.join("alias/new/file");
        let resolved = canonical_for_policy(candidate.to_str().unwrap()).unwrap();
        assert_eq!(resolved, format!("{}/new/file", outside.to_string_lossy()));
        let missing = inside.join("not-created/child");
        assert_eq!(
            canonical_for_policy(missing.to_str().unwrap()).unwrap(),
            missing.to_string_lossy()
        );
        fs::remove_dir_all(base).unwrap();
    }
}

#[cfg(test)]
mod system_scope_tests {
    use super::system_path_scope;

    #[test]
    fn system_path_scope_matches_prefix_roots_not_nested_suffixes() {
        assert_eq!(system_path_scope("/etc"), Some("/etc".to_string()));
        assert_eq!(system_path_scope("/etc/config"), Some("/etc".to_string()));
        assert_eq!(system_path_scope("/usr"), Some("/usr".to_string()));
        assert_eq!(system_path_scope("/usr/bin"), Some("/usr".to_string()));
        assert_eq!(system_path_scope("/"), None);
        assert_eq!(system_path_scope("/tmp"), None);
        assert_eq!(
            system_path_scope("/tmp/abc/luci-app-harbor-file-pro/root/etc"),
            None
        );
        assert_eq!(system_path_scope("/home/user/etc"), None);
        assert_eq!(
            system_path_scope("/overlay/upper/etc"),
            Some("/overlay".to_string())
        );
    }
}
