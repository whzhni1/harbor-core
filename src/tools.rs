pub fn valid_name(name: &str) -> bool {
    name.len() <= 128
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

pub fn valid_package(name: &str) -> bool {
    valid_name(name)
}

pub fn package_for(name: &str) -> &'static str {
    match name {
        "bsdtar" => "bsdtar",
        "tar" => "tar",
        "zip" => "zip",
        "unzip" => "unzip",
        "gzip" | "gunzip" => "gzip",
        "bzip2" | "bunzip2" => "bzip2",
        "xz" | "unxz" => "xz",
        "zstd" | "unzstd" => "zstd",
        "lz4" => "lz4",
        "lzip" => "lzip",
        "lzop" => "lzop",
        "7z" | "7zz" => "p7zip",
        "unrar" => "unrar",
        "ffmpeg" => "ffmpeg",
        "convert" | "magick" => "imagemagick",
        "gm" => "graphicsmagick",
        "stat" => "coreutils-stat",
        "sha256sum" => "coreutils-sha256sum",
        "sftp" => "openssh-sftp-server",
        _ => "",
    }
}

/// The package mapping and installed response are shared by local and SSH
/// install adapters; an unmapped, validated tool is its own package name.
pub fn package_name_for(name: &str) -> &str {
    let mapped = package_for(name);
    if mapped.is_empty() {
        name
    } else {
        mapped
    }
}

pub fn packages_for_tool(name: &str) -> Vec<String> {
    package_name_for(name)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

pub fn installed_tool(name: &str) -> serde_json::Value {
    serde_json::json!({ "tool": name, "package_name": package_name_for(name),
        "installed": true, "available": true, "state": "success", "done": true, "success": true })
}

pub fn missing_tool_data(name: &str) -> serde_json::Value {
    serde_json::json!({ "missing_tool": name, "package_name": package_name_for(name) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_mapping_covers_common_tools() {
        assert_eq!(package_for("gm"), "graphicsmagick");
        assert_eq!(package_for("xz"), "xz");
        assert_eq!(package_for("ssh"), "");
        assert_eq!(package_for("sftp"), "openssh-sftp-server");
        assert_eq!(package_for("ucode"), "");
        assert_eq!(package_for("unmapped"), "");
        assert_eq!(package_name_for("unmapped"), "unmapped");
        assert_eq!(packages_for_tool("gm"), vec!["graphicsmagick"]);
        assert_eq!(missing_tool_data("gm")["package_name"], "graphicsmagick");
        assert_eq!(installed_tool("gm")["done"], true);
    }

    #[test]
    fn rejects_unsafe_tool_and_package_names() {
        assert!(valid_name("bsdtar"));
        assert!(valid_package("coreutils-stat"));
        assert!(!valid_name("-rf"));
        assert!(!valid_name("/bin/sh"));
        assert!(!valid_name("tool;id"));
    }
}
