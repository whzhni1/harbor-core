//! Fail-closed archive preflight shared by local and SSH extraction.
//!
//! BusyBox tar's textual listing rewrites absolute/traversing paths and emits
//! literal newlines. Inspect tar headers instead of trusting that listing.

use std::collections::HashSet;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

const MAX_EXTENSION: u64 = 64 * 1024;
const MAX_NAME: usize = 4096;
const MAX_TRAILER: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    /// Normalized display/policy name.
    pub name: String,
    /// The actual name in the archive, as required by tar -T.
    pub selector: String,
    pub is_dir: bool,
    /// Unix mode from the raw tar header (zero for non-tar listings).
    pub mode: u32,
    /// A different legacy header name, checked too in case an extractor
    /// interprets a GNU/PAX extension differently.
    pub fallback: Option<String>,
}

pub(crate) fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\0')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && !name.split('/').any(|part| part == "..")
        && name.len() <= MAX_NAME
}

fn normalize_member(raw: &str, is_dir: bool) -> Result<Option<String>, String> {
    if raw.contains('\0') || raw.starts_with('/') || raw.len() > MAX_NAME {
        return Err("Archive contains an unsafe path".into());
    }
    let mut name = raw;
    while let Some(rest) = name.strip_prefix("./") {
        name = rest;
    }
    if name.is_empty() || name == "." {
        return if is_dir {
            Ok(None)
        } else {
            Err("Archive contains an unsafe path".into())
        };
    }
    if !is_dir && name.ends_with('/') {
        return Err("Archive contains an ambiguous member type".into());
    }
    name = name.trim_end_matches('/');
    if !safe_name(name) {
        return Err("Archive contains an unsafe path".into());
    }
    Ok(Some(name.to_string()))
}

pub(crate) fn member(raw: &str, is_dir: bool) -> Result<Option<Member>, String> {
    Ok(normalize_member(raw, is_dir)?.map(|name| Member {
        name,
        selector: raw.to_string(),
        is_dir,
        mode: 0,
        fallback: None,
    }))
}

// PAX records use an explicit byte length. Reject duplicate and unrecognized
// keys rather than guessing whether another tar implementation honors them.
fn pax_path(data: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut i = 0usize;
    let mut seen = HashSet::new();
    let mut path = None;
    while i < data.len() {
        let space = data[i..]
            .iter()
            .position(|b| *b == b' ')
            .ok_or("Invalid PAX metadata")?
            + i;
        let length = std::str::from_utf8(&data[i..space])
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or("Invalid PAX metadata")?;
        let end = i
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or("Invalid PAX metadata")?;
        if end <= space + 2 || data[end - 1] != b'\n' {
            return Err("Invalid PAX metadata".into());
        }
        let body = &data[space + 1..end - 1];
        let equal = body
            .iter()
            .position(|b| *b == b'=')
            .ok_or("Invalid PAX metadata")?;
        let key = std::str::from_utf8(&body[..equal]).map_err(|_| "Invalid PAX metadata")?;
        if !seen.insert(key.to_string()) {
            return Err("Ambiguous PAX metadata".into());
        }
        match key {
            "path" => path = Some(body[equal + 1..].to_vec()),
            "mtime" | "atime" | "ctime" | "uid" | "gid" | "uname" | "gname" | "comment" => {}
            // size, sparse, linkpath, global extensions, ACLs and implementation-
            // specific path overrides can be interpreted differently by tools.
            _ => return Err("Unsupported archive metadata for safe extraction".into()),
        }
        i = end;
    }
    Ok(path)
}

fn read_extension<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<Vec<u8>, String> {
    let size = entry.size();
    if size > MAX_EXTENSION {
        return Err("Archive metadata is too large to validate safely".into());
    }
    let mut data = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut data)
        .map_err(|_| "Cannot safely inspect archive members")?;
    if data.len() as u64 != size {
        return Err("Truncated archive metadata".into());
    }
    Ok(data)
}

/// Read one uncompressed tar stream. `tar::Archive::raw(true)` prevents
/// unbounded allocation for extension headers; extensions are handled above.
#[cfg(test)]
pub(crate) fn inspect_tar<R: Read>(reader: R, limit: usize) -> Result<Vec<Member>, String> {
    inspect_tar_with_limit(reader, limit, None)
}

fn inspect_tar_with_limit<R: Read>(
    reader: R,
    limit: usize,
    payload_limit: Option<u64>,
) -> Result<Vec<Member>, String> {
    let mut archive = tar::Archive::new(reader);
    let mut output = Vec::new();
    let mut long_name: Option<Vec<u8>> = None;
    let mut pax_name: Option<Vec<u8>> = None;
    let mut have_pax = false;
    let mut count = 0usize;
    let mut payload = 0u64;
    {
        let entries = archive
            .entries()
            .map_err(|_| "Cannot safely inspect archive members")?
            .raw(true);
        for entry in entries {
            let mut entry = entry.map_err(|_| "Cannot safely inspect archive members")?;
            // Reject excessive declared output before decompressing/skipping
            // the member body, including extensions and integer overflow.
            payload = payload
                .checked_add(entry.size())
                .ok_or("Archive expands beyond the allowed size")?;
            if payload_limit.is_some_and(|limit| payload > limit) {
                return Err("Archive expands beyond the allowed size".into());
            }
            let kind = entry.header().entry_type();
            if kind == tar::EntryType::GNULongName {
                if long_name.is_some() || have_pax {
                    return Err("Ambiguous archive metadata".into());
                }
                let mut data = read_extension(&mut entry)?;
                if data.last() != Some(&0) {
                    return Err("Ambiguous archive metadata".into());
                }
                data.pop();
                if data.contains(&0) {
                    return Err("Archive contains an unsafe path".into());
                }
                long_name = Some(data);
                continue;
            }
            if kind == tar::EntryType::XHeader {
                if have_pax || long_name.is_some() {
                    return Err("Ambiguous archive metadata".into());
                }
                have_pax = true;
                pax_name = pax_path(&read_extension(&mut entry)?)?;
                continue;
            }
            if kind != tar::EntryType::Regular && kind != tar::EntryType::Directory {
                return Err(
                    if kind == tar::EntryType::Symlink || kind == tar::EntryType::Link {
                        "Archives containing links cannot be extracted"
                    } else {
                        "Archive contains unsupported special entries"
                    }
                    .into(),
                );
            }
            count += 1;
            if count > limit {
                return Err("Archive is too large to validate safely".into());
            }
            let is_dir = kind == tar::EntryType::Directory;
            let header_bytes = entry.header().path_bytes();
            let header_name = std::str::from_utf8(&header_bytes)
                .map_err(|_| "Archive contains an unsafe path")?;
            let fallback = normalize_member(header_name, is_dir)?;
            let effective = long_name.take().or_else(|| pax_name.take());
            have_pax = false;
            let effective_name = match effective.as_ref() {
                Some(bytes) => {
                    std::str::from_utf8(bytes).map_err(|_| "Archive contains an unsafe path")?
                }
                None => header_name,
            };
            if let Some(mut value) = member(effective_name, is_dir)? {
                value.mode = entry
                    .header()
                    .mode()
                    .map_err(|_| "Invalid archive permissions")?;
                value.fallback = fallback.filter(|name| name != &value.name);
                output.push(value);
            }
        }
    }
    if long_name.is_some() || have_pax {
        return Err("Truncated archive metadata".into());
    }
    // Require the second zero block. Also reject appended, ambiguous archives
    // and cap padding, rather than accepting a truncated/concatenated stream.
    let mut reader = archive.into_inner();
    let mut second = [0u8; 512];
    reader
        .read_exact(&mut second)
        .map_err(|_| "Truncated archive")?;
    if second.iter().any(|b| *b != 0) {
        return Err("Ambiguous archive trailer".into());
    }
    let mut tail = reader.take(MAX_TRAILER + 1);
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = tail
            .read(&mut buffer)
            .map_err(|_| "Cannot safely inspect archive members")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_TRAILER || buffer[..n].iter().any(|b| *b != 0) {
            return Err("Ambiguous archive trailer".into());
        }
    }
    Ok(output)
}

/// Program that streams the *decompressed* tar bytes, not a textual listing.
pub(crate) fn tar_stream_command(path: &str, kind: &str) -> Option<(&'static str, Vec<String>)> {
    let program = match kind {
        "tar" => "cat",
        "targz" => "gzip",
        "tarbz2" => "bzip2",
        "tarxz" => "xz",
        _ => return None,
    };
    let args = if kind == "tar" {
        vec![path.to_string()]
    } else {
        vec!["-dc".to_string(), path.to_string()]
    };
    Some((program, args))
}

#[cfg(test)]
pub(crate) fn inspect_local_tar(
    path: &str,
    kind: &str,
    limit: usize,
) -> Result<Vec<Member>, String> {
    inspect_local_tar_with_limit(path, kind, limit, None)
}

pub(crate) fn inspect_local_tar_with_limit(
    path: &str,
    kind: &str,
    limit: usize,
    payload_limit: Option<u64>,
) -> Result<Vec<Member>, String> {
    use std::os::unix::process::CommandExt;
    let (program, args) = tar_stream_command(path, kind).ok_or("Unsupported archive format")?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Match the SSH child: the watchdog can kill its isolated process group.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = cmd.spawn().map_err(|_| "Cannot start archive inspection")?;
    let child = crate::ssh::ByteStream::from_child(child, true)?;
    inspect_child_with_limit(child, limit, payload_limit, None)
}

pub(crate) fn inspect_local_tar_cancellable(
    path: &str,
    kind: &str,
    limit: usize,
    cancelled: Arc<AtomicBool>,
) -> Result<Vec<Member>, String> {
    use std::os::unix::process::CommandExt;
    let (program, args) = tar_stream_command(path, kind).ok_or("Unsupported archive format")?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = cmd.spawn().map_err(|_| "Cannot start archive inspection")?;
    let child = crate::ssh::ByteStream::from_child(child, true)?;
    inspect_child_with_limit(child, limit, None, Some(cancelled))
}

/// Inspect a local decompressor or SSH child with bounded metadata/stderr and a
/// watchdog. The caller must have started the child in a new process group.
pub(crate) fn inspect_child(
    child: crate::ssh::ByteStream,
    limit: usize,
) -> Result<Vec<Member>, String> {
    inspect_child_with_limit(child, limit, None, None)
}

fn inspect_child_with_limit(
    mut child: crate::ssh::ByteStream,
    limit: usize,
    payload_limit: Option<u64>,
    cancelled: Option<Arc<AtomicBool>>,
) -> Result<Vec<Member>, String> {
    child.stdin.take();
    let stdout = child.stdout.take().ok_or("Cannot inspect archive")?;
    let stderr = child.stderr.take().ok_or("Cannot inspect archive")?;
    let err_reader = std::thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0u8; 4096];
        while matches!(reader.read(&mut buf), Ok(n) if n > 0) {}
    });
    let timed_out = Arc::new(AtomicBool::new(false));
    let timed_out_thread = Arc::clone(&timed_out);
    let (tx, rx) = mpsc::channel::<()>();
    let cancelled_thread = cancelled.clone();
    let abort = child.abort_handle();
    let watchdog = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            if cancelled_thread
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
            {
                abort.abort();
                break;
            }
            if start.elapsed() >= Duration::from_secs(3600) {
                timed_out_thread.store(true, Ordering::Relaxed);
                abort.abort();
                break;
            }
        }
    });
    let result = inspect_tar_with_limit(stdout, limit, payload_limit);
    if result.is_err()
        || timed_out.load(Ordering::Relaxed)
        || cancelled
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
    {
        let _ = child.kill();
    }
    let status = child.wait();
    let _ = tx.send(());
    let _ = watchdog.join();
    let _ = err_reader.join();
    if timed_out.load(Ordering::Relaxed) {
        return Err("Archive inspection timed out".into());
    }
    if cancelled
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
    {
        return Err("Archive inspection cancelled".into());
    }
    let result = result?;
    if !status.is_ok_and(|code| code == 0) {
        return Err("Cannot safely inspect archive members".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn cancelling_stalled_archive_inspection_kills_the_decompressor() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir().join(format!(
            "harbor-archive-cancel-{}",
            crate::uci::random_hex(8)
        ));
        std::fs::create_dir(&root).unwrap();
        let fifo = root.join("stall.tar");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let flag = Arc::new(AtomicBool::new(false));
        let inner = flag.clone();
        let started = std::time::Instant::now();
        let worker = std::thread::spawn(move || {
            inspect_local_tar_cancellable(fifo.to_str().unwrap(), "tar", 10, inner)
        });
        std::thread::sleep(Duration::from_millis(150));
        flag.store(true, Ordering::Release);
        assert_eq!(
            worker.join().unwrap().unwrap_err(),
            "Archive inspection cancelled"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn declared_uncompressed_payload_is_bounded_before_reading() {
        let mut tar = tar::Builder::new(Vec::new());
        append(&mut tar, "one", tar::EntryType::Regular, b"12345");
        append(&mut tar, "two", tar::EntryType::Regular, b"678901");
        let bytes = tar.into_inner().unwrap();
        assert_eq!(
            inspect_tar_with_limit(Cursor::new(&bytes), 10, Some(10)).unwrap_err(),
            "Archive expands beyond the allowed size"
        );
        assert_eq!(
            inspect_tar_with_limit(Cursor::new(&bytes), 10, Some(11))
                .unwrap()
                .len(),
            2
        );
        // A tiny compressed bomb can declare huge output; reject immediately,
        // even when the payload is missing, rather than decompressing it.
        let mut header = tar::Header::new_ustar();
        header.set_path("bomb").unwrap();
        header.set_size(9 * 1024 * 1024 * 1024);
        header.set_mode(0o644);
        header.set_cksum();
        assert_eq!(
            inspect_tar_with_limit(Cursor::new(header.as_bytes()), 10, Some(1024)).unwrap_err(),
            "Archive expands beyond the allowed size"
        );
    }

    fn append(builder: &mut tar::Builder<Vec<u8>>, name: &str, kind: tar::EntryType, data: &[u8]) {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(if kind == tar::EntryType::Directory {
            0o755
        } else {
            0o644
        });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(kind);
        assert!(name.len() <= 100);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }
    fn make(name: &str, kind: tar::EntryType) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        append(&mut builder, name, kind, b"");
        builder.into_inner().unwrap()
    }
    fn inspect(bytes: &[u8]) -> Result<Vec<Member>, String> {
        inspect_tar(Cursor::new(bytes), 4000)
    }

    #[test]
    fn reads_raw_tar_names_without_busybox_normalization() {
        let mut builder = tar::Builder::new(Vec::new());
        append(&mut builder, "./", tar::EntryType::Directory, b"");
        append(&mut builder, "./folder/", tar::EntryType::Directory, b"");
        append(
            &mut builder,
            "./folder/中文.txt",
            tar::EntryType::Regular,
            b"hello",
        );
        let bytes = builder.into_inner().unwrap();
        let entries = inspect(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "folder");
        assert_eq!(entries[1].name, "folder/中文.txt");
        assert_eq!(entries[1].selector, "./folder/中文.txt");
        for name in [
            "../evil",
            "/etc/passwd",
            "folder/../../secret",
            "a\nb",
            "safe\n-rwxrwxrwx 0 0 fake",
            "back\\slash",
        ] {
            assert!(
                inspect(&make(name, tar::EntryType::Regular)).is_err(),
                "accepted {name:?}"
            );
        }
    }

    #[test]
    fn rejects_links_special_types_limits_and_truncation() {
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Fifo,
        ] {
            assert!(inspect(&make("test", kind)).is_err(), "accepted {kind:?}");
        }
        let mut builder = tar::Builder::new(Vec::new());
        append(&mut builder, "one", tar::EntryType::Regular, b"one");
        append(&mut builder, "two", tar::EntryType::Regular, b"two");
        let bytes = builder.into_inner().unwrap();
        assert!(inspect_tar(Cursor::new(&bytes), 1).is_err());
        assert!(inspect(&bytes[..512 + 512 + 512]).is_err());
        let mut appended = bytes.clone();
        appended.extend_from_slice(b"a second hidden archive");
        assert!(inspect(&appended).is_err());
    }

    #[test]
    fn pax_unicode_is_checked_along_with_the_legacy_header() {
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", "dir/中文.txt".as_bytes())])
            .unwrap();
        append(&mut builder, "legacy.txt", tar::EntryType::Regular, b"ok");
        let members = inspect(&builder.into_inner().unwrap()).unwrap();
        assert_eq!(members[0].name, "dir/中文.txt");
        assert_eq!(members[0].fallback.as_deref(), Some("legacy.txt"));

        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", b"safe.txt".as_slice())])
            .unwrap();
        append(&mut builder, "../evil", tar::EntryType::Regular, b"ok");
        assert!(inspect(&builder.into_inner().unwrap()).is_err());

        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", b"../evil".as_slice())])
            .unwrap();
        append(&mut builder, "safe", tar::EntryType::Regular, b"ok");
        assert!(inspect(&builder.into_inner().unwrap()).is_err());

        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("GNU.sparse.name", b"elsewhere".as_slice())])
            .unwrap();
        append(&mut builder, "safe", tar::EntryType::Regular, b"ok");
        assert!(inspect(&builder.into_inner().unwrap()).is_err());
    }

    #[test]
    fn gnu_long_names_are_bounded_and_validated() {
        let long = format!("dir/{}", "a".repeat(120));
        let mut payload = long.as_bytes().to_vec();
        payload.push(0);
        let mut builder = tar::Builder::new(Vec::new());
        append(
            &mut builder,
            "././@LongLink",
            tar::EntryType::GNULongName,
            &payload,
        );
        append(
            &mut builder,
            "dir/legacy",
            tar::EntryType::Regular,
            b"hello",
        );
        let entries = inspect(&builder.into_inner().unwrap()).unwrap();
        assert_eq!(entries[0].name, long);
        assert_eq!(entries[0].fallback.as_deref(), Some("dir/legacy"));
        let mut too_big = tar::Builder::new(Vec::new());
        append(
            &mut too_big,
            "././@LongLink",
            tar::EntryType::GNULongName,
            &vec![b'a'; MAX_EXTENSION as usize + 1],
        );
        append(&mut too_big, "safe", tar::EntryType::Regular, b"");
        assert!(inspect(&too_big.into_inner().unwrap()).is_err());
    }
}
