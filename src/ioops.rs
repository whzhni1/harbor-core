use crate::atomic_u64::AtomicU64;
use crate::auth;
use crate::meta::{self, Kind};
use crate::params::Params;
use crate::paths::{self, quote_header_filename};
use crate::reply::json_response;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub const SLICE_MAX: u64 = 8 * 1024 * 1024;
const CHUNK: usize = 256 * 1024;

pub(crate) struct RequestCancelGuard {
    cancelled: Arc<AtomicBool>,
    active: bool,
}

impl RequestCancelGuard {
    pub(crate) fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            active: true,
        }
    }

    pub(crate) fn finish(&mut self) {
        self.active = false;
    }
}

impl Drop for RequestCancelGuard {
    fn drop(&mut self) {
        if self.active {
            self.cancelled.store(true, Ordering::Relaxed);
        }
    }
}

// Cooperative cancellation between filesystem I/O calls. Use Other rather
// than Interrupted: std::io::copy retries Interrupted indefinitely.
pub(crate) struct CancelRead<R> {
    pub(crate) inner: R,
    pub(crate) cancelled: Arc<AtomicBool>,
}
impl<R: Read> Read for CancelRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("rewrite cancelled"));
        }
        self.inner.read(bytes)
    }
}
pub(crate) struct CancelWrite<W> {
    pub(crate) inner: W,
    pub(crate) cancelled: Arc<AtomicBool>,
}
impl<W: Write> Write for CancelWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("rewrite cancelled"));
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("rewrite cancelled"));
        }
        self.inner.flush()
    }
}

fn reply(body: Value) -> Response {
    json_response(StatusCode::OK, body)
}

fn reply_status(status: StatusCode, mut body: Value) -> Response {
    if body["code"].as_i64().is_some_and(|code| code != 0) {
        if let Some(message) = body["message"].as_str() {
            body["message"] = Value::String(crate::i18n::translate(message));
        }
    }
    json_response(status, body)
}

fn io_error(status: StatusCode, message: &str) -> Response {
    reply_status(
        status,
        json!({ "code": 1, "message": message, "data": Value::Null }),
    )
}

#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

pub enum RangeOutcome {
    None,
    Satisfiable(ByteRange),
    Unsatisfiable,
}

pub fn parse_range(header_value: Option<&str>, size: u64) -> RangeOutcome {
    let value = match header_value {
        Some(v) => v.trim(),
        None => return RangeOutcome::None,
    };
    let spec = match value.strip_prefix("bytes=") {
        Some(s) => s,
        None => return RangeOutcome::None,
    };

    let spec = spec.split(',').next().unwrap_or("").trim();
    let (first, last) = match spec.split_once('-') {
        Some(v) => v,
        None => return RangeOutcome::None,
    };
    let (start, end) = if first.is_empty() {
        let n: u64 = match last.trim().parse() {
            Ok(v) => v,
            Err(_) => return RangeOutcome::None,
        };
        if n == 0 {
            return RangeOutcome::None;
        }
        (size.saturating_sub(n), size.saturating_sub(1))
    } else {
        let start: u64 = match first.trim().parse() {
            Ok(v) => v,
            Err(_) => return RangeOutcome::None,
        };
        let end = if last.trim().is_empty() {
            size.saturating_sub(1)
        } else {
            match last.trim().parse::<u64>() {
                Ok(v) => v.min(size.saturating_sub(1)),
                Err(_) => return RangeOutcome::None,
            }
        };
        (start, end)
    };
    if size == 0 || start >= size || end < start {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Satisfiable(ByteRange { start, end })
}

pub(crate) async fn stream_file(path: String, offset: u64, len: u64) -> std::io::Result<Body> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = tokio::fs::File::open(&path).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    let limited = file.take(len);
    let stream = tokio_util::io::ReaderStream::with_capacity(limited, CHUNK);
    Ok(Body::from_stream(stream))
}

pub enum Source<'a> {
    Local,
    Remote {
        target: &'a crate::ssh::Target,
        path: &'a str,
    },
}

pub struct FileHeaders<'a> {
    pub path: &'a str,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub inline: bool,
}

pub async fn serve_file(
    st: &AppState,
    headers: &HeaderMap,
    method: &Method,
    fh: FileHeaders<'_>,
    source: Source<'_>,
) -> Response {
    let etag = format!("\"{:x}-{:x}-{:x}\"", fh.mtime, fh.mtime_ns, fh.size);
    let inm = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !inm.is_empty() && inm.split(',').any(|t| t.trim() == etag) {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::ETAG, etag)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let range = parse_range(range_header.as_deref(), fh.size);

    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, fh.mime.clone())
        .header(
            header::CONTENT_DISPOSITION,
            format!(
                "{}; {}",
                if fh.inline { "inline" } else { "attachment" },
                quote_header_filename(&fh.name)
            ),
        )
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, "private, max-age=0, must-revalidate")
        .header("X-Content-Type-Options", "nosniff");

    let (status, offset, len) = match range {
        RangeOutcome::Unsatisfiable => {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{}", fh.size))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        RangeOutcome::Satisfiable(r) => {
            builder = builder.header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", r.start, r.end, fh.size),
            );
            (StatusCode::PARTIAL_CONTENT, r.start, r.len())
        }
        RangeOutcome::None => (StatusCode::OK, 0, fh.size),
    };

    builder = builder.header(header::CONTENT_LENGTH, len.to_string());

    if method == Method::HEAD {
        return builder
            .status(status)
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let slot = match st.limits.begin_transfer() {
        Some(slot) => slot,
        None => {
            return io_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Too many transfers in flight",
            )
        }
    };
    let body = match source {
        Source::Local => stream_file(fh.path.to_string(), offset, len)
            .await
            .map(|body| (body, None))
            .map_err(|_| ()),
        Source::Remote { target, path } => {
            let target = target.clone();
            let path = path.to_string();
            tokio::task::spawn_blocking(move || {
                crate::remoteio::stream_range(&target, &path, offset, len)
            })
            .await
            .map_err(|_| ())
            .and_then(|result| {
                result
                    .map(|(body, child)| (body, Some(child)))
                    .map_err(|_| ())
            })
        }
    };
    match body {
        Ok((body, child)) => {
            let tracked =
                crate::api::transferops::track_download(st, fh.path, len, body, child, slot);
            builder
                .status(status)
                .header("X-Harbor-Task", tracked.0)
                .body(tracked.1)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(_) => io_error(StatusCode::FORBIDDEN, "cannot open file"),
    }
}

mod byteops;

fn byte_int(params: &Params, key: &str) -> Option<u64> {
    params.get(key)?.trim().parse::<u64>().ok()
}

pub async fn handle(st: Arc<AppState>, params: Params, req: Request) -> Response {
    byteops::handle(st, params, req).await
}

#[allow(clippy::result_large_err)]
pub async fn read_body(req: Request, limit: u64) -> std::result::Result<Vec<u8>, Response> {
    crate::limits::read_body_limited(req, limit)
        .await
        .map_err(|error| match error {
            crate::limits::BodyReadError::TooLarge => {
                io_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
            }
            crate::limits::BodyReadError::Invalid => {
                io_error(StatusCode::BAD_REQUEST, "invalid request body")
            }
            crate::limits::BodyReadError::TimedOut => {
                io_error(StatusCode::REQUEST_TIMEOUT, "request body timed out")
            }
        })
}

fn decode_needle(raw: &str, encoding: &str) -> Option<Vec<u8>> {
    match encoding {
        "hex" => {
            let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            let cleaned = cleaned.trim_start_matches("0x");
            if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
                return None;
            }
            hex::decode(cleaned).ok()
        }
        _ => {
            if raw.is_empty() {
                None
            } else {
                Some(raw.as_bytes().to_vec())
            }
        }
    }
}

// Linear-time literal matching, including overlapping candidates. This avoids
// quadratic scans for patterns such as thousands of 'a' bytes followed by 'b'.
fn find_literal_all(
    hay: &[u8],
    needle: &[u8],
    icase: bool,
    min_start: usize,
    out: &mut Vec<usize>,
) {
    if needle.is_empty() || hay.len() < needle.len() {
        return;
    }
    let fold = |b: u8| if icase { b.to_ascii_lowercase() } else { b };
    let mut prefix = vec![0usize; needle.len()];
    let mut matched = 0usize;
    for i in 1..needle.len() {
        while matched > 0 && fold(needle[i]) != fold(needle[matched]) {
            matched = prefix[matched - 1];
        }
        if fold(needle[i]) == fold(needle[matched]) {
            matched += 1;
        }
        prefix[i] = matched;
    }
    matched = 0;
    for (i, byte) in hay.iter().enumerate().skip(min_start.min(hay.len())) {
        while matched > 0 && fold(*byte) != fold(needle[matched]) {
            matched = prefix[matched - 1];
        }
        if fold(*byte) == fold(needle[matched]) {
            matched += 1;
        }
        if matched == needle.len() {
            out.push(i + 1 - needle.len());
            matched = prefix[matched - 1];
        }
    }
}

fn build_regex(pattern: &str, icase: bool) -> Result<regex::bytes::Regex, String> {
    // Validate expanded repetition before compilation or an uninterruptible search.
    let _ = regex_stream_overlap(pattern, icase)?;
    regex::bytes::RegexBuilder::new(pattern)
        .case_insensitive(icase)
        .size_limit(16 * 1024 * 1024)
        .build()
        .map_err(|e| {
            let msg = e.to_string();
            msg.lines()
                .next()
                .unwrap_or("invalid regular expression")
                .to_string()
        })
}

// Regexes with a finite maximum length and no assertions can be streamed
// exactly with that maximum overlap. Other patterns need the whole haystack to
// preserve anchors, greedy matches and word boundaries; cap memory explicitly.
const REGEX_FULL_MAX: u64 = 64 * 1024 * 1024;
const REGEX_STREAM_OVERLAP_MAX: usize = 1024 * 1024;

pub(crate) struct SearchPlan {
    needle: Vec<u8>,
    regex: Option<regex::bytes::Regex>,
    icase: bool,
    pub(crate) start: u64,
    size: u64,
    limit: usize,
    last_mode: bool,
    before: Option<u64>,
    window_mode: bool,
    progressive_scan: bool,
    scan_to: u64,
    overlap: usize,
    regex_full: bool,
}

impl SearchPlan {
    pub(crate) fn read_start(&self) -> u64 {
        if self.regex_full {
            0
        } else {
            self.start
        }
    }
    pub(crate) fn read_end(&self) -> u64 {
        if self.regex_full {
            self.size
        } else {
            self.scan_to
                .saturating_add(self.overlap as u64)
                .min(self.size)
        }
    }
}

// Repetition-heavy expressions can force the regex engine to spend minutes in
// a single uninterruptible search despite its finite automaton. Bound the
// expanded HIR, including nested repetitions, for both search and replace.
fn regex_complexity(hir: &regex_syntax::hir::Hir) -> Result<usize, String> {
    use regex_syntax::hir::HirKind;
    const MAX_REPEAT: u32 = 512;
    const MAX_COST: usize = 4096;
    let error = || "Regular expression is too complex (repetition limit 512)".to_string();
    let cost = match hir.kind() {
        HirKind::Empty | HirKind::Look(_) | HirKind::Class(_) => 1,
        HirKind::Literal(bytes) => bytes.0.len().max(1),
        HirKind::Capture(capture) => regex_complexity(&capture.sub)?,
        HirKind::Repetition(repeat) => {
            let times = repeat.max.unwrap_or(repeat.min.saturating_add(1));
            if repeat.min > MAX_REPEAT || times > MAX_REPEAT {
                return Err(error());
            }
            regex_complexity(&repeat.sub)?
                .saturating_mul(times.max(1) as usize)
                .saturating_add(1)
        }
        HirKind::Concat(parts) | HirKind::Alternation(parts) => {
            let mut sum = 1usize;
            for part in parts {
                sum = sum.saturating_add(regex_complexity(part)?);
            }
            sum
        }
    };
    if cost > MAX_COST {
        Err(error())
    } else {
        Ok(cost)
    }
}

// Returns an exact streaming overlap, or None when full-file context is
// required. Reject empty matches instead of silently looping or corrupting data.
fn regex_stream_overlap(pattern: &str, icase: bool) -> Result<Option<usize>, String> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .case_insensitive(icase)
        .build()
        .parse(pattern)
        .map_err(|_| "invalid regular expression".to_string())?;
    regex_complexity(&hir)?;
    if hir.properties().minimum_len() == Some(0) {
        return Err("pattern may match an empty string".to_string());
    }
    Ok(match hir.properties().maximum_len() {
        Some(max)
            if max > 0
                && max <= REGEX_STREAM_OVERLAP_MAX
                && hir.properties().look_set().is_empty() =>
        {
            Some(max - 1)
        }
        _ => None,
    })
}

pub(crate) fn prepare_search(params: &Params, size: u64) -> Result<SearchPlan, String> {
    let encoding = params.str_or("encoding", "text");
    let raw = params
        .get("q")
        .or_else(|| params.get("query"))
        .unwrap_or_default();
    let needle = decode_needle(&raw, &encoding)
        .filter(|needle| !needle.is_empty())
        .ok_or_else(|| "empty or malformed pattern".to_string())?;
    if needle.len() > 4096 {
        return Err("pattern too long".to_string());
    }
    let start = byte_int(params, "start").unwrap_or(0).min(size);
    let mut limit = params.int("limit").unwrap_or(100);
    if limit < 1 {
        limit = 100;
    }
    let limit = limit.min(1000) as usize;
    let icase = params.get("ignorecase").as_deref() == Some("1") && encoding != "hex";
    let mut regex_full = false;
    let mut overlap = needle.len().saturating_sub(1);
    let regex = if params.get("regex").as_deref() == Some("1") {
        let pattern = String::from_utf8_lossy(&needle);
        let re = build_regex(&pattern, icase)?;
        match regex_stream_overlap(&pattern, icase)? {
            Some(width) => overlap = width,
            None => {
                if size > REGEX_FULL_MAX {
                    return Err("This regex requires a file no larger than 64 MiB; use a bounded pattern without anchors for larger files".into());
                }
                regex_full = true;
                overlap = 0;
            }
        }
        Some(re)
    } else {
        None
    };
    let last_mode = params.get("last").as_deref() == Some("1");
    let before = params.get("before").and_then(|v| v.parse::<u64>().ok());
    let window_mode = last_mode || before.is_some();
    let scan_bytes = if window_mode {
        None
    } else {
        byte_int(params, "scan_bytes").filter(|v| *v > 0)
    };
    let progressive_scan = scan_bytes.is_some();
    let scan_to = scan_bytes
        .map(|bytes| start.saturating_add(bytes.min(16 * 1024 * 1024)).min(size))
        .unwrap_or(size);
    Ok(SearchPlan {
        needle,
        regex,
        icase,
        start,
        size,
        limit,
        last_mode,
        before,
        window_mode,
        progressive_scan,
        scan_to,
        overlap,
        regex_full,
    })
}

struct SearchResults<'a> {
    plan: &'a SearchPlan,
    matches: Vec<u64>,
    lengths: Vec<u64>,
    window: std::collections::VecDeque<(u64, u64)>,
    accepted: u64,
    total: u64,
    next_allowed: u64,
    capped: bool,
}

impl<'a> SearchResults<'a> {
    fn new(plan: &'a SearchPlan) -> Self {
        Self {
            plan,
            matches: Vec::new(),
            lengths: Vec::new(),
            window: Default::default(),
            accepted: 0,
            total: 0,
            next_allowed: plan.start,
            capped: false,
        }
    }

    // Return false once a non-progressive page has a known next page.
    fn add(&mut self, absolute: u64, len: u64) -> bool {
        if absolute >= self.plan.scan_to || absolute < self.next_allowed {
            return true;
        }
        self.next_allowed = absolute.saturating_add(len);
        self.total += 1;
        if self.plan.window_mode {
            if self.plan.last_mode
                || self
                    .plan
                    .before
                    .map(|before| absolute < before)
                    .unwrap_or(true)
            {
                self.window.push_back((absolute, len));
                self.accepted += 1;
                if self.window.len() > self.plan.limit {
                    self.window.pop_front();
                }
            }
        } else if self.matches.len() < self.plan.limit {
            self.matches.push(absolute);
            self.lengths.push(len);
        } else if !self.plan.progressive_scan {
            self.capped = true;
            return false;
        }
        true
    }

    fn finish(self, path: &str, position: u64) -> Value {
        let plan = self.plan;
        if plan.window_mode {
            let matches: Vec<u64> = self.window.iter().map(|(at, _)| *at).collect();
            let lengths: Vec<u64> = self.window.iter().map(|(_, len)| *len).collect();
            return json!({
                "path": path, "matches": matches,
                "lengths": if plan.regex.is_some() { json!(lengths) } else { Value::Null },
                "count": matches.len(), "total": self.total,
                "below": self.accepted.saturating_sub(matches.len() as u64),
                "first": matches.first().copied(), "next": Value::Null,
                "scanned_to": position, "size": plan.size, "done": true
            });
        }
        let last_end = self
            .matches
            .last()
            .zip(self.lengths.last())
            .map(|(at, len)| at.saturating_add(*len));
        let next = if plan.progressive_scan {
            if self.total > self.matches.len() as u64 {
                last_end.map(Value::from).unwrap_or(Value::Null)
            } else if plan.scan_to < plan.size {
                Value::from(plan.scan_to.max(self.next_allowed))
            } else {
                Value::Null
            }
        } else if self.capped {
            last_end.map(Value::from).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        json!({
            "path": path, "matches": self.matches, "count": self.matches.len(), "total": self.total,
            "lengths": if plan.regex.is_some() { json!(self.lengths) } else { Value::Null },
            "next": next,
            "scanned_to": if plan.progressive_scan { plan.scan_to.max(self.next_allowed) } else { position },
            "size": plan.size,
            "done": if plan.progressive_scan { plan.scan_to.max(self.next_allowed) >= plan.size } else { true }
        })
    }
}

/// Shared streaming search engine. The reader starts at plan.read_start().
pub(crate) fn scan_search<R: Read>(
    reader: &mut R,
    path: &str,
    plan: &SearchPlan,
    cancelled: &AtomicBool,
) -> Result<Value, String> {
    let mut result = SearchResults::new(plan);
    let mut position = plan.read_start();
    if plan.regex_full {
        let mut hay = Vec::with_capacity(plan.size as usize);
        let mut buffer = vec![0u8; CHUNK];
        while position < plan.size {
            if cancelled.load(Ordering::Relaxed) {
                return Err("search canceled".into());
            }
            let want = (plan.size - position).min(buffer.len() as u64) as usize;
            let n = reader
                .read(&mut buffer[..want])
                .map_err(|e| format!("cannot read file: {e}"))?;
            if n == 0 {
                return Err("file changed during search".into());
            }
            hay.extend_from_slice(&buffer[..n]);
            position += n as u64;
        }
        let re = plan.regex.as_ref().expect("full search requires a regex");
        let mut cursor = plan.start as usize;
        while cursor <= hay.len() {
            if cancelled.load(Ordering::Relaxed) {
                return Err("search canceled".into());
            }
            let Some(m) = re.find_at(&hay, cursor) else {
                break;
            };
            if m.start() == m.end() {
                return Err("pattern may match an empty string".into());
            }
            if m.start() as u64 >= plan.scan_to {
                break;
            }
            if !result.add(m.start() as u64, (m.end() - m.start()) as u64) {
                break;
            }
            cursor = m.end();
        }
    } else {
        let mut carry = Vec::<u8>::new();
        let mut carry_pos = plan.start;
        let mut buffer = vec![0u8; CHUNK];
        let read_limit = plan.read_end();
        'chunks: loop {
            if cancelled.load(Ordering::Relaxed) {
                return Err("search canceled".into());
            }
            let want = read_limit.saturating_sub(position).min(buffer.len() as u64) as usize;
            if want == 0 {
                break;
            }
            let n = reader
                .read(&mut buffer[..want])
                .map_err(|e| format!("cannot read file: {e}"))?;
            if n == 0 {
                return Err("file changed during search".into());
            }
            let mut hay = Vec::with_capacity(carry.len() + n);
            hay.extend_from_slice(&carry);
            hay.extend_from_slice(&buffer[..n]);
            let base = carry_pos;
            let min_start = result
                .next_allowed
                .saturating_sub(base)
                .min(hay.len() as u64) as usize;
            position = base + hay.len() as u64;
            let mut found = Vec::<(usize, usize)>::new();
            if let Some(re) = &plan.regex {
                // These regexes have no look assertions, so slicing at the
                // first eligible offset preserves their semantics.
                for m in re.find_iter(&hay[min_start..]) {
                    if m.start() == m.end() {
                        return Err("pattern may match an empty string".into());
                    }
                    found.push((m.start() + min_start, m.end() - m.start()));
                }
            } else {
                let mut offsets = Vec::new();
                find_literal_all(&hay, &plan.needle, plan.icase, min_start, &mut offsets);
                found.extend(offsets.into_iter().map(|at| (at, plan.needle.len())));
            }
            let safe_until = if position < read_limit {
                position.saturating_sub(plan.overlap as u64)
            } else {
                position
            };
            for (index, (at, len)) in found.into_iter().enumerate() {
                if index % 1024 == 0 && cancelled.load(Ordering::Relaxed) {
                    return Err("search canceled".into());
                }
                let absolute = base + at as u64;
                if absolute >= safe_until {
                    continue;
                }
                if !result.add(absolute, len as u64) {
                    break 'chunks;
                }
            }
            let keep = plan.overlap.min(hay.len());
            carry = hay[hay.len() - keep..].to_vec();
            carry_pos = position - carry.len() as u64;
        }
    }
    Ok(result.finish(path, position))
}

pub struct ReplacePlan {
    pub needle: Vec<u8>,
    pub repl: Vec<u8>,
    pub icase: bool,
    pub regex: Option<regex::bytes::Regex>,

    pub range: Option<(u64, u64)>,
}

pub const HF_REMOTE_REPLACE_LIMIT_DEFAULT: u64 = 256 * 1024 * 1024;

pub fn remote_replace_limit() -> u64 {
    std::env::var("HARBOR_REMOTE_REPLACE_LIMIT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(HF_REMOTE_REPLACE_LIMIT_DEFAULT)
}

pub fn parse_replace(params: &Params) -> Result<ReplacePlan, (StatusCode, String)> {
    let encoding = params.str_or("encoding", "text");
    let rencoding = params.get("rencoding").unwrap_or_else(|| encoding.clone());
    let repl = match decode_needle(&params.get("r").unwrap_or_default(), &rencoding) {
        Some(v) if v.len() <= 65536 => v,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "empty or malformed pattern".to_string(),
            ))
        }
    };
    let range: Option<(u64, u64)> = params.get("range").and_then(|v| {
        let mut it = v.split(':');
        let at = it.next()?.trim().parse::<u64>().ok()?;
        let len = it.next()?.trim().parse::<u64>().ok()?;
        Some((at, len))
    });
    let needle = match decode_needle(&params.get("q").unwrap_or_default(), &encoding) {
        Some(n) if !n.is_empty() => n,
        _ => {
            if range.is_some() {
                Vec::new()
            } else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "empty or malformed pattern".to_string(),
                ));
            }
        }
    };
    if needle.len() > 4096 {
        return Err((StatusCode::BAD_REQUEST, "pattern too long".to_string()));
    }
    let icase = params.get("ignorecase").as_deref() == Some("1") && encoding != "hex";
    let regex = if params.get("regex").as_deref() == Some("1") {
        let pattern = String::from_utf8_lossy(&needle).into_owned();
        match build_regex(&pattern, icase) {
            Ok(re) => Some(re),
            Err(e) => return Err((StatusCode::BAD_REQUEST, e)),
        }
    } else {
        None
    };
    Ok(ReplacePlan {
        needle,
        repl,
        icase,
        regex,
        range,
    })
}

pub fn replace_stream<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    plan: &ReplacePlan,
    total: u64,
    progress: &dyn Fn(u64),
) -> Result<(u64, u64), String> {
    let mut replaced: u64 = 0;
    let mut written: u64 = 0;
    progress(0);

    if let Some((at, len)) = plan.range {
        let mut pre = Read::take(Read::by_ref(input), at);
        let prefix = std::io::copy(&mut pre, output).map_err(|_| "rewrite failed".to_string())?;
        if prefix != at {
            return Err("file changed during rewrite".into());
        }
        written += prefix;
        output
            .write_all(&plan.repl)
            .map_err(|_| "rewrite failed".to_string())?;
        written += plan.repl.len() as u64;
        let mut skip = Read::take(Read::by_ref(input), len);
        let skipped = std::io::copy(&mut skip, &mut std::io::sink())
            .map_err(|_| "rewrite failed".to_string())?;
        if skipped != len {
            return Err("file changed during rewrite".into());
        }
        let suffix = std::io::copy(input, output).map_err(|_| "rewrite failed".to_string())?;
        if at.checked_add(len).and_then(|n| n.checked_add(suffix)) != Some(total) {
            return Err("file changed during rewrite".into());
        }
        written += suffix;
        progress(total);
        return Ok((1, written));
    }

    let overlap = if let Some(regex) = &plan.regex {
        match regex_stream_overlap(regex.as_str(), plan.icase)? {
            Some(overlap) => overlap,
            None => {
                if total > REGEX_FULL_MAX {
                    return Err("This regex requires a file no larger than 64 MiB; use a bounded pattern without anchors for larger files".into());
                }
                let mut hay = Vec::with_capacity(total as usize);
                let mut reader = input.take(total.saturating_add(1));
                reader
                    .read_to_end(&mut hay)
                    .map_err(|_| "rewrite failed".to_string())?;
                if hay.len() as u64 != total {
                    return Err("file changed during rewrite".into());
                }
                let mut last = 0usize;
                for m in regex.find_iter(&hay) {
                    if m.start() == m.end() {
                        return Err("pattern may match an empty string".into());
                    }
                    output
                        .write_all(&hay[last..m.start()])
                        .map_err(|_| "rewrite failed".to_string())?;
                    output
                        .write_all(&plan.repl)
                        .map_err(|_| "rewrite failed".to_string())?;
                    written += (m.start() - last + plan.repl.len()) as u64;
                    last = m.end();
                    replaced += 1;
                }
                output
                    .write_all(&hay[last..])
                    .map_err(|_| "rewrite failed".to_string())?;
                written += (hay.len() - last) as u64;
                progress(total);
                return Ok((replaced, written));
            }
        }
    } else {
        plan.needle.len().saturating_sub(1)
    };
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let mut processed: u64 = 0;
    loop {
        let n = input
            .read(&mut buf)
            .map_err(|_| "rewrite failed".to_string())?;
        if n == 0 {
            if processed != total {
                return Err("file changed during rewrite".into());
            }
            let matches = find_matches(&carry, &plan.needle, plan.icase, plan.regex.as_ref())?;
            let mut out: Vec<u8> = Vec::with_capacity(carry.len());
            let mut last = 0usize;
            for (start, end) in &matches {
                out.extend_from_slice(&carry[last..*start]);
                out.extend_from_slice(&plan.repl);
                last = *end;
                replaced += 1;
            }
            out.extend_from_slice(&carry[last..]);
            output
                .write_all(&out)
                .map_err(|_| "rewrite failed".to_string())?;
            written += out.len() as u64;
            break;
        }
        let mut hay = Vec::with_capacity(carry.len() + n);
        hay.extend_from_slice(&carry);
        hay.extend_from_slice(&buf[..n]);

        let matches = find_matches(&hay, &plan.needle, plan.icase, plan.regex.as_ref())?;
        let safe_end = hay.len().saturating_sub(overlap);
        let mut cut = safe_end;
        for (start, end) in &matches {
            if *end > safe_end {
                cut = cut.min(*start);
                break;
            }
        }

        let mut out: Vec<u8> = Vec::with_capacity(cut + 64);
        let mut last = 0usize;
        for (start, end) in &matches {
            if *end > cut {
                break;
            }
            out.extend_from_slice(&hay[last..*start]);
            out.extend_from_slice(&plan.repl);
            last = *end;
            replaced += 1;
        }
        out.extend_from_slice(&hay[last..cut]);
        output
            .write_all(&out)
            .map_err(|_| "rewrite failed".to_string())?;
        written += out.len() as u64;
        carry = hay[cut..].to_vec();
        processed += n as u64;
        progress(processed);
    }
    Ok((replaced, written))
}

// Progress belongs to a single device, path, and (when provided) client
// operation. A mutex makes updates atomic without temporary files or a shared
// global progress file. Entries are removed even if a rewrite fails or panics.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplaceProgressKey {
    device: String,
    path: String,
    operation: String,
}

type ProgressEntry = (u64, u64, u64); // generation, done, total

fn replace_progress_map() -> &'static Mutex<HashMap<ReplaceProgressKey, ProgressEntry>> {
    static MAP: OnceLock<Mutex<HashMap<ReplaceProgressKey, ProgressEntry>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn replace_progress_key(device: &str, path: &str, params: &Params) -> ReplaceProgressKey {
    let operation = params
        .get("progress_id")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .unwrap_or_default();
    ReplaceProgressKey {
        device: device.to_string(),
        path: path.to_string(),
        operation,
    }
}

pub(crate) struct ReplaceProgress {
    key: ReplaceProgressKey,
    generation: u64,
}

impl ReplaceProgress {
    pub(crate) fn start(device: &str, path: &str, params: &Params) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let key = replace_progress_key(device, path, params);
        let generation = NEXT.fetch_add(1, Ordering::Relaxed);
        replace_progress_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.clone(), (generation, 0, 0));
        Self { key, generation }
    }

    pub(crate) fn update(&self, done: u64, total: u64) {
        if let Some(entry) = replace_progress_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&self.key)
        {
            if entry.0 == self.generation {
                *entry = (self.generation, done, total);
            }
        }
    }
}

impl Drop for ReplaceProgress {
    fn drop(&mut self) {
        let mut map = replace_progress_map()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if map
            .get(&self.key)
            .is_some_and(|entry| entry.0 == self.generation)
        {
            map.remove(&self.key);
        }
    }
}

pub(crate) fn replace_progress(device: &str, path: &str, params: &Params) -> Response {
    let (done, total) = replace_progress_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&replace_progress_key(device, path, params))
        .map(|entry| (entry.1, entry.2))
        .unwrap_or((0, 0));
    reply(
        json!({ "code": 0, "message": "success", "data": { "path": path, "done": done, "total": total } }),
    )
}

// Best-effort concurrent modification detection before replacing a file.
// The final check and rename are not one atomic operation.
fn same_file_revision(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
}

fn metadata_matches_snapshot(metadata: &fs::Metadata, snapshot: meta::Meta) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file()
        && metadata.dev() == snapshot.dev
        && metadata.ino() == snapshot.ino
        && metadata.len() == snapshot.size.max(0) as u64
        && metadata.mtime() == snapshot.mtime
        && metadata.mtime_nsec() == snapshot.mtime_ns
        && metadata.ctime() == snapshot.ctime
        && metadata.mode() == snapshot.mode
}

fn verify_file_revision(file: &fs::File, path: &str, before: &fs::Metadata) -> std::io::Result<()> {
    let handle_metadata = file.metadata()?;
    let path_metadata = fs::metadata(path)?;
    if !same_file_revision(before, &handle_metadata) || !same_file_revision(before, &path_metadata)
    {
        return Err(std::io::Error::other("file changed during rewrite"));
    }
    Ok(())
}

struct RemoveRewriteTemp(String);
impl Drop for RemoveRewriteTemp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn find_matches(
    hay: &[u8],
    needle: &[u8],
    icase: bool,
    regex: Option<&regex::bytes::Regex>,
) -> Result<Vec<(usize, usize)>, String> {
    let mut out = Vec::new();
    if let Some(re) = regex {
        for m in re.find_iter(hay) {
            if m.start() == m.end() {
                return Err("pattern may match an empty string".to_string());
            }
            out.push((m.start(), m.end()));
        }
        return Ok(out);
    }
    let mut offsets = Vec::new();
    find_literal_all(hay, needle, icase, 0, &mut offsets);
    let mut next = 0;
    for at in offsets {
        if at >= next {
            out.push((at, at + needle.len()));
            next = at + needle.len();
        }
    }
    Ok(out)
}

pub fn authorized(st: &AppState, headers: &HeaderMap, _params: &Params) -> bool {
    let key = match st.auth_key() {
        Some(key) => key,
        None => return false,
    };
    let now = meta::now_secs();
    let token = match auth::cookie_value(
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
        auth::COOKIE_NAME,
    ) {
        Some(token) => token,
        None => return false,
    };
    let payload = match auth::verify_token(&key, &token, now) {
        Some(payload) => payload,
        None => return false,
    };
    if !payload
        .get("perm")
        .and_then(|v| v.as_str())
        .map(|perm| perm == "session" || perm == "write")
        .unwrap_or(false)
    {
        return false;
    }
    let id = payload.get("sid").and_then(|v| v.as_str()).unwrap_or("");
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    !id.is_empty() && !username.is_empty() && st.sessions.touch(id, now)
}

#[cfg(test)]
mod search_replace_tests {
    use super::{replace_stream, ReplacePlan, CHUNK};
    use std::io::Cursor;

    #[test]
    fn replace_all_handles_matches_crossing_stream_chunks() {
        let mut input = vec![b'a'; CHUNK + 8];
        input[CHUNK - 1..CHUNK + 2].copy_from_slice(b"xyz");
        input[CHUNK + 4..CHUNK + 7].copy_from_slice(b"xyz");
        let mut output = Vec::new();
        let plan = ReplacePlan {
            needle: b"xyz".to_vec(),
            repl: b"Q".to_vec(),
            icase: false,
            regex: None,
            range: None,
        };
        let (replaced, written) = replace_stream(
            &mut Cursor::new(&input),
            &mut output,
            &plan,
            input.len() as u64,
            &|_| {},
        )
        .unwrap();
        assert_eq!(replaced, 2);
        assert_eq!(written, output.len() as u64);
        assert_eq!(&output[CHUNK - 1..CHUNK], b"Q");
        assert_eq!(&output[CHUNK + 2..CHUNK + 3], b"Q");
        assert_eq!(output.len(), input.len() - 4);
    }

    #[test]
    fn replace_current_range_replaces_only_selected_match() {
        let input = b"abcdef";
        let mut output = Vec::new();
        let plan = ReplacePlan {
            needle: Vec::new(),
            repl: b"XYZ".to_vec(),
            icase: false,
            regex: None,
            range: Some((2, 3)),
        };
        let (replaced, written) = replace_stream(
            &mut Cursor::new(input),
            &mut output,
            &plan,
            input.len() as u64,
            &|_| {},
        )
        .unwrap();
        assert_eq!(replaced, 1);
        assert_eq!(written, 6);
        assert_eq!(output, b"abXYZf");
    }
}

#[cfg(test)]
mod shared_search_regressions {
    use super::*;
    use std::io::{Cursor, Read};

    struct ShortReader<'a> {
        inner: Cursor<&'a [u8]>,
        max: usize,
    }
    impl Read for ShortReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let n = output.len().min(self.max);
            self.inner.read(&mut output[..n])
        }
    }
    fn search(bytes: &[u8], params: &Params, max_read: usize) -> Value {
        let plan = prepare_search(params, bytes.len() as u64).unwrap();
        let mut reader = ShortReader {
            inner: Cursor::new(&bytes[plan.read_start() as usize..]),
            max: max_read,
        };
        scan_search(&mut reader, "/test", &plan, &AtomicBool::new(false)).unwrap()
    }
    fn params(query: &str) -> Params {
        let mut p = Params::default();
        p.set("q", query);
        p
    }
    fn offsets(value: &Value) -> Vec<u64> {
        value["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect()
    }

    #[test]
    fn literal_crosses_chunks_and_progressive_windows() {
        let mut bytes = vec![b'~'; CHUNK * 2 + 32];
        let starts = [CHUNK - 2, CHUNK + 12, CHUNK * 2 - 1];
        for start in starts {
            bytes[start..start + 5].copy_from_slice(b"abcde");
        }
        let mut p = params("abcde");
        p.set("limit", "1000");
        assert_eq!(offsets(&search(&bytes, &p, 31)), starts.map(|n| n as u64));
        p.set("scan_bytes", &CHUNK.to_string());
        let first = search(&bytes, &p, 113);
        assert_eq!(offsets(&first), vec![(CHUNK - 2) as u64]);
        assert_eq!(first["scanned_to"], json!(CHUNK + 3));
        p.set("start", &first["scanned_to"].to_string());
        let second = search(&bytes, &p, 79);
        assert_eq!(
            offsets(&second),
            vec![(CHUNK + 12) as u64, (CHUNK * 2 - 1) as u64]
        );
        assert_eq!(second["done"], json!(false));
        p.set("start", &second["scanned_to"].to_string());
        let third = search(&bytes, &p, 79);
        assert!(offsets(&third).is_empty());
        assert_eq!(third["done"], json!(true));
    }

    #[test]
    fn pages_do_not_repeat_or_overlap_and_last_before_are_consistent() {
        let bytes = b"ab".repeat(2501);
        let mut p = params("ab");
        p.set("limit", "1000");
        let first = search(&bytes, &p, CHUNK);
        assert_eq!(offsets(&first).len(), 1000);
        assert_eq!(first["next"], json!(2000));
        p.set("start", "2000");
        let second = search(&bytes, &p, CHUNK);
        assert_eq!(offsets(&second).first(), Some(&2000));
        assert_eq!(second["next"], json!(4000));
        p.set("start", "4000");
        let third = search(&bytes, &p, CHUNK);
        assert_eq!(offsets(&third).len(), 501);
        assert_eq!(third["next"], Value::Null);
        p.set("start", "0");
        p.set("limit", "10");
        p.set("last", "1");
        let last = search(&bytes, &p, 51);
        assert_eq!(
            offsets(&last),
            (2491..2501).map(|i| i * 2).collect::<Vec<u64>>()
        );
        assert_eq!(last["below"], json!(2491));
        p.set("last", "0");
        p.set("before", "2000");
        let before = search(&bytes, &p, 17);
        assert_eq!(
            offsets(&before),
            (990..1000).map(|i| i * 2).collect::<Vec<u64>>()
        );
        assert_eq!(before["below"], json!(990));
    }

    #[test]
    fn hex_and_ascii_case_behave_identically_under_short_reads() {
        let bytes = b"aB--Ab--ab--AA";
        let mut p = params("ab");
        p.set("ignorecase", "1");
        assert_eq!(offsets(&search(bytes, &p, 1)), vec![0, 4, 8]);
        p.set("q", "41 62");
        p.set("encoding", "hex");
        assert_eq!(offsets(&search(bytes, &p, 2)), vec![4]);
    }

    #[test]
    fn bounded_regex_crosses_chunk_boundaries() {
        let mut bytes = vec![b'x'; CHUNK + 500];
        let start = CHUNK - 100;
        bytes[start] = b'a';
        bytes[start + 301] = b'b';
        let mut p = params("(?-u:a.{300}b)");
        p.set("regex", "1");
        let result = search(&bytes, &p, CHUNK);
        assert_eq!(offsets(&result), vec![start as u64]);
        assert_eq!(result["lengths"], json!([302]));
    }

    #[test]
    fn pathological_repetition_is_rejected_before_search_and_replace() {
        let mut p = params("a{1,50000}b");
        p.set("regex", "1");
        p.set("r", "x");
        assert!(prepare_search(&p, 1_000_000)
            .err()
            .unwrap()
            .contains("too complex"));
        assert!(parse_replace(&p).err().unwrap().1.contains("too complex"));
        p.set("q", "(?:a{512}){512}");
        assert!(prepare_search(&p, 1_000_000).is_err());
    }

    #[test]
    fn literal_near_matches_use_linear_scan() {
        let mut bytes = vec![b'a'; CHUNK * 2];
        bytes.push(b'b');
        let needle = format!("{}b", "a".repeat(4095));
        let result = search(&bytes, &params(&needle), CHUNK);
        assert_eq!(offsets(&result), vec![(bytes.len() - needle.len()) as u64]);
    }

    #[test]
    fn regex_anchors_and_greedy_matches_use_real_file_context() {
        let mut p = params("^ab");
        p.set("regex", "1");
        p.set("start", "2");
        assert!(offsets(&search(b"zzab", &p, 2)).is_empty());
        p.set("q", "a+");
        p.set("start", "0");
        let mut bytes = vec![b'~'; CHUNK - 5];
        bytes.extend(vec![b'a'; 40_000]);
        bytes.push(b'~');
        let result = search(&bytes, &p, 997);
        assert_eq!(offsets(&result), vec![(CHUNK - 5) as u64]);
        assert_eq!(result["lengths"], json!([40000]));
        p.set("q", "a$");
        let mut bytes = vec![b'x'; CHUNK];
        bytes[CHUNK - 1] = b'a';
        bytes.push(b'x');
        assert!(offsets(&search(&bytes, &p, CHUNK)).is_empty());
    }

    #[test]
    fn bounded_regex_stream_matches_reference_on_many_boundaries() {
        let mut bytes = Vec::new();
        for i in 0..80000 {
            bytes.extend_from_slice(if i % 3 == 0 { b"aaabb_" } else { b"ab___X" });
        }
        let mut p = params("a{1,3}b{1,2}");
        p.set("regex", "1");
        p.set("scan_bytes", "65536");
        p.set("limit", "1000");
        let expected: Vec<(u64, u64)> = regex::bytes::Regex::new("a{1,3}b{1,2}")
            .unwrap()
            .find_iter(&bytes)
            .map(|m| (m.start() as u64, (m.end() - m.start()) as u64))
            .collect();
        let mut found = Vec::new();
        let mut cursor = 0u64;
        // Page using `next`; it returns last match end if a window is capped.
        loop {
            p.set("start", &cursor.to_string());
            let result = search(&bytes, &p, 257);
            let page = offsets(&result);
            let lengths = result["lengths"].as_array().unwrap();
            found.extend(
                page.iter()
                    .zip(lengths)
                    .map(|(at, len)| (*at, len.as_u64().unwrap())),
            );
            match result["next"].as_u64() {
                Some(next) => {
                    assert!(next > cursor);
                    cursor = next;
                }
                None => break,
            }
        }
        assert_eq!(found, expected);
    }

    #[test]
    fn rejects_unsupported_large_context_empty_patterns_and_short_files() {
        let mut p = params("a+");
        p.set("regex", "1");
        assert!(prepare_search(&p, REGEX_FULL_MAX + 1).is_err());
        p.set("q", "a{1,3}");
        assert!(prepare_search(&p, REGEX_FULL_MAX + 1).is_ok());
        p.set("q", "a*");
        assert!(prepare_search(&p, 5).is_err());
        let p = params("test");
        let plan = prepare_search(&p, 20).unwrap();
        let mut reader = Cursor::new(b"too short");
        assert!(scan_search(&mut reader, "/test", &plan, &AtomicBool::new(false)).is_err());
        let mut reader = Cursor::new(b"ignored");
        assert!(scan_search(&mut reader, "/test", &plan, &AtomicBool::new(true)).is_err());
    }

    #[test]
    fn progress_keys_and_generations_are_isolated() {
        let mut a = Params::default();
        a.set("progress_id", "one");
        let mut b = Params::default();
        b.set("progress_id", "two");
        let first = ReplaceProgress::start("device-a", "/file", &a);
        first.update(10, 100);
        let second = ReplaceProgress::start("device-a", "/file", &b);
        second.update(20, 100);
        let remote = ReplaceProgress::start("device-b", "/file", &a);
        remote.update(30, 100);
        let replacement = ReplaceProgress::start("device-a", "/file", &a);
        replacement.update(40, 100);
        first.update(99, 100);
        drop(first);
        let map = replace_progress_map().lock().unwrap();
        assert_eq!(map[&replace_progress_key("device-a", "/file", &a)].1, 40);
        assert_eq!(map[&replace_progress_key("device-a", "/file", &b)].1, 20);
        assert_eq!(map[&replace_progress_key("device-b", "/file", &a)].1, 30);
        drop(map);
        drop(replacement);
        drop(second);
        drop(remote);
        let map = replace_progress_map().lock().unwrap();
        assert!(!map.contains_key(&replace_progress_key("device-a", "/file", &a)));
    }

    #[test]
    fn regex_rewrite_handles_long_greedy_and_anchors_and_checks_short_input() {
        let mut p = params("a+");
        p.set("regex", "1");
        p.set("r", "X");
        let plan = parse_replace(&p).unwrap();
        let bytes = b"a".repeat(CHUNK + 20000);
        let mut output = Vec::new();
        assert_eq!(
            replace_stream(
                &mut Cursor::new(&bytes),
                &mut output,
                &plan,
                bytes.len() as u64,
                &|_| {}
            )
            .unwrap(),
            (1, 1)
        );
        assert_eq!(output, b"X");
        let mut output = Vec::new();
        assert!(replace_stream(&mut Cursor::new(b"aaa"), &mut output, &plan, 4, &|_| {}).is_err());
        let mut p = params("^a");
        p.set("regex", "1");
        p.set("r", "Z");
        let plan = parse_replace(&p).unwrap();
        let mut bytes = vec![b'x'; CHUNK * 2];
        bytes[0] = b'a';
        bytes[CHUNK] = b'a';
        let mut output = Vec::new();
        let (count, _) = replace_stream(
            &mut Cursor::new(&bytes),
            &mut output,
            &plan,
            bytes.len() as u64,
            &|_| {},
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(output[0], b'Z');
        assert_eq!(output[CHUNK], b'a');
    }
}
