//! harbor-core: the Rust backend + web UI for Harbor File Pro.

mod api;
mod archive_inspect;
mod atomic_u64;
mod auth;
mod config;
mod crypto;
mod i18n;
mod icons;
mod ioops;
mod limits;
mod meta;
mod params;
mod paths;
mod private_file;
mod remote;
mod remoteio;
mod remoteops;
mod reply;
#[cfg(test)]
mod root_policy_tests;
mod security;
mod ssh;
mod state;
mod task_registry;
mod tasks;
mod terminal;
mod tools;
mod transfers;
mod uci;
mod wallpapers;
mod web;

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use serde_json::json;
use state::{AppState, Settings};
use std::io::{IsTerminal, Read};
use std::sync::Arc;

const USAGE: &str = "\
harbor-core - Harbor File Pro backend

USAGE:
    harbor-core [serve] [options]
    harbor-core thumbnail-worker <manifest.json> <log>
    harbor-core hash-password [password]
    harbor-core init-auth [options]
    harbor-core reset-auth [options]
    harbor-core print-config

OPTIONS:
    -c, --config <path>       UCI config (default /etc/config/harbor_file_pro)
    -l, --listen <addr:port>  listen address (default 0.0.0.0:9700)
    -s, --state-dir <path>    secret + password storage (default /etc/harbor)
        --roots <a,b>         allow access only within these roots
        --exclude-roots <a,b> block these roots and their descendants
        --unrestricted        disable path root restrictions
        (use only one of --roots, --exclude-roots, --unrestricted)
        --workers <n>         tokio worker threads (default min(cpus, 4))
        --max-connections <n> concurrent request cap (default 16)
        --max-transfers <n>   concurrent transfer cap (default 4)
        --request-timeout <s> whole-request timeout (default 60)
        --session-ttl <s>     absolute session lifetime (default 43200)
        --session-idle <s>    log out after this idle time, 0 disables (default 7200)
        --no-session-sliding  keep the fixed expiry instead of renewing active sessions
        --dev                 load web assets from ./assets on disk (developer mode)
    -v, --version              print version and binary architecture
    -h, --help
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        run_server(settings_from_args(&[]));
        return;
    }
    match args[0].as_str() {
        "thumbnail-worker" => {
            let code = thumbnail_worker(
                args.get(1).map(|s| s.as_str()),
                args.get(2).map(|s| s.as_str()),
            );
            std::process::exit(code);
        }
        "init-auth" => std::process::exit(initialize_auth(&args[1..])),
        "reset-auth" => {
            let settings = settings_from_args(&args[1..]);
            if let Err(error) = security::reset_auth_dir(&settings.state_dir) {
                eprintln!("harbor-core: account reset failed: {error}");
                std::process::exit(1);
            }
            println!(
                "harbor-core: account reset - username is back to \"{}\" and no password is set",
                security::DEFAULT_USERNAME
            );
        }
        "hash-password" => {
            let password = match args.get(1) {
                Some(value) if !value.is_empty() => {
                    eprintln!("harbor-core: warning: password in argv is visible to local users; pipe it on stdin instead");
                    value.clone()
                }
                _ => {
                    let mut buffer = String::new();
                    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer).is_err() {
                        eprintln!("usage: harbor-core hash-password [password]");
                        std::process::exit(2);
                    }
                    buffer.trim_end_matches(['\n', '\r']).to_string()
                }
            };
            if password.is_empty() {
                eprintln!("usage: harbor-core hash-password [password]");
                std::process::exit(2);
            }
            println!("{}", auth::hash_password(&password));
        }
        "print-config" => {
            let settings = settings_from_args(&args[1..]);
            println!("{settings:#?}");
        }
        "-v" | "--version" => {
            println!(
                "harbor-core {} ({})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::ARCH
            );
        }
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
        }
        "serve" => run_server(settings_from_args(&args[1..])),
        _ => run_server(settings_from_args(&args)),
    }
}

fn initialize_auth(args: &[String]) -> i32 {
    if std::io::stdin().is_terminal() {
        eprintln!("Account input must be piped from a no-echo prompt");
        eprintln!(
            "Use harbor-core init-auth with username and two matching password lines on stdin"
        );
        return 2;
    }

    let stdin = std::io::stdin();
    let mut input = String::new();
    if stdin.lock().take(2049).read_to_string(&mut input).is_err() || input.len() > 2048 {
        eprintln!("Invalid password input");
        return 2;
    }
    let lines: Vec<&str> = input.lines().collect();
    if lines.len() != 3 || lines[1] != lines[2] || !security::valid_username(lines[0].trim()) {
        eprintln!("A valid username and two matching password lines are required");
        return 2;
    }

    let state = AppState::new(settings_from_args(args));
    match security::initialize_password(&state, lines[1]) {
        Ok(()) => match security::set_username(&state, lines[0].trim()) {
            Ok(()) => {
                println!("harbor-core: authentication initialized");
                0
            }
            Err(()) => {
                let _ = std::fs::remove_file(state.password_file());
                eprintln!("harbor-core: cannot store the username");
                1
            }
        },
        Err(message) => {
            eprintln!("harbor-core: {message}");
            1
        }
    }
}

fn validate_root_policy_args(args: &[String]) {
    let has_allowlist = args.iter().any(|arg| arg == "--roots");
    let has_denylist = args.iter().any(|arg| arg == "--exclude-roots");
    let has_unrestricted = args.iter().any(|arg| arg == "--unrestricted");
    let selected = has_allowlist as usize + has_denylist as usize + has_unrestricted as usize;
    if selected > 1 {
        eprintln!(
            "harbor-core: --roots, --exclude-roots, and --unrestricted are mutually exclusive; choose one path policy"
        );
        std::process::exit(2);
    }
}

fn parse_root_list(value: &str, option: &str) -> Vec<String> {
    let mut roots = Vec::new();
    for item in value.split(',') {
        match paths::normalize_path(item.trim()) {
            Some(path) if !roots.contains(&path) => roots.push(path),
            Some(_) => {}
            None => {
                eprintln!("harbor-core: {option} requires comma-separated absolute paths");
                std::process::exit(2);
            }
        }
    }
    if roots.is_empty() {
        eprintln!("harbor-core: {option} requires at least one absolute path");
        std::process::exit(2);
    }
    roots
}

fn parse_uci_roots(values: &[String], option: &str) -> Vec<String> {
    let mut roots = Vec::new();
    for value in values {
        let Some(path) = paths::normalize_path(value.trim()) else {
            eprintln!("harbor-core: UCI option '{option}' requires absolute paths");
            std::process::exit(2);
        };
        if !roots.contains(&path) {
            roots.push(path);
        }
    }
    roots
}

fn settings_from_args(args: &[String]) -> Settings {
    validate_root_policy_args(args);
    let mut settings = Settings::default();
    if let Some(index) = args.iter().position(|arg| arg == "-c" || arg == "--config") {
        if let Some(path) = args.get(index + 1) {
            settings.config_path = path.clone();
        }
    }
    let cli_root_policy = args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--roots" | "--exclude-roots" | "--unrestricted"
        )
    });
    apply_uci(&mut settings, cli_root_policy);
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let take = |idx: usize| -> Option<String> { args.get(idx).cloned() };
        match arg {
            "-c" | "--config" => {
                if let Some(v) = take(i + 1) {
                    settings.config_path = v;
                    i += 1;
                }
            }
            "-l" | "--listen" => {
                if let Some(v) = take(i + 1) {
                    settings.listen = v;
                    i += 1;
                }
            }
            "-a" | "--auth" => {
                if let Some(v) = take(i + 1) {
                    if !v.eq_ignore_ascii_case("password") {
                        eprintln!("harbor-core: auth mode {v} is no longer supported; password authentication is mandatory");
                    }
                    i += 1;
                }
            }
            "-s" | "--state-dir" => {
                if let Some(v) = take(i + 1) {
                    settings.state_dir = v;
                    i += 1;
                }
            }
            "--roots" | "--exclude-roots" => {
                settings.root_policy_cli_override = true;
                let option = arg;
                let Some(value) = take(i + 1) else {
                    eprintln!("harbor-core: {option} requires a comma-separated path list");
                    std::process::exit(2);
                };
                let roots = parse_root_list(&value, option);
                if option == "--roots" {
                    settings.root_policy = state::RootPolicy::Allowlist;
                    settings.roots = roots;
                } else {
                    settings.root_policy = state::RootPolicy::Denylist;
                    settings.excluded_roots = roots;
                }
                i += 1;
            }
            "--unrestricted" => {
                settings.root_policy_cli_override = true;
                settings.root_policy = state::RootPolicy::Unrestricted;
            }
            "--workers" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<usize>() {
                        settings.workers = n.clamp(1, 16);
                    }
                    i += 1;
                }
            }
            "--max-connections" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<usize>() {
                        settings.max_connections = n.clamp(1, 512);
                    }
                    i += 1;
                }
            }
            "--max-transfers" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<usize>() {
                        settings.max_transfers = n.clamp(1, 64);
                    }
                    i += 1;
                }
            }
            "--session-ttl" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<i64>() {
                        settings.session_ttl = n.clamp(5, 30 * 86400);
                    }
                    i += 1;
                }
            }
            "--session-idle" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<i64>() {
                        settings.session_idle = n.clamp(0, 30 * 86400);
                    }
                    i += 1;
                }
            }
            "--no-session-sliding" => {
                settings.session_sliding = false;
            }
            "--dev" => {
                settings.dev_mode = true;
            }
            "--request-timeout" => {
                if let Some(v) = take(i + 1) {
                    if let Ok(n) = v.trim().parse::<u64>() {
                        settings.request_timeout = n.clamp(1, 3600);
                    }
                    i += 1;
                }
            }
            option if option.starts_with('-') => {
                eprintln!("harbor-core: unsupported option: {option}");
                std::process::exit(2);
            }
            _ => {}
        }
        i += 1;
    }
    settings
}

fn apply_uci(settings: &mut Settings, skip_root_policy: bool) {
    let uci = match uci::Uci::load(&settings.config_path) {
        Some(u) => u,
        None => return,
    };
    let sec = match uci.section(config::CONFIG_SECTION) {
        Some(s) => s,
        None => return,
    };
    if let Some(v) = sec.get("listen") {
        if !v.trim().is_empty() {
            settings.listen = v.trim().to_string();
        }
    }
    if let Some(port) = sec.get("port").and_then(|p| p.trim().parse::<u16>().ok()) {
        let host = settings
            .listen
            .rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        settings.listen = format!("{host}:{port}");
    }
    if let Some(v) = sec
        .get("session_ttl")
        .and_then(|v| v.trim().parse::<i64>().ok())
    {
        if (300..=30 * 86400).contains(&v) {
            settings.session_ttl = v;
        }
    }
    if let Some(v) = sec
        .get("session_idle")
        .and_then(|v| v.trim().parse::<i64>().ok())
    {
        if (0..=30 * 86400).contains(&v) {
            settings.session_idle = v;
        }
    }
    if let Some(v) = sec.get("session_sliding") {
        settings.session_sliding = !matches!(v.trim(), "0" | "off" | "false" | "no");
    }
    if !skip_root_policy {
        let raw_roots = sec.get_all("root");
        let raw_excluded_roots = sec.get_all("exclude_root");
        let roots = parse_uci_roots(&raw_roots, "root");
        let excluded_roots = parse_uci_roots(&raw_excluded_roots, "exclude_root");
        let policy = match state::RootPolicyConfig::from_uci(
            sec.get("root_policy"),
            roots,
            excluded_roots,
        ) {
            Ok(policy) => policy,
            Err(error) => {
                eprintln!("harbor-core: {error}");
                std::process::exit(2);
            }
        };
        settings.root_policy = policy.policy;
        settings.roots = policy.roots;
        settings.excluded_roots = policy.excluded_roots;
    }
    if let Some(v) = sec.get("secure_cookie") {
        settings.secure_cookie = v == "1";
    }
    if let Some(v) = sec.get("dev_mode") {
        if matches!(v.trim(), "1" | "on" | "true" | "yes") {
            settings.dev_mode = true;
        }
    }
    let numbers: [(&str, &mut usize, usize, usize); 3] = [
        ("workers", &mut settings.workers, 0, 16),
        ("max_connections", &mut settings.max_connections, 1, 512),
        ("max_transfers", &mut settings.max_transfers, 1, 64),
    ];
    for (key, slot, low, high) in numbers {
        if let Some(value) = sec.get(key).and_then(|v| v.trim().parse::<usize>().ok()) {
            *slot = value.clamp(low, high);
        }
    }
    let durations: [(&str, &mut u64, u64, u64); 2] = [
        ("request_timeout", &mut settings.request_timeout, 1, 3600),
        (
            "body_idle_timeout",
            &mut settings.body_idle_timeout,
            1,
            3600,
        ),
    ];
    for (key, slot, low, high) in durations {
        if let Some(value) = sec.get(key).and_then(|v| v.trim().parse::<u64>().ok()) {
            *slot = value.clamp(low, high);
        }
    }
    let sizes: [(&str, &mut u64, u64, u64); 2] = [
        (
            "chunk_size",
            &mut settings.chunk_size,
            64 * 1024,
            64 * 1024 * 1024,
        ),
        (
            "chunk_limit",
            &mut settings.chunk_limit,
            64 * 1024,
            1024 * 1024 * 1024,
        ),
    ];
    for (key, slot, low, high) in sizes {
        if let Some(value) = sec.get(key).and_then(|v| v.trim().parse::<u64>().ok()) {
            *slot = value.clamp(low, high);
        }
    }
    if let Some(value) = sec
        .get("upload_session_hours")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        settings.upload_session_hours = value.clamp(1, 24 * 30);
    }
    if let Some(value) = sec
        .get("transfer_history")
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        settings.transfer_history = value.clamp(8, 4096);
    }
    if settings.chunk_limit < settings.chunk_size {
        settings.chunk_limit = settings.chunk_size;
    }
}

fn run_server(settings: Settings) {
    // The runtime has global compatibility links and upload staging. Without
    // an interprocess lease, another daemon could expire a live upload.
    let _runtime_lock = match crate::tasks::lock_runtime_instance() {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("harbor-core: cannot acquire runtime lock: {error}");
            std::process::exit(1);
        }
    };
    let workers = if settings.workers > 0 {
        settings.workers
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 4))
            .unwrap_or(2)
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(workers)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("harbor-core: cannot start runtime: {e}");
            std::process::exit(1);
        }
    };
    runtime.block_on(async move {
        let listen = settings.listen.clone();
        let state = AppState::new(settings);
        web::set_dev_mode(state.settings.dev_mode);
        crate::paths::init_tmp_journal(&state.settings.state_dir);
        crate::paths::cleanup_tmp_journal();
        if let Err(error) = state.rotate_auth_key() {
            eprintln!("harbor-core: cannot rotate session signing key: {error}");
            std::process::exit(1);
        }
        let app = build_router(state.clone());
        let listener = match tokio::net::TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("harbor-core: cannot listen on {listen}: {e}");
                std::process::exit(1);
            }
        };
        eprintln!(
            "harbor-core {} listening on http://{} (password authentication, assets: {})",
            state.settings.version,
            listen,
            web::ASSET_COUNT
        );
        if state.password_hash().is_none() {
            eprintln!("harbor-core: no password set; run harbor-core init-auth locally");
        }
        crate::api::transferops::start_upload_maintenance(&state);
        let shutdown = async {
            let mut term =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(signal) => signal,
                    Err(_) => {
                        let _ = tokio::signal::ctrl_c().await;
                        return;
                    }
                };
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            eprintln!("harbor-core: shutting down, upload sessions are kept for resume");
        };
        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
        {
            eprintln!("harbor-core: server error: {e}");
        }
    });
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/index.html", get(index))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/healthz", get(health))
        .route("/io", any(io_endpoint))
        .route("/io/{*tail}", any(io_endpoint))
        .route("/assets/icons.svg", any(icon_sprite))
        .route("/wallpapers/custom/{name}", get(custom_wallpaper))
        .route("/wallpapers/{key}", any(builtin_wallpaper))
        .route("/assets/{*path}", any(asset))
        .route("/favicon.ico", any(favicon))
        .route("/api/v1/terminal/ws", get(terminal::ws_endpoint))
        .route(
            "/api/v1/{name}",
            any(api::dispatch).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::limits::session_refresh,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::limits::guard,
        ))
        .fallback(any(fallback))
        .with_state(state)
}

async fn health(State(st): State<Arc<AppState>>) -> Response {
    api::health(st).await
}

async fn index(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !ioops::authorized(&st, &headers, &params::Params::default()) {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/login")
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    web::serve_asset(&headers, &Method::GET, "index.html").await
}

async fn login_page() -> Response {
    web::serve_asset(&HeaderMap::new(), &Method::GET, "login.html").await
}

async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(key) = st.auth_key() {
        if let Some(token) = auth::cookie_value(
            headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
            auth::COOKIE_NAME,
        ) {
            if let Some(payload) = auth::verify_token(&key, &token, meta::now_secs()) {
                if let Some(id) = payload.get("sid").and_then(|v| v.as_str()) {
                    st.sessions.forget(id);
                    st.system_access.revoke_session(id);
                }
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, auth::clear_cookie())
        .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
        .body(Body::from("{\"code\":0,\"message\":\"success\"}"))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn login_submit(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let lang = i18n::Lang::default();
    let bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return bad_login(lang, "Invalid request", None),
    };
    let form = params::Params::parse(&String::from_utf8_lossy(&bytes));
    let lang = i18n::lang_for(&parts.headers, &form);
    let client_ip = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let now = meta::now_secs();
    if let Some(locked_until) = st.login_limiter.blocked_until(&client_ip, now) {
        if locked_until == i64::MAX {
            return bad_login(
                lang,
                "Account locked",
                Some(json!({
                    "locked_until": locked_until,
                    "is_permanent": true,
                    "remaining_attempts": 0,
                })),
            );
        }
        return bad_login(
            lang,
            "Too many login attempts",
            Some(json!({
                "locked_until": locked_until,
                "is_permanent": false,
                "remaining_attempts": 0,
            })),
        );
    }
    let password = form.get("password").unwrap_or_default();
    let username = form
        .get("username")
        .unwrap_or_else(|| security::username(&st));
    let totp_code = form
        .get("totp")
        .or_else(|| form.get("code"))
        .unwrap_or_default();

    let existing = match st.password_hash() {
        Some(hash) => hash,
        None => {
            return bad_login(
                lang,
                "Authentication is not initialized; run harbor-core init-auth on the device",
                None,
            )
        }
    };
    let username_matches = security::matches_user(&st, &username);
    let verify_stored = existing.clone();
    let verify_given = password.to_string();
    let password_matches =
        tokio::task::spawn_blocking(move || auth::verify_password(&verify_given, &verify_stored))
            .await
            .unwrap_or(false);
    if !username_matches || !password_matches {
        let result = st.login_limiter.record_failure(&client_ip, now);
        eprintln!("harbor-core: failed login from {client_ip}");
        match result {
            Some(res) if res.is_permanent => {
                return bad_login(
                    lang,
                    "账户已锁定",
                    Some(json!({
                        "locked_until": res.locked_until,
                        "is_permanent": true,
                        "remaining_attempts": 0,
                    })),
                );
            }
            Some(res) if res.locked_until.is_some() => {
                return bad_login(
                    lang,
                    "Too many login attempts",
                    Some(json!({
                        "locked_until": res.locked_until,
                        "is_permanent": false,
                        "remaining_attempts": 0,
                    })),
                );
            }
            Some(res) => {
                return bad_login(
                    lang,
                    "Wrong username or password",
                    Some(json!({
                        "locked_until": null,
                        "is_permanent": false,
                        "remaining_attempts": res.remaining_attempts,
                    })),
                );
            }
            None => {
                return bad_login(lang, "Wrong username or password", None);
            }
        }
    }
    if security::is_enabled(&st) {
        if totp_code.trim().is_empty() {
            let _ = st.login_limiter.record_failure(&client_ip, now);
            let body = json!({
                "code": 2,
                "message": i18n::translate_in(lang, "Two-factor code required"),
                "data": { "totp_required": true }
            });
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
                .body(Body::from(body.to_string()))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        if !security::verify_active_code(&st, &totp_code) {
            let _ = st.login_limiter.record_failure(&client_ip, now);
            return bad_login(lang, "Invalid two-factor code", None);
        }
    }
    if auth::password_needs_rehash(&existing) && st.set_password(&password).is_err() {
        eprintln!("harbor-core: could not upgrade password hash");
    }
    st.login_limiter.record_success(&client_ip);
    let key = match st.auth_key() {
        Some(key) => key,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let (session, sid, exp) = auth::make_session(
        &key,
        &security::username(&st),
        st.settings.session_ttl,
        "session",
    );
    if !st.sessions.register(&sid, meta::now_secs(), exp) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let cookie_ttl = auth::cookie_ttl(st.settings.session_ttl, st.settings.session_idle);
    let cookie = auth::session_cookie(&session, cookie_ttl, st.settings.secure_cookie);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(
            "{\"code\":0,\"message\":\"success\",\"data\":{}}",
        ))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn bad_login(lang: i18n::Lang, message: &str, data: Option<serde_json::Value>) -> Response {
    let mut body = json!({ "code": 1, "message": i18n::translate_in(lang, message) });
    if let Some(data) = data {
        body.as_object_mut()
            .unwrap()
            .insert("data".to_string(), data);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn asset(Path(path): Path<String>, req: Request) -> Response {
    let headers = req.headers().clone();
    let full = format!("assets/{path}");
    web::serve_asset(&headers, &Method::GET, &full).await
}

async fn icon_sprite(headers: HeaderMap, method: Method) -> Response {
    match icons::sprite() {
        Some(sprite) => web::serve_bytes(
            &headers,
            &method,
            sprite.as_bytes(),
            "image/svg+xml",
            web::IMMUTABLE,
        ),
        None => (StatusCode::NOT_FOUND, "no icons bundled").into_response(),
    }
}

async fn builtin_wallpaper(
    Path(key): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    if matches!(key.as_str(), "img1" | "img2") {
        let path = format!("assets/wallpapers/{key}.jpg");
        return web::serve_asset(&headers, &method, &path).await;
    }
    match wallpapers::svg(&key) {
        Some(svg) => web::serve_bytes(
            &headers,
            &method,
            svg.as_bytes(),
            "image/svg+xml",
            web::IMMUTABLE,
        ),
        None => (StatusCode::NOT_FOUND, "no such built-in wallpaper").into_response(),
    }
}

async fn custom_wallpaper(
    State(st): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    if !wallpapers::valid_custom_name(&name) {
        return (StatusCode::NOT_FOUND, "no such wallpaper").into_response();
    }
    let prefs = st.prefs();
    let is_current = prefs.wallpaper_enabled != 0
        && prefs.wallpaper_login_enabled != 0
        && prefs.wallpaper_source == "custom"
        && prefs.wallpaper_id == wallpapers::custom_id(&name);
    if !is_current && !ioops::authorized(&st, &headers, &params::Params::default()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let path = wallpapers::custom_dir(&st).join(&name);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::NOT_FOUND, "no such wallpaper").into_response(),
    };
    let mime = meta::image_mime(name.rsplit('.').next().unwrap_or(""))
        .unwrap_or("application/octet-stream");
    web::serve_bytes(&headers, &method, &bytes, mime, "private, max-age=60")
}

async fn favicon(headers: HeaderMap, method: Method) -> Response {
    web::serve_asset(&headers, &method, "assets/favicon.svg").await
}

async fn io_endpoint(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers.clone();
    let method = parts.method.clone();
    let mut params = params::Params::parse(parts.uri.query().unwrap_or(""));
    let raw_path = parts.uri.path().to_string();
    let path_suffix = raw_path.strip_prefix("/io/").and_then(|tail| {
        let decoded = crate::params::urldecode_path(tail);
        let trimmed = decoded.trim_start_matches('/').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(format!("/{trimmed}"))
        }
    });
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let (req, params) = if method == Method::POST
        && content_type.starts_with("application/x-www-form-urlencoded")
    {
        let body = match axum::body::to_bytes(body, 64 * 1024).await {
            Ok(body) => body,
            Err(_) => {
                return reply::fail_status(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    1,
                    "Request body too large",
                    serde_json::Value::Null,
                );
            }
        };
        let Some(form) = params::parse_form(&body, 64 * 1024) else {
            return reply::fail_status(
                StatusCode::PAYLOAD_TOO_LARGE,
                1,
                "Request body too large",
                serde_json::Value::Null,
            );
        };
        params.merge(form);
        if let Some(path) = &path_suffix {
            params.set("path", path);
        }
        if path_suffix.is_some() && params.get("mode").is_none() {
            params.set("mode", "download");
        }
        (Request::from_parts(parts, Body::empty()), params)
    } else {
        if let Some(path) = &path_suffix {
            params.set("path", path);
        }
        if path_suffix.is_some() && params.get("mode").is_none() {
            params.set("mode", "download");
        }
        (Request::from_parts(parts, body), params)
    };

    let lang = i18n::lang_for(&headers, &params);
    i18n::scope(lang, async move {
        if !ioops::authorized(&st, &headers, &params) {
            return reply::fail_status(
                StatusCode::UNAUTHORIZED,
                1,
                "Authentication required",
                serde_json::Value::Null,
            );
        }
        ioops::handle(st, params, req).await
    })
    .await
}

async fn fallback(State(st): State<Arc<AppState>>, req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/').to_string();
    if path.is_empty() {
        return index(State(st), req.headers().clone()).await;
    }
    let headers = req.headers().clone();
    let response = web::serve_asset(&headers, &Method::GET, &path).await;
    if response.status() == StatusCode::NOT_FOUND {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    response
}

fn thumbnail_worker(manifest: Option<&str>, _log: Option<&str>) -> i32 {
    let manifest = match manifest {
        Some(m) => m,
        None => return 2,
    };
    let raw = match std::fs::read(manifest) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let value: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let size = value["size"].as_i64().unwrap_or(256);
    let jobs = value["jobs"].as_array().cloned().unwrap_or_default();
    let mut failures = 0;
    for job in jobs {
        let src = job["src"].as_str().unwrap_or("");
        let dst = job["dst"].as_str().unwrap_or("");
        if src.is_empty() || dst.is_empty() {
            continue;
        }
        println!("BEGIN {src}");
        let output = std::process::Command::new("gm")
            .args([
                "convert",
                src,
                "-auto-orient",
                "-thumbnail",
                &format!("{size}x{size}"),
                dst,
            ])
            .output();
        match output {
            Ok(out) if out.status.success() => println!("OK {src}"),
            Ok(out) => {
                failures += 1;
                let text = String::from_utf8_lossy(&out.stderr);
                println!("FAIL {src}");
                for line in text.lines() {
                    println!("  {line}");
                }
            }
            Err(e) => {
                failures += 1;
                println!("FAIL {src}");
                println!("  {e}");
            }
        }
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod cli_help_tests {
    use super::*;

    #[test]
    fn documented_connection_limit_matches_the_actual_default() {
        let help = USAGE
            .lines()
            .find(|line| line.contains("--max-connections"))
            .unwrap();
        assert!(help.contains(&format!("default {}", Settings::default().max_connections)));
    }
}
