use super::runtime;
use super::Target;
use russh::client::{AuthResult, Handler, KeyboardInteractiveAuthResponse};
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct ClientHandler {
    expected: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl ClientHandler {
    pub fn new(expected: Option<String>, seen: Arc<Mutex<Option<String>>>) -> Self {
        ClientHandler { expected, seen }
    }
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = fingerprint_public(&server_public_key.public_key());
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(fp.clone());
        }
        match self.expected.as_deref() {
            None | Some("") => Ok(true),
            Some(expected) => Ok(expected == fp),
        }
    }
}

pub fn fingerprint_public(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

pub async fn authenticate(
    handle: &mut russh::client::Handle<ClientHandler>,
    target: &Target,
) -> Result<(), String> {
    let user = target.username.clone();
    let password = target.password.clone().unwrap_or_default();
    match handle
        .authenticate_password(&user, &password)
        .await
        .map_err(|error| error.to_string())?
    {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure { .. } => {}
    }
    let mut response = handle
        .authenticate_keyboard_interactive_start(&user, None)
        .await
        .map_err(|error| error.to_string())?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure { .. } => {
                return Err("SSH authentication failed".to_string());
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let replies = prompts.iter().map(|_| password.clone()).collect();
                response = handle
                    .authenticate_keyboard_interactive_respond(replies)
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    }
}

pub fn probe_host_key(
    target: &Target,
    _workspace: &super::Workspace,
) -> Result<(String, String), String> {
    runtime::block_on(probe_host_key_async(target))
}

async fn probe_host_key_async(target: &Target) -> Result<(String, String), String> {
    let seen = Arc::new(Mutex::new(None));
    let handler = ClientHandler::new(None, Arc::clone(&seen));
    let config = russh::client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    };
    let handle = russh::client::connect(
        Arc::new(config),
        (target.host.as_str(), target.port),
        handler,
    )
    .await
    .map_err(|error| error.to_string())?;
    let fingerprint = seen
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .ok_or_else(|| "Cannot read SSH host key".to_string())?;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;
    Ok((fingerprint.clone(), fingerprint))
}

pub async fn connect_authenticated(
    target: &Target,
) -> Result<russh::client::Handle<ClientHandler>, String> {
    let expected = if target.host_key.is_empty() {
        None
    } else {
        Some(target.host_key.clone())
    };
    let seen = Arc::new(Mutex::new(None));
    let handler = ClientHandler::new(expected, seen);
    let config = russh::client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    };
    let mut handle = russh::client::connect(
        Arc::new(config),
        (target.host.as_str(), target.port),
        handler,
    )
    .await
    .map_err(|error| error.to_string())?;
    authenticate(&mut handle, target).await?;
    Ok(handle)
}
