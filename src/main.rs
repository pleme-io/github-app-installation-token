//! `pleme-io/github-app-installation-token` — issue an installation access
//! token from GitHub App credentials.
//!
//! Auth primitive consumed by any workflow that needs to act as a GitHub App
//! identity rather than `GITHUB_TOKEN` (cross-repo dispatch, write access to
//! protected branches, attestation signing, etc).
//!
//! Reads the App's id + installation_id + private_key (PEM) as inputs, signs
//! a short-lived JWT, exchanges it via
//! `POST /app/installations/{id}/access_tokens`, masks the resulting token in
//! the runner log, and emits it as an output the consumer references via
//! `${{ steps.<id>.outputs.token }}`.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, EncodingKey, Header};
use pleme_actions_shared::{ActionError, Input, Output, StepSummary};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Inputs {
    app_id: String,
    installation_id: String,
    /// Full PEM (BEGIN RSA PRIVATE KEY ... END RSA PRIVATE KEY).
    private_key: String,
    /// Optional repository scope — when set, the token is scoped to those
    /// repos only. Format: comma-separated `owner/repo` slugs.
    #[serde(default)]
    repositories: Option<String>,
    /// Optional permissions scope JSON, e.g. `{"contents":"read","actions":"write"}`.
    #[serde(default)]
    permissions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: serde_json::Value,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    pleme_actions_shared::log::init();
    if let Err(e) = run().await {
        e.emit_to_stdout();
        if e.is_fatal() {
            std::process::exit(1);
        }
    }
}

async fn run() -> Result<(), ActionError> {
    let inputs = Input::<Inputs>::from_env()?;
    let app_id_u64: u64 = inputs.app_id.parse().map_err(|_| {
        ActionError::error(format!("input app-id must be a numeric string (got `{}`)", inputs.app_id))
    })?;
    let jwt = sign_app_jwt(app_id_u64, &inputs.private_key)?;
    let response = exchange_for_installation_token(&jwt, &inputs.installation_id, &inputs).await?;

    // Mask the token in the runner log so it doesn't appear in subsequent
    // step output. GitHub Actions specifically scrubs values logged via
    // `::add-mask::`.
    println!("::add-mask::{}", response.token);

    let output = Output::from_runner_env()?;
    output.set("token", &response.token)?;
    output.set("expires-at", &response.expires_at)?;

    let mut summary = StepSummary::from_runner_env()?;
    summary
        .heading(2, "github-app-installation-token")
        .table(
            &["Field", "Value"],
            vec![
                vec!["app-id".into(), inputs.app_id.clone()],
                vec!["installation-id".into(), inputs.installation_id.clone()],
                vec!["expires-at".into(), response.expires_at.clone()],
                vec![
                    "permissions".into(),
                    response.permissions.to_string(),
                ],
            ],
        );
    summary.commit()?;

    Ok(())
}

fn sign_app_jwt(app_id: u64, private_key_pem: &str) -> Result<String, ActionError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| ActionError::error(format!("system clock before epoch: {e}")))?;
    let claims = AppJwtClaims {
        iat: now - 60,        // backdate 1 min for clock skew
        exp: now + 9 * 60,    // GitHub max is 10 min
        iss: app_id.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| ActionError::error(format!("failed to parse RSA private key: {e}")))?;
    encode(&Header::new(jsonwebtoken::Algorithm::RS256), &claims, &key)
        .map_err(|e| ActionError::error(format!("failed to sign JWT: {e}")))
}

async fn exchange_for_installation_token(
    jwt: &str,
    installation_id: &str,
    inputs: &Inputs,
) -> Result<InstallationTokenResponse, ActionError> {
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let mut body = serde_json::Map::new();
    if let Some(repos_csv) = &inputs.repositories {
        let repos: Vec<&str> = repos_csv.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        // Format expected: array of repo names (not full slugs) when using `repositories`,
        // or full slugs when using `repository_ids`. We accept the slug form for clarity
        // and split into bare names; consumers using the slug form `owner/repo` get the
        // tail used as the repo name.
        let repo_names: Vec<&str> = repos.iter().map(|s| s.rsplit('/').next().unwrap_or(s)).collect();
        body.insert(
            "repositories".into(),
            serde_json::Value::Array(repo_names.into_iter().map(|s| serde_json::Value::String(s.to_string())).collect()),
        );
    }
    if let Some(perms) = &inputs.permissions {
        body.insert("permissions".into(), perms.clone());
    }
    let response = reqwest::Client::new()
        .post(&url)
        .header("User-Agent", "pleme-io/github-app-installation-token")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| ActionError::error(format!("HTTP request failed: {e}")))?;
    let status = response.status();
    let body_text = response.text().await
        .map_err(|e| ActionError::error(format!("failed to read response body: {e}")))?;
    if !status.is_success() {
        return Err(ActionError::error(format!(
            "installation-token request returned {status}: {body_text}"
        )));
    }
    serde_json::from_str(&body_text)
        .map_err(|e| ActionError::error(format!("failed to parse installation-token response: {e} (body: {body_text})")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture — generated with `openssl genrsa 2048`. NEVER used for
    /// real auth. See tests/fixtures/test-rsa.pem.
    const TEST_PEM: &str = include_str!("../tests/fixtures/test-rsa.pem");

    #[test]
    fn jwt_signs_with_test_key() {
        let jwt = sign_app_jwt(12345, TEST_PEM).unwrap();
        // 3 dot-separated segments
        assert_eq!(jwt.matches('.').count(), 2);
        assert!(!jwt.is_empty());
    }

    #[test]
    fn jwt_rejects_garbage_pem() {
        let err = sign_app_jwt(12345, "not a pem").unwrap_err();
        assert!(err.as_workflow_command().contains("RSA private key"));
    }
}
