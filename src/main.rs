use axum::{
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Shared application state
#[derive(Clone)]
struct AppState {
    http_client: Client,
    db_pool: PgPool,
}

#[derive(Deserialize)]
struct SallaCallbackParams {
    code: String,
}

// OAuth token response from Salla
#[derive(Deserialize, Debug)]
struct OAuthResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

// Merchant info response from Salla API
#[derive(Deserialize, Debug)]
struct MerchantInfo {
    data: MerchantData,
}

#[derive(Deserialize, Debug)]
struct MerchantData {
    id: u64,
    name: String,
}

#[tokio::main]
async fn main() {
    // Load .env
    dotenvy::dotenv().ok();

    // Structured logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Connect to Postgres
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    tracing::info!("Database connected");

    let state = Arc::new(AppState {
        http_client: Client::builder()
            .pool_idle_timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        db_pool: pool,
    });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/callback", get(salla_auth_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Reactor active on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root_handler() -> &'static str {
    "Salla 3D Engine: DB CONNECTED"
}

async fn salla_auth_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SallaCallbackParams>,
) -> impl IntoResponse {
    let client_id = std::env::var("SALLA_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("SALLA_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = std::env::var("SALLA_REDIRECT_URI").unwrap_or_default();

    // Step 1: Exchange code for token
    let token_res = state
        .http_client
        .post("https://accounts.salla.sa/oauth2/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", params.code.as_str()),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_res = match token_res {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Network error exchanging code: {}", e);
            return Json(json!({"error": "Network error", "details": e.to_string()}));
        }
    };

    if !token_res.status().is_success() {
        let status = token_res.status();
        let body = token_res.text().await.unwrap_or_default();
        tracing::error!("Salla rejected code: {} - {}", status, body);
        return Json(json!({"error": "Salla rejected code", "status": status.as_u16()}));
    }

    let oauth_data: OAuthResponse = match token_res.json().await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("Failed to parse token response: {}", e);
            return Json(json!({"error": "Invalid token response"}));
        }
    };

    // Step 2: Fetch merchant info using the new token
    let info_res = state
        .http_client
        .get("https://api.salla.dev/admin/v2/oauth2/user/info")
        .header(
            "Authorization",
            format!("Bearer {}", oauth_data.access_token),
        )
        .send()
        .await;

    let merchant_info: MerchantInfo = match info_res {
        Ok(r) => match r.json().await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Failed to parse merchant info: {}", e);
                return Json(json!({"error": "Invalid merchant info response"}));
            }
        },
        Err(e) => {
            tracing::error!("Failed to fetch merchant info: {}", e);
            return Json(json!({"error": "Could not fetch merchant info"}));
        }
    };

    let merchant_id_str = merchant_info.data.id.to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(oauth_data.expires_in);

    // Step 3: Upsert into database
    let result = sqlx::query(
        r#"
        INSERT INTO merchants (merchant_id, name, access_token, refresh_token, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (merchant_id)
        DO UPDATE SET
            name = EXCLUDED.name,
            access_token = EXCLUDED.access_token,
            refresh_token = EXCLUDED.refresh_token,
            expires_at = EXCLUDED.expires_at,
            updated_at = NOW()
        "#,
    )
    .bind(&merchant_id_str)
    .bind(&merchant_info.data.name)
    .bind(&oauth_data.access_token)
    .bind(&oauth_data.refresh_token)
    .bind(expires_at)
    .execute(&state.db_pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!("Merchant {} ({}) secured in vault", merchant_id_str, merchant_info.data.name);
            Json(json!({
                "status": "success",
                "message": "Installation successful",
                "merchant_id": merchant_id_str
            }))
        }
        Err(e) => {
            tracing::error!("DB error: {}", e);
            Json(json!({"error": "Database failure", "details": e.to_string()}))
        }
    }
}
