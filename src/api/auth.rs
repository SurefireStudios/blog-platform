use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;

use crate::{ApiError, AppState, CreateUserRequest, LoginRequest, User, UserResponse};

#[derive(Clone)]
pub struct CurrentUser {
    pub user_id: Uuid,
}

pub async fn require_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<CurrentUser, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("Missing or invalid Authorization header"))?;

    let user_id = validate_token(&state, token)
        .await
        .map_err(|e| ApiError::unauthorized(&e.message))?;

    Ok(CurrentUser { user_id })
}

pub async fn require_site_member(
    state: &AppState,
    site_id: Uuid,
    user_id: Uuid,
) -> Result<(), ApiError> {
    let member = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT user_id FROM site_members WHERE site_id = $1 AND user_id = $2",
    )
    .bind(site_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::new("Database error"))?;

    if member.is_none() {
        return Err(ApiError::forbidden("Not authorized to access this site"));
    }
    Ok(())
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.email.is_empty() || payload.password.is_empty() {
        return Err(ApiError::new("Email and password are required"));
    }

    if payload.password.len() < 8 {
        return Err(ApiError::new("Password must be at least 8 characters"));
    }

    let password_hash = hash(&payload.password, DEFAULT_COST)
        .map_err(|e| ApiError::new(format!("Failed to hash password: {}", e)))?;

    let result = sqlx::query_as::<_, (Uuid, String, String, Option<String>)>(
        "INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, password_hash, name"
    )
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&payload.name)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok((id, email, _, name)) => {
            let email_clone = email.clone();
            let name_clone = name.clone();
            let token = Uuid::new_v4().to_string();

            sqlx::query(
                "INSERT INTO auth_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 days')"
            )
            .bind(id)
            .bind(&token)
            .execute(&state.db)
            .await
            .map_err(|e| ApiError::new(format!("Failed to create auth token: {}", e)))?;

            // Bootstrap only: adopt a site that nobody administers yet.
            //
            // Registration is unauthenticated, so this must never attach a new
            // account to a site that already has members - that would hand any
            // anonymous registrant write access to an existing site.
            if let Ok(Some(site_id)) = sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT s.id FROM sites s
                 WHERE NOT EXISTS (SELECT 1 FROM site_members m WHERE m.site_id = s.id)
                 LIMIT 1",
            )
            .fetch_optional(&state.db)
            .await
            {
                sqlx::query(
                    "INSERT INTO site_members (site_id, user_id, role) VALUES ($1, $2, 'admin') ON CONFLICT DO NOTHING"
                )
                .bind(site_id)
                .bind(id)
                .execute(&state.db)
                .await
                .ok();

                return Ok((
                    StatusCode::CREATED,
                    Json(crate::LoginResponse {
                        user: crate::errors::UserResponse {
                            id,
                            email: email_clone,
                            name: name_clone,
                        },
                        site_id,
                        token,
                    }),
                ));
            }

            Ok((
                StatusCode::CREATED,
                Json(crate::LoginResponse {
                    user: crate::errors::UserResponse {
                        id,
                        email: email_clone,
                        name: name_clone,
                    },
                    site_id: None,
                    token,
                }),
            ))
        }
        Err(e) => {
            if e.to_string().contains("duplicate") {
                Err(ApiError::new("Email already exists"))
            } else {
                Err(ApiError::new(format!("Failed to create user: {}", e)))
            }
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user =
        sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                String,
                Option<String>,
                chrono::DateTime<chrono::Utc>,
            ),
        >("SELECT id, email, password_hash, name, created_at FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_one(&state.db)
        .await
        .map_err(|_| ApiError::unauthorized("Invalid email or password"))?;

    let valid = verify(&payload.password, &user.2)
        .map_err(|_| ApiError::unauthorized("Invalid email or password"))?;

    if !valid {
        return Err(ApiError::unauthorized("Invalid email or password"));
    }

    let user = User {
        id: user.0,
        email: user.1,
        name: user.3,
        created_at: user.4,
    };

    let user_response = UserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
    };

    let site_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT site_id FROM site_members WHERE user_id = $1 LIMIT 1",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await
    .ok()
    .flatten();

    let token = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO auth_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 days')"
    )
    .bind(user.id)
    .bind(&token)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::new(format!("Failed to create auth token: {}", e)))?;

    Ok(Json(crate::LoginResponse {
        user: user_response,
        site_id,
        token,
    }))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if let Some(token) = token {
        sqlx::query("DELETE FROM auth_tokens WHERE token = $1")
            .bind(token)
            .execute(&state.db)
            .await
            .ok();
    }

    (StatusCode::OK, "Logged out")
}

pub async fn validate_token(state: &AppState, token: &str) -> Result<Uuid, ApiError> {
    let user_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT user_id FROM auth_tokens WHERE token = $1 AND (expires_at IS NULL OR expires_at > NOW())"
    )
    .bind(token)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::unauthorized("Invalid token"))?
    .ok_or_else(|| ApiError::unauthorized("Invalid or expired token"))?;

    Ok(user_id)
}
