use axum::{
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use crate::api::auth::{require_auth, require_site_member};
use crate::models::MediaRow;
use crate::util;
use crate::{ApiError, AppState, Media};

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(site_id): Path<Uuid>,
) -> Result<Json<Vec<Media>>, ApiError> {
    let current_user = require_auth(State(state.clone()), headers).await?;
    require_site_member(&state, site_id, current_user.user_id).await?;

    let media = sqlx::query_as::<_, MediaRow>(
        "SELECT id, site_id, filename, mime_type, size, url, alt_text, created_at FROM media WHERE site_id = $1 ORDER BY created_at DESC"
    )
    .bind(site_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::new(format!("Failed to fetch media: {}", e)))?;

    let media: Vec<Media> = media
        .into_iter()
        .map(|m| Media {
            id: m.0,
            site_id: m.1,
            filename: m.2,
            mime_type: m.3,
            size: m.4,
            url: m.5,
            alt_text: m.6,
            created_at: m.7,
        })
        .collect();

    Ok(Json(media))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((site_id, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Media>, ApiError> {
    let current_user = require_auth(State(state.clone()), headers).await?;
    require_site_member(&state, site_id, current_user.user_id).await?;

    let media = sqlx::query_as::<_, MediaRow>(
        "SELECT id, site_id, filename, mime_type, size, url, alt_text, created_at FROM media WHERE site_id = $1 AND id = $2"
    )
    .bind(site_id)
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::new("Media not found"))?;

    Ok(Json(Media {
        id: media.0,
        site_id: media.1,
        filename: media.2,
        mime_type: media.3,
        size: media.4,
        url: media.5,
        alt_text: media.6,
        created_at: media.7,
    }))
}

pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(site_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = require_auth(State(state.clone()), headers).await?;
    require_site_member(&state, site_id, current_user.user_id).await?;

    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => return Err(ApiError::new("No file provided")),
        Err(e) => return Err(ApiError::new(format!("Failed to read multipart: {}", e))),
    };

    let filename = field
        .file_name()
        .ok_or_else(|| ApiError::new("No filename provided"))?
        .to_string();

    let filename = std::path::Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ApiError::new("Invalid filename"))?;

    let safe_filename = format!("{}_{}", Uuid::new_v4(), filename);

    let content_type = field
        .content_type()
        .unwrap_or("application/octet-stream")
        .to_string();

    // Save file to disk
    let media_dir = std::path::Path::new("media");
    tokio::fs::create_dir_all(media_dir).await.ok();

    let bytes = field
        .bytes()
        .await
        .map_err(|e| ApiError::new(format!("Failed to read file: {}", e)))?;

    // Validate file content (magic bytes)
    if let Err(e) = util::validate_file_content(&bytes, filename) {
        return Err(ApiError::new(format!("Invalid file: {}", e)));
    }

    let file_path = media_dir.join(&safe_filename);
    tokio::fs::write(&file_path, &bytes)
        .await
        .map_err(|e| ApiError::new(format!("Failed to save file: {}", e)))?;

    let result = sqlx::query_as::<_, MediaRow>(
        "INSERT INTO media (site_id, filename, mime_type, size, url) VALUES ($1, $2, $3, $4, $5) 
         RETURNING id, site_id, filename, mime_type, size, url, alt_text, created_at",
    )
    .bind(site_id)
    .bind(&safe_filename)
    .bind(&content_type)
    .bind(bytes.len() as i32)
    .bind(format!("/media/{}", safe_filename))
    .fetch_one(&state.db)
    .await
    .map_err(|e| ApiError::new(format!("Failed to save media record: {}", e)))?;

    Ok((
        StatusCode::CREATED,
        Json(Media {
            id: result.0,
            site_id: result.1,
            filename: result.2,
            mime_type: result.3,
            size: result.4,
            url: result.5,
            alt_text: result.6,
            created_at: result.7,
        }),
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((site_id, id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, ApiError> {
    let current_user = require_auth(State(state.clone()), headers).await?;
    require_site_member(&state, site_id, current_user.user_id).await?;

    sqlx::query("DELETE FROM media WHERE site_id = $1 AND id = $2")
        .bind(site_id)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::new(format!("Failed to delete media: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}
