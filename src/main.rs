mod errors;
mod models;
mod state;
mod util;

pub use errors::{
    ApiError, CreatePageRequest, CreatePostRequest, CreateSiteRequest, CreateUserRequest,
    LoginRequest, LoginResponse, UpdatePageRequest, UpdatePostRequest, UserResponse,
};
pub use models::{ContactSubmission, Media, Page, Post, Site, User};
pub use state::AppState;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

pub mod api;
pub mod ssg;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactFormRequest {
    pub name: String,
    pub email: String,
    pub message: String,
    pub honeypot: Option<String>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "blog_platform=info,axum=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set. See .env.example for configuration.");

    let db = match sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            tracing::info!("Database connected successfully");
            pool
        }
        Err(e) => {
            tracing::error!("Failed to connect to database: {}", e);
            panic!("Database connection failed: {}", e);
        }
    };

    run_migrations(&db).await;
    seed_default_pages(&db).await;

    let state = AppState { db };

    let output_dir = std::path::Path::new("output");
    let needs_build = !output_dir.exists()
        || std::fs::read_dir(output_dir)
            .map(|mut e| e.next().is_none())
            .unwrap_or(true);
    if needs_build {
        if let Ok(site) = sqlx::query("SELECT id FROM sites LIMIT 1")
            .fetch_one(&state.db)
            .await
        {
            let site_id: uuid::Uuid = site.get("id");
            tracing::info!("Building static site for site_id: {}", site_id);
            if let Err(e) = ssg::build_site(&state.db, site_id).await {
                tracing::error!("Failed to build static site: {}", e);
            }
        }
    }

    let static_files = ServeDir::new("output");

    let media_files = ServeDir::new("media");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .with_state(state.clone())
        .route("/admin", get(admin_handler))
        .route("/admin/{*path}", get(admin_handler))
        .route(
            "/",
            get(|_state: State<AppState>| async move {
                let html_path = "output/index.html";
                if std::path::Path::new(html_path).exists() {
                    if let Ok(content) = tokio::fs::read_to_string(html_path).await {
                        return axum::response::Html(content).into_response();
                    }
                }
                (StatusCode::NOT_FOUND, axum::response::Html("Not found")).into_response()
            }),
        )
        .route(
            "/{*path}",
            get(
                |axum::extract::Path(path): axum::extract::Path<String>| async move {
                    // The request path is attacker-controlled and axum neither
                    // normalises `..` nor rejects percent-encoded traversal, so
                    // every candidate path is resolved against `output/` first.
                    let not_found = || {
                        (StatusCode::NOT_FOUND, axum::response::Html("Not found")).into_response()
                    };

                    // Try .html first
                    if let Some(html_path) =
                        util::resolve_within("output", &format!("{}.html", path))
                    {
                        if html_path.exists() {
                            if let Ok(content) = tokio::fs::read_to_string(&html_path).await {
                                return axum::response::Html(content).into_response();
                            }
                        }
                    }
                    // Try exact file match (for sitemap.xml, feed.xml, etc)
                    let Some(file_path) = util::resolve_within("output", &path) else {
                        return not_found();
                    };
                    if file_path.exists() {
                        if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
                            // Determine content type based on extension
                            let content_type = if path.ends_with(".xml") {
                                if path.contains("sitemap") {
                                    "application/xml"
                                } else if path.contains("feed") || path.contains("rss") {
                                    "application/rss+xml"
                                } else {
                                    "application/xml"
                                }
                            } else if path.ends_with(".json") {
                                "application/json"
                            } else if path.ends_with(".css") {
                                "text/css"
                            } else if path.ends_with(".js") {
                                "application/javascript"
                            } else if path.ends_with(".png") {
                                "image/png"
                            } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                                "image/jpeg"
                            } else if path.ends_with(".svg") {
                                "image/svg+xml"
                            } else if path.ends_with(".ico") {
                                "image/x-icon"
                            } else {
                                "text/html"
                            };

                            return (
                                StatusCode::OK,
                                [(axum::http::header::CONTENT_TYPE, content_type)],
                                content,
                            )
                                .into_response();
                        }
                    }
                    (StatusCode::NOT_FOUND, axum::response::Html("Not found")).into_response()
                },
            ),
        )
        .nest_service("/static", static_files.clone())
        .nest_service("/media", media_files)
        .merge(api::routes())
        .layer(cors)
        .with_state(state);

    let host = std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("APP_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap_or(3000);
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));

    tracing::info!("Starting server on http://{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => (StatusCode::OK, "OK"),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"),
    }
}

async fn admin_handler(
    _path: Option<axum::extract::Path<String>>,
) -> impl axum::response::IntoResponse {
    match tokio::fs::read_to_string("admin.html").await {
        Ok(html) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/html")],
            html,
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            "Admin panel not found".to_string(),
        ),
    }
}

async fn run_migrations(db: &sqlx::PgPool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sites (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            subdomain VARCHAR(63) UNIQUE,
            custom_domain VARCHAR(255) UNIQUE,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            logo_url VARCHAR(1000),
            favicon_url VARCHAR(1000),
            theme VARCHAR(100) DEFAULT 'default',
            nav_links JSONB DEFAULT '[]',
            footer_text VARCHAR(500),
            social_links JSONB DEFAULT '{}',
            contact_phone VARCHAR(50),
            contact_email VARCHAR(255),
            contact_address VARCHAR(500),
            homepage_type VARCHAR(20) DEFAULT 'both',
            landing_blocks JSONB DEFAULT '[]',
            blog_path VARCHAR(100) DEFAULT '/blog',
            blog_sort_order INTEGER DEFAULT 1,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            settings JSONB DEFAULT '{}'
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create sites table");

    sqlx::query("ALTER TABLE sites ADD COLUMN IF NOT EXISTS favicon_url VARCHAR(1000)")
        .execute(db)
        .await
        .ok();
    sqlx::query("ALTER TABLE sites ADD COLUMN IF NOT EXISTS blog_sort_order INTEGER DEFAULT 1")
        .execute(db)
        .await
        .ok();
    sqlx::query(
        "ALTER TABLE sites ADD COLUMN IF NOT EXISTS homepage_type VARCHAR(20) DEFAULT 'both'",
    )
    .execute(db)
    .await
    .ok();
    sqlx::query(
        "ALTER TABLE sites ADD COLUMN IF NOT EXISTS blog_path VARCHAR(100) DEFAULT '/blog'",
    )
    .execute(db)
    .await
    .ok();
    sqlx::query("ALTER TABLE sites ADD COLUMN IF NOT EXISTS landing_blocks JSONB DEFAULT '[]'")
        .execute(db)
        .await
        .ok();
    sqlx::query("ALTER TABLE sites ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}'")
        .execute(db)
        .await
        .ok();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255),
            created_at TIMESTAMPTZ DEFAULT NOW()
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create users table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS auth_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR(255) UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create auth_tokens table");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_auth_tokens_token ON auth_tokens(token)")
        .execute(db)
        .await
        .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id)")
        .execute(db)
        .await
        .ok();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS site_members (
            site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            role VARCHAR(50) DEFAULT 'editor',
            PRIMARY KEY (site_id, user_id)
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create site_members table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS posts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
            author_id UUID REFERENCES users(id),
            title VARCHAR(500) NOT NULL,
            slug VARCHAR(500) NOT NULL,
            content JSONB NOT NULL DEFAULT '[]',
            excerpt TEXT,
            featured_image VARCHAR(1000),
            status VARCHAR(50) DEFAULT 'draft',
            published_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            seo JSONB DEFAULT '{}',
            UNIQUE(site_id, slug)
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create posts table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pages (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
            title VARCHAR(500) NOT NULL,
            slug VARCHAR(500) NOT NULL,
            content JSONB NOT NULL DEFAULT '[]',
            is_homepage BOOLEAN DEFAULT FALSE,
            show_in_nav BOOLEAN DEFAULT TRUE,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            seo JSONB DEFAULT '{}',
            UNIQUE(site_id, slug)
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create pages table");

    sqlx::query("ALTER TABLE pages ADD COLUMN IF NOT EXISTS show_in_nav BOOLEAN DEFAULT TRUE")
        .execute(db)
        .await
        .ok();
    sqlx::query("ALTER TABLE pages ADD COLUMN IF NOT EXISTS sort_order INTEGER DEFAULT 0")
        .execute(db)
        .await
        .ok();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS media (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
            filename VARCHAR(500) NOT NULL,
            mime_type VARCHAR(100),
            size INTEGER,
            url VARCHAR(1000) NOT NULL,
            alt_text VARCHAR(500),
            created_at TIMESTAMPTZ DEFAULT NOW()
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create media table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS contact_submissions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            honeypot VARCHAR(255) DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            read BOOLEAN DEFAULT FALSE
        )",
    )
    .execute(db)
    .await
    .expect("Failed to create contact_submissions table");

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_site_status ON posts(site_id, status)")
        .execute(db)
        .await
        .ok();
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_published ON posts(site_id, published_at DESC)",
    )
    .execute(db)
    .await
    .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_pages_site ON pages(site_id)")
        .execute(db)
        .await
        .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_media_site ON media(site_id)")
        .execute(db)
        .await
        .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_slug ON posts(site_id, slug)")
        .execute(db)
        .await
        .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_pages_slug ON pages(site_id, slug)")
        .execute(db)
        .await
        .ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_site_members_user ON site_members(user_id)")
        .execute(db)
        .await
        .ok();
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_contact_submissions_site_created ON contact_submissions(site_id, created_at DESC)",
    )
    .execute(db)
    .await
    .ok();
}

async fn seed_default_pages(db: &sqlx::PgPool) {
    let sites = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM sites WHERE id NOT IN (SELECT DISTINCT site_id FROM pages)",
    )
    .fetch_all(db)
    .await;

    if let Ok(sites) = sites {
        let site_count = sites.len();

        let homepage_content = serde_json::json!([
            {"block_type": "hero", "content": {"title": "Welcome to Our Site", "subtitle": "Your amazing blog starts here", "ctaText": "Read More", "ctaLink": "/blog"}}
        ]);

        let about_content = serde_json::json!([
            {"block_type": "heading", "content": {"text": "About Us"}},
            {"block_type": "paragraph", "content": {"text": "Welcome to our about page! We are a company that does amazing things."}}
        ]);

        let contact_content = serde_json::json!([
            {"block_type": "heading", "content": {"text": "Contact Us"}},
            {"block_type": "paragraph", "content": {"text": "Get in touch with us!"}}
        ]);

        for (site_id,) in sites {
            sqlx::query(
                "INSERT INTO pages (site_id, title, slug, content, is_homepage) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(site_id)
            .bind("Home")
            .bind("home")
            .bind(&homepage_content)
            .bind(true)
            .execute(db)
            .await.ok();

            sqlx::query(
                "INSERT INTO pages (site_id, title, slug, content, is_homepage) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(site_id)
            .bind("About")
            .bind("about")
            .bind(&about_content)
            .bind(false)
            .execute(db)
            .await.ok();

            sqlx::query(
                "INSERT INTO pages (site_id, title, slug, content, is_homepage) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(site_id)
            .bind("Contact")
            .bind("contact")
            .bind(&contact_content)
            .bind(false)
            .execute(db)
            .await.ok();
        }
        if site_count > 0 {
            tracing::info!("Seeded default pages for {} existing sites", site_count);
        }
    }

    sqlx::query(
        "UPDATE sites SET homepage_type = 'both' WHERE homepage_type IS NULL OR homepage_type = ''",
    )
    .execute(db)
    .await
    .ok();

    let default_nav = serde_json::json!([{"label": "Home", "url": "/"}, {"label": "Blog", "url": "/blog"}, {"label": "About", "url": "/about"}, {"label": "Contact", "url": "/contact"}]);
    sqlx::query(
        "UPDATE sites SET nav_links = $1 WHERE nav_links IS NULL OR nav_links = '[]'::jsonb",
    )
    .bind(&default_nav)
    .execute(db)
    .await
    .ok();
}
