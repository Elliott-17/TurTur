use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use lazy_static::lazy_static;
use log::{info, warn};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use warp::http::StatusCode;
use warp::{Filter, Rejection, Reply};
use rand::Rng;
use serde_json::json;
use openssl::x509::X509;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm, TokenData};
use chrono;
use warp::cors;
use std::fs::read_to_string;
use dotenv::dotenv;


use crate::db::{get_db_connection, get_user_by_id, insert_user, grant_access, get_users, add_previously_deleted_user};
use crate::chatserver::listener_endpoint;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // The unique ID of the user
    email: Option<String>,
    name: Option<String>,
    exp: usize,  // Expiration time
    iat: usize,  // Issued at time
    aud: Option<String>,
    iss: Option<String>,
    auth_time: Option<usize>,
}

impl Claims {
    fn copy(&self) -> Claims {
        Claims {
            sub: self.sub.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            exp: self.exp,
            iat: self.iat,
            aud: self.aud.clone(),
            iss: self.iss.clone(),
            auth_time: self.auth_time,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenRequest {
    id_token: String,
}


// Session Struct

#[derive(Debug, Deserialize, Serialize)]
pub struct Session {
    pub encryption_key: String,
    pub session_id: String,
    pub user_id: String,
    pub nonce: String,
    pub email: String,
    pub expiration: i64,
}

impl Session {
    fn copy(&self) -> Session {
        Session {
            encryption_key: self.encryption_key.clone(),
            session_id: self.session_id.clone(),
            user_id: self.user_id.clone(),
            nonce: self.nonce.clone(),
            email: self.email.clone(),
            expiration: self.expiration,
        }
    }
    pub fn new() -> Session {
        Session {
            encryption_key: "".to_string(),
            session_id: "".to_string(),
            user_id: "".to_string(),
            nonce: "".to_string(),
            email: "".to_string(),
            expiration: 0,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.encryption_key.is_empty() || self.session_id.is_empty() || self.user_id.is_empty()
    }
    pub fn update(&mut self, session: &Session) {
        self.encryption_key = session.encryption_key.clone();
        self.session_id = session.session_id.clone();
        self.user_id = session.user_id.clone();
        self.nonce = session.nonce.clone();
        self.email = session.email.clone();
        self.expiration = session.expiration;
    }
}








lazy_static! {
    pub static ref SESSION_STORE: Arc<Mutex<HashMap<String, Session>>> = Arc::new(Mutex::new(HashMap::new()));
}


fn read_file_in_html_dir(file_name: &str, debug: bool) -> &str {
    // Get from debughtml folder if debug is true
    let path = if debug {
        format!("debughtml/{}", file_name)
    } else {
        format!("html/{}", file_name)
    };
    let file = read_to_string(path).expect("Unable to read HTML file");

    Box::leak(file.into_boxed_str())
}


pub async fn setup_endpoints(debug: bool) {
    // In-memory store for sessions
    let session_store = Arc::clone(&SESSION_STORE);


    // Filter to check if user is authenticated
    let check_auth = warp::cookie::optional("session_id")
        .and(with_session_store(session_store.clone()))
        .and_then(move |session_id: Option<String>, session_store: Arc<Mutex<HashMap<String, Session>>>| {
            let session_store = session_store.clone();
            async move {
                if let Some(session_id) = session_id {
                    let sessions = session_store.lock().unwrap();
                    if let Some(session) = sessions.get(&session_id) {
                        // Check if session is expired
                        if session.expiration < chrono::Utc::now().timestamp() {
                            // Remove session if expired
                            let mut sessions = session_store.lock().unwrap();
                            sessions.remove(&session_id);
                            return Err(warp::reject::custom(Unauthorized));
                        }
                        return Ok(session.copy());
                    }
                }
                Err(warp::reject::custom(Unauthorized))
            }
        });

    let check_admin = warp::cookie::optional("session_id")
        .and(with_session_store(session_store.clone()))
        .and_then(move |session_id: Option<String>, session_store: Arc<Mutex<HashMap<String, Session>>>| async move {
            if let Some(session_id) = session_id {
                let sessions = session_store.lock().unwrap();
                if let Some(session) = sessions.get(&session_id) {
                    if session.email == dotenv::var("ADMIN_EMAIL").unwrap() {
                        return Ok(());
                    }
                }
            }

            Err(warp::reject::custom(Unauthorized))
        });

    // Routes
    let login = warp::get()
        .and(warp::path("login"))
        .and(warp::cookie::optional("session_id"))
        .and(with_debug(debug))
        .map(|session_id: Option<String>, debug: bool| {
            // Get session store and check if user is already authenticated
            let session_store = SESSION_STORE.lock().unwrap();
            if let Some(session_id) = session_id {
                if let Some(_) = session_store.get(&session_id) {
                    // Redirect to chat page if user is already authenticated using javascript
                    return warp::reply::html(r###"
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Redirecting...</title>
                            <script>
                                window.location.href = '/app';
                            </script>
                        </head>
                        <body>
                            <h2>Redirecting...</h2>
                        </body>
                        </html>)
                    "###);
                }
            }

            let html = read_file_in_html_dir("login.html", debug);
            
            warp::reply::html(html)
        });

    let chat_page = warp::get()
        .and(warp::path("app"))
        .and(check_auth.clone())
        .and(with_debug(debug))
        .map(|_, debug| {
            let html = read_file_in_html_dir("app.html", debug);
            warp::reply::html(html)
        });

    let logout = warp::get()
        .and(warp::path("logout"))
        .and(with_session_store(session_store.clone()))
        .and(warp::cookie::optional("session_id"))
        .map(|session_store: Arc<Mutex<HashMap<String, Session>>>, session_id: Option<String>| {
            if let Some(session_id) = session_id {
                let mut sessions = session_store.lock().unwrap();
                sessions.remove(&session_id);
            }
            // Redirect to login page and remove all cookies
            warp::reply::with_header(
                warp::redirect(warp::http::Uri::from_static("/login")),
                "Set-Cookie",
                "session_id=0; HttpOnly; Max-Age=0; Path=/",
            )
        });

    let admin_page = warp::get()
        .and(warp::path("admin"))
        .and(check_admin.clone()
                 .and(with_debug(debug)))
        .map(|_, debug| {
            let html = read_file_in_html_dir("admin.html", debug);
            warp::reply::html(html)
        });

    let get_users = warp::get()
        .and(warp::path("users"))
        .and(check_admin.clone())
        .and_then(get_users_handler);
        
    let verify_auth = warp::post()
        .and(warp::path("verify"))
        .and(warp::body::json())
        .and_then(verify_handler);

    let css_style = warp::path("css")
        .and(warp::path("style.css"))
        .and(with_debug(debug))
        .map(|debug| {
            let css = read_file_in_html_dir("style.css", debug);
            warp::reply::with_header(warp::reply::html(css), "Content-Type", "text/css")
        });

    let login_js = warp::path("js")
        .and(warp::path("login.js"))
        .and(with_debug(debug))
        .map(|debug| {
            let js = read_file_in_html_dir("login.js", debug);
            warp::reply::with_header(warp::reply::html(js), "Content-Type", "application/javascript")
        });

    let app_js = warp::path("js")
        .and(warp::path("app.js"))
        .and(with_debug(debug))
        .map(|debug| {
            let js = read_file_in_html_dir("app.js", debug);
            warp::reply::with_header(warp::reply::html(js), "Content-Type", "application/javascript")
        });

    let favicon = warp::get()
        .and(warp::path("favicon.ico"))
        .and(warp::fs::file("images/turturicon.ico"));

    let error_img = warp::get()
        .and(warp::path("images"))
        .and(warp::path("error.png"))
        .and(warp::fs::file("images/confused_turtle.png"));

    let logo_img = warp::get()
        .and(warp::path("images"))
        .and(warp::path("logo.png"))
        .and(warp::fs::file("images/travelling_turtle.png"));

    let success_img = warp::get()
        .and(warp::path("images"))
        .and(warp::path("success.png"))
        .and(warp::fs::file("images/success_turtle.png"));

    let websocket = listener_endpoint(debug).await;

    let routes = 
        chat_page
        .or(login)
        .or(websocket)
        .or(logout)
        .or(verify_auth)
        .or(css_style)
        .or(login_js)
        .or(app_js)
        .or(favicon)
        .or(error_img)
        .or(admin_page)
        .or(get_users)
        .or(logo_img)
        .or(success_img)
        .recover(handle_rejection);


    
    let cors = cors()
        .allow_any_origin()
        .allow_header("content-type")
        .allow_methods(vec!["GET", "POST"]);

    let routes_with_cors = routes.with(cors);

    if debug {
        warn!("Running in debug mode, serving without SSL");
        // Serve with HTTP
        warp::serve(routes_with_cors)
            .run(([0, 0, 0, 0], 3030))
            .await;
    } else {
        info!("Running in production mode, serving with SSL");
        // Load SSL certificate and key
        let cert_path = "/etc/letsencrypt/live/turtur.ddns.net/fullchain.pem";
        let key_path = "/etc/letsencrypt/live/turtur.ddns.net/privkey.pem";

        // Serve with HTTPS
        warp::serve(routes_with_cors)
            .tls()
            .cert_path(cert_path)
            .key_path(key_path)
            .run(([0, 0, 0, 0], 443))
            .await;

    }
}

// Filter to pass the session store to handlers
fn with_session_store(session_store: Arc<Mutex<HashMap<String, Session>>>) -> impl Filter<Extract = (Arc<Mutex<HashMap<String, Session>>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || session_store.clone())
}

fn with_debug(debug: bool) -> impl Filter<Extract = (bool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || debug)
}


// Custom rejection for unauthorized access
#[derive(Debug)]
struct Unauthorized;

impl warp::reject::Reject for Unauthorized {
}

async fn handle_rejection(_: Rejection) -> Result<impl Reply, Rejection> {
    // Return the error.html page
    let html = read_file_in_html_dir("error.html", false);
    Ok(warp::reply::html(html))
}

async fn verify_handler(body: IdTokenRequest) -> Result<impl warp::Reply, warp::Rejection> {

    info!("New login attempt...");
    match decode_token(&body.id_token).await {
        Ok(token_data) => {

            
            // Validate token
            verify_token(token_data.claims.copy()).await?;

            // Generate a session ID
            let session_id = uuid::Uuid::new_v4().to_string();

            // Generate random encryption key 32 characters long
            let encryption_key: String = rand::thread_rng()
                                .sample_iter(&Alphanumeric)
                                .take(32)
                                .map(char::from)
                                .collect();
            let nonce = generate_nonce();

            // Create a session
            let session = Session {
                encryption_key: encryption_key.clone(),
                session_id: session_id.clone(),
                user_id: token_data.claims.sub.clone(),
                nonce: nonce.clone(),
                email: token_data.claims.email.clone().unwrap().to_string(),
                expiration: chrono::Utc::now().timestamp() + 3600,
            };

            // Get user details
            let name = token_data.claims.name.clone().unwrap_or({
                // Get email before @
                let email = token_data.claims.email.clone().unwrap();
                email.split('@').collect::<Vec<&str>>()[0].to_string()
            }).to_string();
            let userid = token_data.claims.sub.clone();
            let email = token_data.claims.email.clone().unwrap().to_string();

            // Insert user into database if not already present
            let pool = get_db_connection().await.unwrap();
            let user = get_user_by_id(&pool, &userid).await.unwrap();

            let mut has_access = false;

            if user.is_none() {
                // New user, will not have access
                insert_user(&pool, &userid, &name, &email).await.unwrap();

                // If email is admin email, grant access
                dotenv().ok();
                let admin_email = std::env::var("ADMIN_EMAIL").unwrap();
                if email == admin_email {
                    grant_access(&pool, &userid).await.unwrap();
                    has_access = true;
                }
            } else if user.clone().unwrap().has_access {
                has_access = true;
            } else if user.unwrap().username == "{USER DELETED}" {
                // User has been deleted, but will add back
                add_previously_deleted_user(&pool, &userid, &name, &email).await.unwrap();
            }

            if has_access{
                // Store the session
                let mut sessions = SESSION_STORE.lock().unwrap();
                sessions.insert(session_id.clone(), session);

                info!("User {} authenticated", token_data.claims.sub);
            } else {
                // User has logged in but does not have access
                warn!("User {} does not have access", token_data.claims.sub);
                return Err(warp::reject::custom(Unauthorized));
            }


            

            let response = json!({
                "user_id": nonce,
                "encryption_key": encryption_key,
                "session_id": session_id,
            });
            Ok(warp::reply::with_status(warp::reply::json(&response), warp::http::StatusCode::OK))
        }
        Err(_) => {
            warn!("Invalid ID token, disallowing auth attempt");
            let response = json!({
                "status": "error",
                "message": "Invalid ID token",
            });
            Ok(warp::reply::with_status(warp::reply::json(&response), warp::http::StatusCode::UNAUTHORIZED))
        }
    }
}


async fn decode_token(id_token: &str) -> Result<TokenData<Claims>, warp::Rejection> {
    let google_certs_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
    let jwks: serde_json::Value = reqwest::get(google_certs_url).await.unwrap().json().await.unwrap();

    // get the kid from the token

    let header = decode_header(id_token).map_err(|e| {
        warn!("Error decoding token header: {:?}", e);
        warp::reject::custom(Unauthorized)
    })?;

    let kid = header.kid.unwrap();

    // Extract the keys
    //Iterate over the keys and find the one with the matching kid
    // if error, return unauthorized
    let certificate = jwks[kid].as_str().ok_or_else(|| {
        warn!("Error getting certificate, Disallowing Auth Attempt");
        warp::reject::custom(Unauthorized)
    })?;


    // Decode the certificate
    let cert = X509::from_pem(certificate.as_bytes()).map_err(|e| {
        warn!("Error decoding certificate: {:?}\nDisallowing Auth Attempt", e);
        warp::reject::custom(Unauthorized)
    })?;
    let rsa = cert.public_key().unwrap().rsa().map_err(|e| {
        warn!("Error getting RSA key: {:?}\nDisallowing Auth Attempt", e);
        warp::reject::custom(Unauthorized)
    })?;
    let public_key_pem = rsa.public_key_to_pem().map_err(|e| {
        warn!("Error getting public key: {:?}\nDisallowing Auth Attempt", e);
        warp::reject::custom(Unauthorized)
    })?;
    let decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).map_err(|e| {
        warn!("Error creating decoding key: {:?}\nDisallowing Auth Attempt", e);
        warp::reject::custom(Unauthorized)
    })?;

    let validation = Validation::new(Algorithm::RS256);

    decode::<Claims>(id_token, &decoding_key, &validation).map_err(|e| {
        warn!("Error decoding token: {:?} Disallowing Auth Attempt", e);
        warp::reject::custom(Unauthorized)
    })
}



async fn verify_token(claims: Claims) -> Result<(), warp::Rejection> {
     // Check if token is expired
     if claims.exp < chrono::Utc::now().timestamp().to_string().parse::<usize>().unwrap() {
        warn!("Token expired, disallowing auth attempt");
        return Err(warp::reject::custom(Unauthorized));
    }

    // Check if token was issued in the future, with some leeway
    if claims.iat > chrono::Utc::now().timestamp().to_string().parse::<usize>().unwrap() + 300 {
        warn!("Token issued in the future, disallowing auth attempt");
        return Err(warp::reject::custom(Unauthorized));
    }

    // Check if token has a valid audience
    if claims.aud != Some("turtur-aa8f8".to_string()) {
        warn!("Invalid audience: {}, disallowing auth attempt", claims.aud.unwrap());
        return Err(warp::reject::custom(Unauthorized));
    }

    // Check if token has a valid issuer
    if claims.iss != Some("https://securetoken.google.com/turtur-aa8f8".to_string()) {
        warn!("Invalid issuer, disallowing auth attempt");
        return Err(warp::reject::custom(Unauthorized));
    }

    // Check if token has a valid auth time but allow for some leeway
    if let Some(auth_time) = claims.auth_time {
        if auth_time > chrono::Utc::now().timestamp().to_string().parse::<usize>().unwrap() + 300 {
            warn!("Invalid auth time, disallowing auth attempt");
            return Err(warp::reject::custom(Unauthorized));
        }
    }

    // Check if token has a valid user ID
    if claims.sub.is_empty() {
        warn!("Invalid ID token, disallowing auth attempt");
        return Err(warp::reject::custom(Unauthorized));
    }

    Ok(())
}



fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect()
}


pub async fn get_users_handler(result: ()) -> Result<impl warp::Reply, warp::Rejection> {

    let pool = get_db_connection().await.unwrap();
    match get_users(&pool).await {
        Ok(users) => Ok(warp::reply::with_status(warp::reply::json(&users), StatusCode::OK)),
        Err(_) => Err(warp::reject::custom(Unauthorized)),
    }
}
