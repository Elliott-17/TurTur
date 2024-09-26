use sqlx::{SqlitePool, Error, Row};
use serde_json::json;
use log::{info, warn};


// Setup the database and initialize it
pub async fn setup_db() -> Result<(), Error> {

    let pool = get_db_connection().await?;

    info!("Setting up the database...");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            nickname TEXT NOT NULL,
            ident TEXT NOT NULL UNIQUE,
            servers TEXT,
            setup_complete BOOLEAN DEFAULT FALSE,
            has_access BOOLEAN DEFAULT FALSE
        );"
    ).execute(&pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner TEXT NOT NULL,
            users TEXT,
            FOREIGN KEY(owner) REFERENCES users(id)
        );"
    ).execute(&pool).await?;

    let _result = insert_user(&pool, "TurTur", "TurTur", "YouShouldntBeAbleToReadThis, Please Email Me So I Can Fix This : turturservice@gmail.com").await;

    let result = insert_server(&pool, "general", "TurTur", "").await;
    if result.is_err() {
        warn!("Error creating general server: {:?}", result.err());
    } 

    // get messages from general server
    let messages = get_messages(&pool, 1, 0).await;
    if messages.unwrap().is_empty() {
        insert_message(&pool, 1, "TurTur", "TurTur", "TurTur Setup Complete").await?;
    }

    drop(pool);

    Ok(())
}

// Insert a new user into the database
pub async fn insert_user(pool: &SqlitePool, id: &str, username: &str, email: &str) -> Result<String, Error> {

    let id_exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    if id_exists.is_some() {
        return Ok("FailAlreadyExists".to_string());
    }

    // Ensure the username is unique
    let username_exists: Option<String> = sqlx::query_scalar("SELECT ident FROM users WHERE ident = ?1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    
    let mut username = username.to_string();

    if username_exists.is_some() {
        // If the username exists, add a number to the end of it
        let mut i = 1;
        loop {
            username = format!("{}{}", username, i);
            let username_exists: Option<String> = sqlx::query_scalar("SELECT ident FROM users WHERE ident = ?1")
                .bind(&username)
                .fetch_optional(pool)
                .await?;
            if username_exists.is_none() {
                break;
            }
            i += 1;
        }
    }
    
    sqlx::query("INSERT INTO users (id, username, nickname, email, ident) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(id)
        .bind(username.clone())
        .bind(username.clone())
        .bind(email)
        .bind(username.clone())
        .execute(pool)
        .await?;

    add_user_to_server(pool, id, 1).await?;

    info!("New user: {}", username);

    Ok("Success".to_string())
}

pub async fn add_previously_deleted_user(pool: &SqlitePool, id: &str, username: &str, email: &str) -> Result<String, Error> {
    

    // Ensure the username is unique
    let username_exists: Option<String> = sqlx::query_scalar("SELECT ident FROM users WHERE ident = ?1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    
    let mut username = username.to_string();

    if username_exists.is_some() {
        // If the username exists, add a number to the end of it
        let mut i = 1;
        loop {
            username = format!("{}{}", username, i);
            let username_exists: Option<String> = sqlx::query_scalar("SELECT ident FROM users WHERE ident = ?1")
                .bind(&username)
                .fetch_optional(pool)
                .await?;
            if username_exists.is_none() {
                break;
            }
            i += 1;
        }
    }
    
    sqlx::query("UPDATE users SET username = ?1, nickname = ?2, email = ?3, ident = ?4, setup_complete = FALSE, has_access = FALSE WHERE id = ?5")
        .bind(username.clone())
        .bind(username.clone())
        .bind(email)
        .bind(username.clone())
        .bind(id)
        .execute(pool)
        .await?;

    add_user_to_server(pool, id, 1).await?;

    info!("New user: {}", username);

    Ok("Success".to_string())
}

// Insert a new server into the database
pub async fn insert_server(pool: &SqlitePool, name: &str, owner: &str, users: &str) -> Result<i64, Error> {

    let server_exists: Option<(String, String)> = sqlx::query_as("SELECT name, owner FROM servers WHERE name = ?1 AND owner = ?2")
        .bind(name)
        .bind(owner)
        .fetch_optional(pool)
        .await?;

    if server_exists.is_some() {
        return Ok(-1);
    }

    let usersjson = if users.is_empty() {
        json!([owner]).to_string()
    } else {
        json!([owner, users]).to_string()
    };

    sqlx::query("INSERT INTO servers (name, owner, users) VALUES (?1, ?2, ?3)")
        .bind(name)
        .bind(owner)
        .bind(usersjson)
        .execute(pool)
        .await?;

    let server_id: i64 = sqlx::query_scalar("SELECT id FROM servers WHERE name = ?1 AND owner = ?2")
        .bind(name)
        .bind(owner)
        .fetch_one(pool)
        .await?;

    let query = format!("CREATE TABLE IF NOT EXISTS messages_{} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userid TEXT NOT NULL,
        userident TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(userid) REFERENCES users(id)
    );", server_id);

    sqlx::query(&query).execute(pool).await?;

    info!("New server: {} created successfully", name);

    // Get owner's servers
    let owner_servers: String = sqlx::query_scalar("SELECT servers FROM users WHERE id = ?1").bind(owner).fetch_one(pool).await?;
    let mut servers: Vec<String> = serde_json::from_str(&owner_servers).unwrap_or(Vec::new());

    servers.push(server_id.to_string());

    // Convert servers to string
    let servers = serde_json::to_string(&servers).unwrap();

    // Add server to owner's servers
    sqlx::query("UPDATE users SET servers = ?1 WHERE id = ?2")
        .bind(servers)
        .bind(owner)
        .execute(pool).await?;

    Ok(server_id)
}

// Insert a new message into the specified server
pub async fn insert_message(pool: &SqlitePool, server_id: i64, user: &str, userident: &str, message: &str) -> Result<(), Error> {
    let query = format!("INSERT INTO messages_{} (userid, userident, message) VALUES (?1, ?2, ?3)", server_id);

    sqlx::query(&query)
        .bind(user)
        .bind(userident)
        .bind(message)
        .execute(pool)
        .await?;

    info!("Message saved, from {} in server {}: {}", user, server_id, message);

    Ok(())
}

// Add a user to a server
pub async fn add_user_to_server(pool: &SqlitePool, id: &str, server_id: i64) -> Result<String, Error> {

    let server_users: String = sqlx::query_scalar("SELECT users FROM servers WHERE id = ?1")
        .bind(server_id)
        .fetch_one(pool)
        .await?;

    let mut users: Vec<String> = serde_json::from_str(&server_users).unwrap();

    if users.contains(&id.to_string()) {
        warn!("User {} is already in server {}", id, server_id);
        return Ok("FailAlreadyIn".to_string());
    }

    users.push(id.to_string());
    let new_users = serde_json::to_string(&users).unwrap();

    sqlx::query("UPDATE servers SET users = ?1 WHERE id = ?2")
        .bind(new_users)
        .bind(server_id)
        .execute(pool)
        .await?;

    let user_servers: Option<String> = sqlx::query_scalar("SELECT servers FROM users WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let mut servers: Vec<String> = match user_servers {
        Some(servers_str) => serde_json::from_str(&servers_str).unwrap_or_else(|_| vec![]),
        None => vec![],
    };

    servers.push(server_id.to_string());
    let new_servers = serde_json::to_string(&servers).unwrap();

    sqlx::query("UPDATE users SET servers = ?1 WHERE id = ?2")
        .bind(new_servers)
        .bind(id)
        .execute(pool)
        .await?;

    info!("User {} added to server {}", id, server_id);
    Ok("Success".to_string())
}

// Remove a user from a server
pub async fn remove_user_from_server(pool: &SqlitePool, id: &str, server_id: i64) -> Result<String, Error> {

    let server_users: String = sqlx::query_scalar("SELECT users FROM servers WHERE id = ?1")
        .bind(server_id)
        .fetch_one(pool)
        .await?;

    let mut users: Vec<String> = serde_json::from_str(&server_users).unwrap();

    if !users.contains(&id.to_string()) {
        warn!("User {} is not in server {}", id, server_id);
        return Ok("FailNotIn".to_string());
    }

    users.retain(|user| user != id);
    let new_users = serde_json::to_string(&users).unwrap();

    sqlx::query("UPDATE servers SET users = ?1 WHERE id = ?2")
        .bind(new_users)
        .bind(server_id)
        .execute(pool)
        .await?;

    let user_servers: Option<String> = sqlx::query_scalar("SELECT servers FROM users WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let mut servers: Vec<String> = match user_servers {
        Some(servers_str) => serde_json::from_str(&servers_str).unwrap_or_else(|_| vec![]),
        None => vec![],
    };

    servers.retain(|server| server.as_str() != server_id.to_string());
    let new_servers = serde_json::to_string(&servers).unwrap();

    sqlx::query("UPDATE users SET servers = ?1 WHERE id = ?2")
        .bind(new_servers)
        .bind(id)
        .execute(pool)
        .await?;

    info!("User {} removed from server {}", id, server_id);
    Ok("Success".to_string())
}

// Fetch messages from a server
pub async fn get_messages(pool: &SqlitePool, server_id: i64, known_messages: i64) -> Result<Vec<MessageStruct>, Error> {

    let mut query;
    if known_messages == 0 {
        query = format!("SELECT * FROM messages_{} ORDER BY id DESC LIMIT 50", server_id);
    } else {
        // Same query but ignore the first known_messages
        query = format!("SELECT * FROM messages_{} ORDER BY id DESC LIMIT 50 OFFSET {}", server_id, known_messages);
    }

    let messages = sqlx::query(&query).fetch_all(pool).await?;

    let mut messages_vec = vec![];
    // Convert the messages to a MessageStruct struct
    for row in messages {
        messages_vec.push(MessageStruct {
            id: row.try_get::<i64, _>("id").unwrap(),
            userid: row.try_get::<String, _>("userid").unwrap(),
            userident: row.try_get::<String, _>("userident").unwrap(),
            message: row.try_get::<String, _>("message").unwrap(),
            timestamp: row.try_get::<String, _>("timestamp").unwrap(),
        });
    }

    Ok(messages_vec)
}

// Get a user by their ID
pub async fn get_user_by_id(pool: &SqlitePool, id: &str) -> Result<Option<User>, Error> {
    let user = sqlx::query("
        SELECT id, username, email, ident, servers, setup_complete, has_access
        FROM users
        WHERE id = ?1
    ")
    .bind(id)
    .fetch_optional(pool)
    .await?;

    // Convert the user to a User struct
    let user = match user {
        Some(row) => Some(User {
            id: row.try_get::<String, _>("id").unwrap(),
            username: row.try_get::<String, _>("username").unwrap(),
            email: row.try_get::<String, _>("email").unwrap(),
            ident: row.try_get::<String, _>("ident").unwrap(),
            servers: row.try_get::<String, _>("servers").unwrap(),
            setup_complete: row.try_get::<bool, _>("setup_complete").unwrap(),
            has_access: row.try_get::<bool, _>("has_access").unwrap(),
        }),
        None => None,
    };

    Ok(user)
}

pub async fn get_user_by_ident(pool: &SqlitePool, ident: &str) -> Result<Option<User>, Error> {
    let user = sqlx::query("
        SELECT id, username, email, ident, servers, setup_complete, has_access
        FROM users
        WHERE ident = ?1
    ")
    .bind(ident)
    .fetch_optional(pool)
    .await?;

    // Convert the user to a User struct
    let user = match user {
        Some(row) => Some(User {
            id: row.try_get::<String, _>("id").unwrap(),
            username: row.try_get::<String, _>("username").unwrap(),
            email: row.try_get::<String, _>("email").unwrap(),
            ident: row.try_get::<String, _>("ident").unwrap(),
            servers: row.try_get::<String, _>("servers").unwrap(),
            setup_complete: row.try_get::<bool, _>("setup_complete").unwrap(),
            has_access: row.try_get::<bool, _>("has_access").unwrap(),
        }),
        None => None,
    };

    Ok(user)
}

pub async fn update_user_ident(pool: &SqlitePool, id: &str, ident: &str) -> Result<(), Error> {
    sqlx::query("UPDATE users SET ident = ?1 WHERE id = ?2")
        .bind(ident)
        .bind(id)
        .execute(pool)
        .await?;
    
    // Get the user's servers
    let user_servers: String = sqlx::query_scalar("SELECT servers FROM users WHERE id = ?1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    
    let servers: Vec<String> = serde_json::from_str(&user_servers).unwrap();
    // Convert the servers to a i64 list
    let servers: Vec<i64> = servers.iter().map(|server| server.parse::<i64>().unwrap()).collect();
    
    // Change the userident of the messages
    for server_id in servers {
        sqlx::query(format!("UPDATE messages_{} SET userident = ?1 WHERE userid = ?2", server_id).as_str())
            .bind(ident)
            .bind(id)
            .execute(pool)
            .await?;
    }
    

    info!("User {} ident updated to {}", id, ident);
    Ok(())
}

pub async fn get_server_by_id(pool: &SqlitePool, id: i64) -> Result<Option<Server>, Error> {
    let server = sqlx::query("
        SELECT id, name, owner, users
        FROM servers
        WHERE id = ?1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    let server = match server {
        Some(row) => Some(Server {
            id: row.try_get::<i64, _>("id").unwrap(),
            name: row.try_get::<String, _>("name").unwrap(),
            owner: row.try_get::<String, _>("owner").unwrap(),
            users: row.try_get::<String, _>("users").unwrap(),
        }),
        None => None,
    };

    Ok(server)
}

pub async fn get_users(pool: &SqlitePool) -> Result<Vec<User>, Error> {
    let users = sqlx::query("SELECT * FROM users")
        .fetch_all(pool)
        .await?;

    // Convert users to a User list
    let mut users_vec: Vec<User> = users
        .into_iter()
        .map(|row| User {
            id: row.try_get::<String, _>("id").unwrap(),
            username: row.try_get::<String, _>("username").unwrap(),
            email: row.try_get::<String, _>("email").unwrap(),
            ident: row.try_get::<String, _>("ident").unwrap(),
            servers: row.try_get::<String, _>("servers").unwrap(),
            setup_complete: row.try_get::<bool, _>("setup_complete").unwrap(),
            has_access: row.try_get::<bool, _>("has_access").unwrap(),
        })
        .collect();

    // Remove TurTur from the list
    users_vec = users_vec.into_iter().filter(|user| user.id != "TurTur").collect();


    Ok(users_vec)
}

pub async fn get_servers(pool: &SqlitePool) -> Result<Vec<Server>, Error> {
    let servers = sqlx::query("SELECT * FROM servers")
        .fetch_all(pool)
        .await?;

    // Convert servers to a Server list
    let servers_vec: Vec<Server> = servers
        .into_iter()
        .map(|row| Server {
            id: row.try_get::<i64, _>("id").unwrap(),
            name: row.try_get::<String, _>("name").unwrap(),
            owner: row.try_get::<String, _>("owner").unwrap(),
            users: row.try_get::<String, _>("users").unwrap(),
        })
        .collect();

    Ok(servers_vec)
}


pub async fn grant_access(pool: &SqlitePool, id: &str) -> Result<(), Error> {
    sqlx::query("UPDATE users SET has_access = TRUE WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    info!("User {} granted access", id);
    Ok(())
}

pub async fn revoke_access(pool: &SqlitePool, id: &str) -> Result<(), Error> {
    sqlx::query("UPDATE users SET has_access = FALSE WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    info!("User {} access revoked", id);
    Ok(())
}

pub async fn delete_user(pool: &SqlitePool, id: &str) -> Result<(), Error> {

    // Get the user's servers
    let user_servers: String = sqlx::query_scalar("SELECT servers FROM users WHERE id = ?1")
        .bind(id)
        .fetch_one(pool)
        .await?;

    let servers: Vec<String> = serde_json::from_str(&user_servers).unwrap_or(Vec::new());
    // Convert the servers to a i64 list
    let servers: Vec<i64> = servers.iter().map(|server| server.parse::<i64>().unwrap()).collect();
    
    revoke_access(pool, id).await?;

    // Remove the user from all servers
    for server_id in servers {
        remove_user_from_server(pool, id, server_id).await?;

        // Change the server owner
        let server = get_server_by_id(pool, server_id).await.unwrap();
        
        let mut deleted = false;
        if let Some(server) = server {
            if server.owner == id {
                let users: Vec<String> = serde_json::from_str(&server.users).unwrap();
                if !users.is_empty() {
                    let new_owner = users[0].clone();
                    sqlx::query("UPDATE servers SET owner = ?1 WHERE id = ?2")
                        .bind(new_owner.clone())
                        .bind(server_id)
                        .execute(pool)
                        .await?;
                    insert_message(pool, server_id, "TurTur", "TurTur", format!("{} is now the owner of this server", new_owner.clone()).as_str()).await?;
                } else {
                    sqlx::query("DELETE FROM servers WHERE id = ?1")
                        .bind(server_id)
                        .execute(pool)
                        .await?;
                    deleted = true;
                }
            }
        }
        // If server was not deleted, change the userident of the messages
        if !deleted {
            let user = get_user_by_id(pool, id).await.unwrap().unwrap();
            sqlx::query(format!("UPDATE messages_{} SET userident = '{}' WHERE userident = ?1", server_id, "{USER DELETED}").as_str())
                .bind(user.ident)
                .execute(pool)
                .await?;
        } else {
            sqlx::query(format!("DROP TABLE messages_{}", server_id).as_str())
                .execute(pool)
                .await?;
        }
    }

    let deleted_id = id.to_string() + "_DELETED";

    // Update the sensitive values of the user to *DELETED*
    sqlx::query("UPDATE users SET username = '{USER DELETED}', email = '{USER DELETED}', nickname = '{USER DELETED}', ident = ?1, servers = '[]' WHERE id = ?2")
        .bind(deleted_id)
        .bind(id)
        .execute(pool)
        .await?;

    

    info!("User {} deleted", id);
    Ok(())
}

pub async fn delete_server(pool: &SqlitePool, id: i64) -> Result<(), Error> {

    let server = get_server_by_id(pool, id).await.unwrap().unwrap();

    let users: Vec<String> = serde_json::from_str(&server.users).unwrap();

    for user in users {
        remove_user_from_server(pool, &user, id).await?;
    }

    sqlx::query("DELETE FROM servers WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;

    sqlx::query(format!("DROP TABLE messages_{}", id).as_str())
        .execute(pool)
        .await?;

    info!("Server {} deleted", id);
    Ok(())
}

// Get a database connection 
pub async fn get_db_connection() -> Result<SqlitePool, Error> {
    let database_url = "turtur.db";

    // Check if the database exists
    if !std::path::Path::new(database_url).exists() {
        info!("Database does not exist, creating it...");
        // Create the database file
        std::fs::File::create(database_url).expect("Failed to create database file");
    }

    SqlitePool::connect(&database_url).await
}

// Define the User structure
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub ident: String,
    pub servers: String,
    pub setup_complete: bool,
    pub has_access: bool,
}

impl Clone for User {
    fn clone(&self) -> Self {
        User {
            id: self.id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            ident: self.ident.clone(),
            servers: self.servers.clone(),
            setup_complete: self.setup_complete,
            has_access: self.has_access,
        }
    }
}


// Define the Server structure
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub owner: String,
    pub users: String,
}

// Define the Message structure
#[derive(Debug)]
pub struct MessageStruct {
    pub id: i64,
    pub userid: String,
    pub userident: String,
    pub message: String,
    pub timestamp: String,
}
