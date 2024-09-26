use warp::Filter;
use warp::ws::{Message, WebSocket};
use tokio::sync::Mutex;
use futures_util::{StreamExt, SinkExt};
use log::{error, info, warn};
use std::sync::Arc;
use futures_util::stream::SplitSink;
use serde_json::json;
use lazy_static::lazy_static;
use uuid::Uuid;

use crate::{
    db::{get_db_connection, get_messages, get_user_by_id, get_user_by_ident, get_server_by_id, insert_message,
         insert_server, grant_access, revoke_access, insert_user, add_user_to_server, delete_server, delete_user,
         get_servers, get_users, remove_user_from_server, update_user_ident},
    endpoints::{Session, SESSION_STORE},
    packet_encryption::{decrypt_packet, encrypt_packet}
};

// Connected Client Struct
pub struct ConnectedClient {
    pub user_id: String,
    pub session_id: String,
    pub stream: Arc<Mutex<SplitSink<WebSocket, Message>>>, // Write half of the WebSocket stream
    pub encryption_key: String,
    pub servers: Vec<String>,
}

impl std::fmt::Display for ConnectedClient {
    // Implement display for ConnectedClient
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectedClient {{ user_id: {}, session_id: {}, servers: {:?} }}", self.user_id, self.session_id, self.servers)
    }
}

// Connected Clients Store
pub struct ConnectedClientsStore {
    pub clients: Vec<ConnectedClient>,
}

lazy_static! {
    pub static ref CONNECTED_CLIENTS: Arc<Mutex<ConnectedClientsStore>> = Arc::new(Mutex::new(ConnectedClientsStore {
        clients: Vec::new(),
    }));
}

// This function returns the Warp route for WebSocket connections
pub async fn listener_endpoint(debug: bool) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {

    if debug {
        setup_debug_user().await;
    }

    // WebSocket route
    warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            // Upgrade the connection to WebSocket and pass it to `handle_client`.
            ws.on_upgrade(move |socket| handle_client(socket))
        })
}

// Handle a new WebSocket client connection
async fn handle_client(ws: WebSocket) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let write = Arc::new(Mutex::new(ws_tx)); // Wrap `ws_tx` in Arc<Mutex<_>> to share it

    let mut session = Session::new();
    let temp_session = Uuid::new_v4().to_string();

    let connected_client = ConnectedClient {
        user_id: session.user_id.clone(),
        session_id: temp_session.clone(), // Set the session ID to a unique value for this session
        stream: Arc::clone(&write),
        encryption_key: String::new(),
        servers: vec![],
    };

    // Add the connected client to the store
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;
    connected_clients.clients.push(connected_client);
    drop(connected_clients);

    // Process incoming WebSocket messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap();
                    let write_clone = Arc::clone(&write); // Clone the Arc for use in the async block
                    handle_packet(text.as_bytes(), &mut session, write_clone, &temp_session).await;
                }
                if msg.is_binary() {
                    let bin = msg.as_bytes();
                    let write_clone = Arc::clone(&write); // Clone the Arc for use in the async block
                    handle_packet(&bin, &mut session, write_clone, &temp_session).await;
                }
                if msg.is_close() {
                    info!("Connection closed for session: {} (Empty means no login occurred)", session.session_id);
                    remove_connected_client(&session.session_id, &temp_session).await;
                    break;
                }
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                remove_connected_client(&session.session_id, &temp_session).await;
                break;
            }
        }
    }
}


// Remove the connected client from the store when they disconnect
async fn remove_connected_client(session_id: &str, temp_session: &str) {
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;

    // Find the client by session_id or temp_session
    let index = connected_clients.clients.iter().position(|c| c.session_id == session_id)
        .or_else(|| connected_clients.clients.iter().position(|c| c.session_id == temp_session));

    if let Some(index) = index {
        connected_clients.clients.remove(index);
        info!("Removed client with session: {}", session_id);
    }
}


async fn handle_packet(packet: &[u8], session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>, temp_session: &String) {
    if session.is_empty() {
        let session_store = Arc::clone(&SESSION_STORE);
        let sessions = session_store.lock().unwrap();

        // Get first 36 bytes of the packet
        let session_uuid = String::from_utf8_lossy(&packet[..36]).to_string();

        // Check if the session exists in the session store
        if let Some(s) = sessions.get(&session_uuid) {
            // Check if the session has expired
            if s.expiration < chrono::Utc::now().timestamp() {
                // Session has expired
                warn!("Session: {} has expired", session_uuid);

                // Remove the session from the session store
                session_store.lock().unwrap().remove(&session_uuid);

                return;
            }

            // Update the session object with the values from the session store
            session.update(s);
        } else {
            // If the session does not exist, ignore the packet
            return;
        }

        info!("Session: {:?}", session);

        drop(sessions);
    }


    // Get a connection to the database
    let conn = get_db_connection().await.unwrap();

    // Check user access
    let user = get_user_by_id(&conn, &session.user_id).await.unwrap();

    if let Some(user) = user {
        if !user.has_access {
            // User does not have access
            warn!("User: {} does not have access", session.user_id);
            return;
        }
    } else {
        // Invalid user
        warn!("Invalid user: {}", session.user_id);
        return;
    }

    // Extract the session UUID from the packet
    let session_uuid = extract_session_uuid(packet);

    // Check if the session UUID matches the session UUID in the session object
    if session_uuid != session.session_id {
        warn!("Invalid session UUID");
        // Invalid session UUID
        return;
    }

    // Remove the session UUID from the packet
    let packet = &packet[36..];

    // Decrypt the packet using symmetric AES encryption
    let decrypted_packet = decrypt_packet_helper(packet, session);
    

    // Extract the nonce from the packet
    let nonce = extract_nonce(&decrypted_packet);

    if nonce != session.nonce {
        warn!("Invalid nonce");
        // Invalid nonce
        return;
    }

    // Remove the nonce from the packet
    let decrypted_packet = &decrypted_packet[16..];

    // Extract the packet type from the packet
    let packet_type = extract_packet_type(decrypted_packet);
    

    let data = extract_data(decrypted_packet);

    match packet_type {
        0 => {
            let write = Arc::clone(&write); // Clone the Arc for use in the async block
            handle_client_hello(session.user_id.clone(), session_uuid, nonce, write, session.encryption_key.clone(), temp_session).await;
        }
        2 => {
            handle_request_server_messages(session_uuid, nonce, data, write, session).await;
        }
        4 => {
            handle_client_message(session_uuid, nonce, data, session).await;
        }
        6 => {
            change_user_access(session_uuid, nonce, data, session, write).await;
        }
        8 => {
            get_server_users(session_uuid, nonce, data, session.encryption_key.clone(), write).await;
        }
        10 => {
            create_new_server(session_uuid, nonce, data, session, write).await;
        }
        12 => {
            change_user_access_to_server(session_uuid, nonce, data, session, write).await;
        }
        14 => {
            update_nickname(session_uuid, nonce, data, session, write).await;
        }
        16 => {
            delete_account(session_uuid, nonce, data, session, write).await;
        }
        18 => {
            get_servers_admin(session_uuid, nonce, session, write).await;
        }
        20 => {
            delete_server_admin(session_uuid, nonce, data, session, write).await;
        }
        _ => {
            // Invalid packet type
            warn!("Invalid packet type: {}", packet_type);
        }
    }
}

fn decrypt_packet_helper(packet: &[u8], session: &mut Session) -> Vec<u8> {
    let key = session.encryption_key.as_bytes(); 
    decrypt_packet(packet, key)
}

fn extract_session_uuid(packet: &[u8]) -> String {
    String::from_utf8_lossy(&packet[..36]).to_string()
}

fn extract_nonce(packet: &[u8]) -> String {
    // Get first 16 bytes of the packet and convert to string
    String::from_utf8_lossy(&packet[..16]).to_string()
}

fn extract_packet_type(packet: &[u8]) -> u8 {
    // Get the number at the start of the packet, followed by either a { or the end of the packet
    let str = String::from_utf8_lossy(&packet[..2]).to_string();
    if str.contains('{') {
        let str = str.replace('{', "");
        str.parse::<u8>().unwrap()
    } else {
        // If there is no {, then check that the string is a number before parsing
        if str.parse::<u8>().is_ok() {
            str.parse::<u8>().unwrap()
        } else {
            // Get only the first character
            let str = str.chars().next().unwrap().to_string();
            str.parse::<u8>().unwrap()
        }
    }
}

fn extract_data(packet: &[u8]) -> String {
    match String::from_utf8(packet.to_vec()) {
        Ok(decoded_string) => {
            // Remove null bytes from the string
            let mut decoded_string = decoded_string.trim_matches(char::from(0)).to_string();
            
            // Remove any characters that precede the first {
            if let Some(pos) = decoded_string.find('{') {
                decoded_string = decoded_string[pos..].to_string();
            }

            // If there is no {, then the data is empty
            if !decoded_string.contains('{') {
                decoded_string = String::new();
            }
            
            decoded_string
        },
        Err(e) => {
            println!("Failed to decode UTF-8: {}", e);
            String::new() // Return an empty string on failure, or handle as needed
        }
    }
}

async fn handle_client_hello(user_id: String, session_uuid: String, nonce: String, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>, encryption_key: String, temp_session: &String) {
    // Get a connection to the database
    let conn = get_db_connection().await.unwrap();

    // Get the user from the database
    let user = get_user_by_id(&conn, &user_id).await.unwrap().unwrap();

    // Get a list of servers the user has access to
    let servers: Vec<String> = serde_json::from_str(&user.servers).unwrap();

    let servers: Vec<i64> = servers.iter().map(|s| s.parse().unwrap()).collect();

    // Fetch server structs from the database
    let mut server_structs = Vec::new();
    for server in servers {
        let server_struct = get_server_by_id(&conn, server).await.unwrap().unwrap();
        server_structs.push(server_struct);
    }

    // Create a JSON object with the server names and IDs
    let mut server_json = Vec::new();
    for server in server_structs {
        let server = json!({
            "id": server.id,
            "name": server.name,
        });
        server_json.push(server);
    }

    let data = json!({
        "servers": server_json,
    }).to_string();


    // Get the connected client from the connected clients store
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;
    let connected_client = connected_clients.clients.iter_mut().find(|c| c.session_id == *temp_session).unwrap();
    
    // Update the values in the connected client
    connected_client.user_id.clone_from(&user_id);
    connected_client.session_id.clone_from(&session_uuid);
    connected_client.servers = server_json.iter().map(|s| s["id"].to_string()).collect();
    connected_client.encryption_key.clone_from(&encryption_key);

    // Insert the updated connected client back into the connected clients store
    drop(connected_clients);



    let packet_response = construct_ttpp(
        session_uuid,
        nonce,
        1,
        data,
        encryption_key,
    );

    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }

}

async fn handle_request_server_messages(session_uuid: String, nonce: String, data: String, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>, session: &mut Session) {

    let data: ServerMessagesData = serde_json::from_str(&data).unwrap();

    // Ensure user has access to the server
    // Get user servers from session
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let connected_clients = connected_clients_store.lock().await;
    let connected_client = connected_clients.clients.iter().find(|c| c.session_id == session_uuid);
    if connected_client.is_none() {
        // User is not connected
        if session.email != dotenv::var("ADMIN_EMAIL").unwrap() {
            warn!("Unauthed client attempting to grab servers");
            return;
        }
    } else if !connected_client.unwrap().servers.contains(&data.server_id.to_string()) {
        // User does not have access to the server
        warn!("User: {} does not have access to server: {}", connected_client.unwrap().user_id, data.server_id);
        return;
    }


    let conn = get_db_connection().await.unwrap();

    let messages = get_messages(&conn, data.server_id, data.known_messages).await.unwrap();

    // Create a JSON object with the messages
    let mut messages_json = Vec::new();
    for message in messages {
        let message = json!({
            "id": message.id,
            "userid": message.userid,
            "userident": message.userident,
            "message": message.message,
            "timestamp": message.timestamp,
        });
        messages_json.push(message);
    }

    let data = json!({
        "server_id": data.server_id,
        "messages": messages_json,
    }).to_string();


    let packet_response = construct_ttpp(
        session_uuid,
        nonce,
        3,
        data,
        session.encryption_key.clone(),
    );

    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }


}



async fn handle_client_message(session_uuid: String, nonce: String, data: String, session: &mut Session) {
    // Deserialize the data into a ClientMessageData struct
    let data: ClientMessageData = serde_json::from_str(&data).unwrap();

    // Get a connection to the database
    let conn = get_db_connection().await.unwrap();


    let user = get_user_by_id(&conn, &session.user_id).await.unwrap().unwrap();

    // Check if the user has access to the server
    let servers: Vec<String> = serde_json::from_str(&user.servers).unwrap();
    let servers: Vec<i64> = servers.iter().map(|s| s.parse().unwrap()).collect();

    if servers.contains(&data.server_id) {
        // User has access to the server
        insert_message(&conn, data.server_id, &session.user_id, &user.ident, &data.message).await.unwrap();
    } else {
        // User does not have access to the server
        warn!("User: {} does not have access to server: {}", session.user_id, data.server_id);
        return;
    }

    // Check the ID of the saved message
    let messages = get_messages(&conn, data.server_id, 0).await.unwrap();
    let message_id = messages.first().unwrap().id;
    let timestamp = &messages.first().unwrap().timestamp;

    // Get all connected clients
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;

    let response = json!({
        "server_id": data.server_id,
        "id": message_id,
        "userid": session.user_id,
        "userident": user.ident,
        "message": data.message,
        "timestamp": timestamp,
    }).to_string();



    // Iterate over all connected clients
    for client in connected_clients.clients.iter_mut() {

        let packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            5,
            response.clone(),
            client.encryption_key.clone(),
        );
        // Check if the client is connected to the server
        if client.servers.contains(&data.server_id.to_string()) {
            // Send the response to the client
            let response = Message::binary(packet_response);
            let mut write = client.stream.lock().await; // Lock the mutex before sending
            match write.send(response).await {
                Ok(()) => continue,
                Err(_) => error!("Failed to send message"),
            }
        }
    }
}

async fn change_user_access(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {

    let data: ChangeUserAccessData = serde_json::from_str(&data).unwrap();

    let conn = get_db_connection().await.unwrap();
    let user = get_user_by_id(&conn, &session.user_id).await.unwrap().unwrap();

    // Get email of the user
    let email = user.email;

    if email != dotenv::var("ADMIN_EMAIL").unwrap() {
        // User is not an admin
        warn!("User: {} is not an admin", session.user_id);
        return;
    }

    if data.access {
        // Grant access to the user
        grant_access(&conn, &data.user_id).await.unwrap();
    } else {
        // Revoke access from the user
        revoke_access(&conn, &data.user_id).await.unwrap();
    }



    let response = json!({
        "success": true,
    }).to_string();

    let packet_response = construct_ttpp(
        session_uuid.clone(),
        nonce.clone(),
        7,
        response,
        session.encryption_key.clone(),
    );

    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }

}


async fn get_server_users(session_uuid: String, nonce: String, data: String, encryption_key: String, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>, ) {
    let data: RequestServerUsersData = serde_json::from_str(&data).unwrap();
    let server_id = data.server_id;
    let conn = get_db_connection().await.unwrap();

    let mut users: Vec<String> = if server_id == 0 {
        // Get all users
        let users = get_users(&conn).await.unwrap();
        let mut user_ids: Vec<String> = Vec::new();
        for user in users {
            user_ids.push(user.id);
        }
        user_ids
    } else {
        // Check if the server exists
        if get_server_by_id(&conn, server_id).await.unwrap().is_none() {
            // Server does not exist
            warn!("Server: {} does not exist", server_id);
            return;
        }

        let users = get_server_by_id(&conn, server_id).await.unwrap().unwrap().users;
        let user_ids: Vec<String> = serde_json::from_str(&users).unwrap();
        user_ids
    };




    // remove TurTur if it exists
    if users.contains(&"TurTur".to_string()) {
        users.retain(|u| u != "TurTur");
    }


    // Convert user IDs to usernames
    let mut usernames = Vec::new();
    for user in users.clone() {
        let user = get_user_by_id(&conn, &user).await.unwrap().unwrap();
        if user.username == "{USER DELETED}" {
            continue;
        }
        usernames.push(user.ident);
    }

    // Make a 2D vector to store the users and a boolean value for if they are connected
    let mut users_connected = Vec::new();
    for (i, user) in usernames.iter().enumerate() {
        users_connected.push(vec![user.clone(), "false".to_string(), users[i].clone()]);
    }

    // Loop through the connected clients and see if they are connected to the server
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;

    for client in connected_clients.clients.iter_mut() {
        if client.servers.contains(&server_id.to_string()) {
            // Set the user to connected
            if let Some(index) = users_connected.iter().position(|u| u[2] == client.user_id) {
                users_connected[index][1] = "true".to_string();
            }
        }
    }

    drop(connected_clients);

    // Create a JSON object with the users and if they are connected
    let mut users_json = Vec::new();
    for user in users_connected {
        let user = json!({
            "username": user[0],
            "connected": user[1],
        });
        users_json.push(user);
    }

    let data = json!({
        "server_id": server_id,
        "users": users_json,
    }).to_string();


    let packet_response = construct_ttpp(
        session_uuid.clone(),
        nonce.clone(),
        9,
        data,
        encryption_key.clone(),
    );

    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }
}

async fn create_new_server(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {

    let data: CreateNewServerData = serde_json::from_str(&data).unwrap();

    let conn = get_db_connection().await.unwrap();
    
    let result = insert_server(&conn, &data.server_name, &session.user_id, "").await;
    
    let mut server_id = 0;
    
    if result.is_ok(){
        let id_check = result.unwrap();
        if id_check == -1 {
            server_id = -1;
        } else {
            server_id = id_check;
        }
    }
    
    let response = json!({
        "id": server_id,
        "name": data.server_name,
    }).to_string();
    
    // Update the user's servers in connected clients
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;
    let connected_client = connected_clients.clients.iter_mut().find(|c| c.session_id == session_uuid).unwrap();
    connected_client.servers.push(server_id.to_string());
    drop(connected_clients);
    
    let packet_response = construct_ttpp(
        session_uuid.clone(),
        nonce.clone(),
        11,
        response,
        session.encryption_key.clone(),
    );
    
    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }
}


async fn change_user_access_to_server(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {
    // Deserialize the data into a AddUserToServerData struct
    let data: ChangeUserAccessToServerData = serde_json::from_str(&data).unwrap();

    let mut packet_response = Vec::new();

    // if server_id is 1, then the user is trying to modify the general server
    if data.server_id == 1 {
        warn!("User: {} is trying to modify the general server", session.user_id);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "You cannot modify the general server",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }

    if data.server_id < 1 {
        warn!("User: {} is trying to modify an invalid server", session.user_id);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "You are not connected to a server",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }

    // Send error message if packet_response is not empty
    if !packet_response.is_empty() {
        // Send the response to the client
        let response = Message::binary(packet_response.clone());
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => return,
            Err(_) => {
                error!("Failed to send message");
                return;
            },
        }
    }

    // If the user does not own the server, return
    let conn = get_db_connection().await.unwrap();
    let server = get_server_by_id(&conn, data.server_id).await.unwrap().unwrap();
    if server.owner != session.user_id {
        warn!("User: {} does not own server: {}", session.user_id, data.server_id);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "You do not own this server",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }



    // Get the user from the database
    let user = get_user_by_ident(&conn, &data.username).await.unwrap().unwrap();

    // If user is trying to modify their own access, return
    if user.id == session.user_id {
        warn!("User: {} is trying to modify their own access", session.user_id);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "You cannot modify your own access",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }

    // Send error message if packet_response is not empty
    if !packet_response.is_empty() {
        // Send the response to the client
        let response = Message::binary(packet_response.clone());
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => return,
            Err(_) => {
                error!("Failed to send message");
                return;
            },
        }
    }


    if data.access {
        add_user_to_server(&conn, &user.id, data.server_id).await.unwrap();
    } else {
        remove_user_from_server(&conn, &user.id, data.server_id).await.unwrap();
    }

    // If user is connected, update their servers
    let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
    let mut connected_clients = connected_clients_store.lock().await;
    for client in connected_clients.clients.iter_mut() {
        if client.user_id == user.id {
            if data.access {
                client.servers.push(data.server_id.to_string());

                // Send new server packet
                let response = json!({
                    "id": data.server_id,
                    "name": server.name,
                }).to_string();

                let packet_response = construct_ttpp(
                    session_uuid.clone(),
                    nonce.clone(),
                    11,
                    response,
                    client.encryption_key.clone(),
                );

                // Send the response to the client
                let response = Message::binary(packet_response);
                let mut write = client.stream.lock().await; // Lock the mutex before sending
                match write.send(response).await {
                    Ok(()) => return,
                    Err(_) => error!("Failed to send message"),
                }
            } else {
                client.servers.retain(|s| s != &data.server_id.to_string());
            }
        }
    }



    let response = json!({
        "success": true,
    }).to_string();

    let packet_response = construct_ttpp(
        session_uuid.clone(),
        nonce.clone(),
        7,
        response,
        session.encryption_key.clone(),
    );



    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => (),
        Err(_) => error!("Failed to send message"),
    }
}


async fn update_nickname(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {
    // Deserialize the data into a UpdateNicknameData struct
    let data: UpdateNicknameData = serde_json::from_str(&data).unwrap();

    let conn = get_db_connection().await.unwrap();

    let users = get_users(&conn).await.unwrap();
    let mut user_idents: Vec<String> = Vec::new();
    for user in users {
        user_idents.push(user.ident);
    }

    let mut packet_response = Vec::new();

    // Check if the new username is already taken
    if user_idents.contains(&data.new_username) {
        warn!("Username: {} is already taken", data.new_username);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "Username is already taken",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }

    // Check if the new username is longer than 30 characters
    if data.new_username.len() > 30 {
        warn!("Username: {} is longer than 30 characters", data.new_username);
        packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            13,
            json!({
                "message": "Username is longer than 30 characters",
            }).to_string(),
            session.encryption_key.clone(),
        );
    }

    // Send error message if packet_response is not empty
    if !packet_response.is_empty() {
        // Send the response to the client
        let response = Message::binary(packet_response);
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => return,
            Err(_) => {
                error!("Failed to send message");
                return;
            },
        }
    }
    
    let old_username = get_user_by_id(&conn, &session.user_id).await.unwrap().unwrap().ident;
    
    // Update the user's ident in the database
    let result = update_user_ident(&conn, &session.user_id, &data.new_username).await;
    
    if result.is_ok() {
        let response = json!({
            "old_username": old_username,
            "new_username": data.new_username,
        }).to_string();
        

        
        // Send ident update to everyone
        let connected_clients_store = Arc::clone(&CONNECTED_CLIENTS);
        let mut connected_clients = connected_clients_store.lock().await;
        for client in connected_clients.clients.iter_mut() {
            let packet_response = construct_ttpp(
                session_uuid.clone(),
                nonce.clone(),
                15,
                response.clone(),
                client.encryption_key.clone(),
            );
            let response = Message::binary(packet_response);
            let mut write = client.stream.lock().await; // Lock the mutex before sending
            match write.send(response).await {
                Ok(()) => continue,
                Err(_) => error!("Failed to send message"),
            }
        }
    } else {
        let response = json!({
            "success": false,
        }).to_string();
        
        let packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            7,
            response,
            session.encryption_key.clone(),
        );
        
        // Send the response to the client
        let response = Message::binary(packet_response);
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => (),
            Err(_) => error!("Failed to send message"),
        }
    }
}


async fn delete_account(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>){

    let user_id: String;

    if data.is_empty() {
        user_id = session.user_id.clone();
    } else {
        if session.email != dotenv::var("ADMIN_EMAIL").unwrap() {
            warn!("User: {} is not an admin", session.user_id);
            return;
        }
        let data: DeleteAccountData = serde_json::from_str(&data).unwrap();
        user_id = data.user_id;
    }
    
    let conn = get_db_connection().await.unwrap();
    
    // Get the user from the database
    let user = get_user_by_id(&conn, &user_id).await.unwrap().unwrap();
    
    if user.email == dotenv::var("ADMIN_EMAIL").unwrap() {
        warn!("User: {} is trying to delete the admin account", session.user_id);
        return;
    }

    let result = delete_user(&conn, &user_id).await;

    if result.is_ok() && data.is_empty() {
        // Remove session from session store
        let session_store = Arc::clone(&SESSION_STORE);
        session_store.lock().unwrap().remove(&session_uuid);
    }

    match result {
        Ok(_) => {
            let response = json!({
                "success": true,
            }).to_string();

            let packet_response = construct_ttpp(
                session_uuid.clone(),
                nonce.clone(),
                7,
                response,
                session.encryption_key.clone(),
            );

            // Send the response to the client
            let response = Message::binary(packet_response);
            let mut write = write.lock().await; // Lock the mutex before sending
            match write.send(response).await {
                Ok(()) => return,
                Err(_) => error!("Failed to send message"),
            }
        },
        Err(e) => {
            error!("Failed to delete user: {}", e);
            let response = json!({
                "success": false,
            }).to_string();

            let packet_response = construct_ttpp(
                session_uuid.clone(),
                nonce.clone(),
                7,
                response,
                session.encryption_key.clone(),
            );

            // Send the response to the client
            let response = Message::binary(packet_response);
            let mut write = write.lock().await; // Lock the mutex before sending
            match write.send(response).await {
                Ok(()) => return,
                Err(_) => error!("Failed to send message"),
            }
        }
    }
}



async fn get_servers_admin(session_uuid: String, nonce: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {

    // Ensure the user is an admin
    if session.email != dotenv::var("ADMIN_EMAIL").unwrap() {
        warn!("User: {} is not an admin, tried to enumerate servers.", session.user_id);
        return;
    }

    let conn = get_db_connection().await.unwrap();

    let servers = get_servers(&conn).await.unwrap();

    let mut server_json = Vec::new();
    for server in servers {
        let server = json!({
            "id": server.id,
            "name": server.name,
            "owner": server.owner,
            "users": server.users,
        });
        server_json.push(server);
    }

    let data = json!({
        "servers": server_json,
    }).to_string();

    let packet_response = construct_ttpp(
        session_uuid.clone(),
        nonce.clone(),
        19,
        data,
        session.encryption_key.clone(),
    );

    // Send the response to the client
    let response = Message::binary(packet_response);
    let mut write = write.lock().await; // Lock the mutex before sending
    match write.send(response).await {
        Ok(()) => return,
        Err(_) => error!("Failed to send message"),
    }

}


async fn delete_server_admin(session_uuid: String, nonce: String, data: String, session: &mut Session, write: Arc<Mutex<impl SinkExt<Message> + Unpin>>) {

    // Ensure the user is an admin
    if session.email != dotenv::var("ADMIN_EMAIL").unwrap() {
        warn!("User: {} is not an admin, tried to delete a server.", session.user_id);
        return;
    }

    let conn = get_db_connection().await.unwrap();

    let data: RequestServerUsersData = serde_json::from_str(&data).unwrap();
    
    if data.server_id == 1 {
        warn!("User: {} is trying to delete the general server", session.user_id);
        return;
    }

    let result = delete_server(&conn, data.server_id).await;

    if result.is_ok() {
        let response = json!({
            "success": true,
        }).to_string();

        let packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            21,
            response,
            session.encryption_key.clone(),
        );

        // Send the response to the client
        let response = Message::binary(packet_response);
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => return,
            Err(_) => error!("Failed to send message"),
        }
    } else {
        error!("Failed to delete server: {}", result.unwrap_err());
        let response = json!({
            "success": false,
        }).to_string();

        let packet_response = construct_ttpp(
            session_uuid.clone(),
            nonce.clone(),
            21,
            response,
            session.encryption_key.clone(),
        );

        // Send the response to the client
        let response = Message::binary(packet_response);
        let mut write = write.lock().await; // Lock the mutex before sending
        match write.send(response).await {
            Ok(()) => return,
            Err(_) => error!("Failed to send message"),
        }
    }

}




fn construct_ttpp(session_id: String, nonce: String, ptype: u8, data: String, encryption_key: String) -> Vec<u8> {
    // Packet consists of:
    // 36 bytes of session UUID, unencrypted
    // -- Encrypted --
    // 16 bytes of nonce
    // 1 packet type (can be one or two digits)
    // -- Data --
    // Data, up to 65535 bytes in a JSON format

    // Construct the packet
    let mut packet = Vec::new();
    let session_id = session_id.as_bytes();
    let nonce = nonce.as_bytes();
    let ptype = vec![ptype];
    let data = data.as_bytes();

    // Add the session ID to the packet
    packet.extend_from_slice(&session_id);

    // create a new vector to store the encrypted data
    let mut encrypted_data = Vec::new();

    // Add the nonce to the packet
    encrypted_data.extend_from_slice(&nonce);

    // Add the packet type to the packet
    encrypted_data.extend_from_slice(&ptype);

    // Add the data to the packet
    encrypted_data.extend_from_slice(&data);

    // Encrypt the data
    let encrypted_data = encrypt_packet(&encrypted_data, encryption_key.as_bytes());

    // Add the encrypted data to the packet
    packet.extend_from_slice(&encrypted_data);

    packet
}


async fn setup_debug_user() { 
    warn!("Setting up debug user, DO NOT USE IN PRODUCTION");
    //Add a session for debugging
    let session = Session{
        user_id: "Bananaid".to_string(), // 36 bytes long
        session_id: "BananaBananaBananaBananaBananaBanana".to_string(),
        encryption_key: "BananaBananaBananaBananaBananaBa".to_string(),
        nonce: "BananaBananaBana".to_string(),
        email: "Banana".to_string(),
        expiration: 9999999999999,
    };
    let session_uuid = "BananaBananaBananaBananaBananaBanana".to_string();
    let session_store = Arc::clone(&SESSION_STORE);
    let mut sessions = session_store.lock().unwrap();
    sessions.insert(session_uuid.clone(), session);
    drop(sessions);

    // Insert test user to database for debugging
    let conn = get_db_connection().await.unwrap();
    let id = "Bananaid";
    let username = "Banana";
    let email = "Banana";

    insert_user(&conn, id, username, email).await.unwrap();
    grant_access(&conn, id).await.unwrap();

    // for i in 0..100 {
    //     insert_message(&conn, 1, id, ident, format!("Message {}", i).to_string().as_str()).await.unwrap();
    // }

    drop(conn);
}


// Server Messages Data packet struct
#[derive(serde::Deserialize)]
struct ServerMessagesData {
    server_id: i64,
    known_messages: i64,
}

// Client Message packet struct
#[derive(serde::Deserialize)]
struct ClientMessageData {
    server_id: i64,
    message: String,
}

// Change User Access packet struct
#[derive(serde::Deserialize)]
struct ChangeUserAccessData {
    user_id: String,
    access: bool,
}

// Request Server Users packet struct
#[derive(serde::Deserialize)]
struct RequestServerUsersData {
    server_id: i64,
}

// Create New Room packet struct
#[derive(serde::Deserialize)]
struct CreateNewServerData {
    server_name: String,
}

// Add User To Room packet struct
#[derive(serde::Deserialize, Debug)]
struct ChangeUserAccessToServerData {
    server_id: i64,
    username: String,
    access: bool,
}

// Update Nickname packet struct
#[derive(serde::Deserialize)]
struct UpdateNicknameData {
    new_username: String,
}

// Delete account struct
#[derive(serde::Deserialize)]
struct DeleteAccountData {
    user_id: String,
}