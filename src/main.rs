use env_logger::Builder;
use log::{info, error};
use std::env;

mod endpoints;
use endpoints::setup_endpoints;

mod db;
use db::setup_db;

mod packet_encryption;
mod chatserver;


#[tokio::main]
async fn main() {

    // Initialize the logger with a default level of "info"
    let mut builder = Builder::new();
    builder.filter_level(log::LevelFilter::Info);
    builder.init();

    info!("Starting Turtur...");

    //Setup the database
    let result = setup_db().await;

    match result {
        Ok(conn) => {
            info!("Database setup successful");
            conn
        },
        Err(e) => {
            error!("Error setting up the database: {:?}", e);
            return;
        }
    };

    let args: Vec<String> = env::args().collect();
    let mut debug = false;

    if args.len() > 1 && args[1] == "--debug" {
        info!("Debug mode enabled");
        log::set_max_level(log::LevelFilter::Debug);
        debug = true;
    }


    // Start the web endpoints
    setup_endpoints(debug).await;

}
