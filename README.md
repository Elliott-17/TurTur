# TurTur

TurTur is a Rust-based web chat application.


This project is intended as a personal project for me to learn Rust, I make no promises to consistently maintain or update TurTur :)

# 

# Setup

To setup, ensure a version of perl is installed to allow for building openssl.

To run TurTur: `cargo run`
To run TurTur in debug mode: `cargo run -- --debug`

Debug mode will host TurTur on localhost, without HTTPS.



# Known Issues

- Removing a user from a room while they are connected to the server does not remove that room from their local room list. (Although they will no longer recieve messages sent to the room)
- There is no mobile/small screen support. Mobile users will not be able to send messages to rooms, or navigate rooms/connected users easily.
- There is no easy way to replace the domain being used by the server, it is currently hardcoded to: `https://turtur.ddns.net`
- There is also no easy way to replace what HTTPS certificates are being used, currently hardcoded to: `/etc/letsencrypt/live/turtur.ddns.net/`
 

## Artwork

Artwork in the /images directory is made by SmileZ: https://www.instagram.com/theclowntoon/
