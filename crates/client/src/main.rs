//! A simple example of hooking up stdin/stdout to a WebSocket stream.
//!
//! The first command-line argument is your username, which is appended to every message.
//! 
//! You will then connect to a localhost server and
//! forward all data read on stdin to the server, printing out all data
//! received on stdout.
//!
//! Note that this is not currently optimized for performance, especially around
//! buffer management. Rather it's intended to show an example of working with a
//! client.
//!
//! This client works together with the `server`.

use std::env;
use std::fs;

use futures_util::{future, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use chacha20poly1305::{
    aead::{Aead, Generate, Key, KeyInit},
    ChaCha20Poly1305, Nonce
};

#[tokio::main]
async fn main() {
    let url = String::from("ws://localhost:8080/");
    let username = env::args().nth(1).unwrap_or_else(|| panic!("this program requires at least one argument"));

    let key_bytes = fs::read("client.key")
        .expect("Should have been able to read the file");

    let key = Key::<ChaCha20Poly1305>::try_from(key_bytes.as_slice())
        .expect("Key must be exactly 32 bytes");

    let cipher = ChaCha20Poly1305::new(&key);

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx, username.clone(), cipher.clone()));

    let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = {
        read.for_each(|message| async {
            let data = message.unwrap().into_data();

            if data.len() < 12 {
                eprintln!("Invalid encrypted message");
                return;
            }

            let (nonce_bytes, ciphertext) = data.split_at(12);

            let nonce = Nonce::try_from(nonce_bytes)
                .expect("Nonce must be exactly 12 bytes");

            match cipher.decrypt(&nonce, ciphertext) {
                Ok(plaintext) => {
                    tokio::io::stdout()
                        .write_all(&plaintext)
                        .await
                        .unwrap();
                }
                Err(_) => {
                    eprintln!("Failed to decrypt message");
                }
            }
        })
    };

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}

// Our helper method which will read data from stdin and send it along the
// sender provided.
async fn read_stdin(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    username: String,
    cipher: ChaCha20Poly1305,
) {
    let mut stdin = tokio::io::stdin();
    loop {
        let mut buf = vec![0; 1024];
        let n = match stdin.read(&mut buf).await {
            Err(_) | Ok(0) => break,
            Ok(n) => n,
        };
        buf.truncate(n);

        let message = String::from_utf8_lossy(&buf);
        let formatted = format!("{}: {}", username, message);

        let nonce = Nonce::generate(); // MUST be unique per message
        let ciphertext = cipher.encrypt(&nonce, formatted.as_bytes()).expect("encryption failed");
        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&ciphertext);

        tx.unbounded_send(Message::binary(payload)).unwrap();
    }
}
