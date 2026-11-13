use std::env;
use std::fs;

use futures_util::{future, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{client_async, tungstenite::protocol::Message};

use chacha20poly1305::{
    aead::{Aead, Generate, Key, KeyInit},
    ChaCha20Poly1305, Nonce
};

use arti_client::{TorClient, TorClientConfig};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <username> <address>", args[0]);
        std::process::exit(1);
    }

    let username = args[1].clone();
    let host = args[2].trim_end_matches('/').to_string();

    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .expect("Bootstrap");

    let tor_stream = tor_client.connect((host.as_str(), 80)).await.expect("Tor stream");

    let url = format!("ws://{}/", host);

    let key_bytes = fs::read("e2e.key")
        .expect("Should have been able to read the file");

    let key = Key::<ChaCha20Poly1305>::try_from(key_bytes.as_slice())
        .expect("Key must be exactly 32 bytes");

    let cipher = ChaCha20Poly1305::new(&key);

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx, username.clone(), cipher.clone()));

    let (ws_stream, _) = client_async(&url, tor_stream).await.expect("WebSocket handshake failed");

    println!("WebSocket connected through Tor!");

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
