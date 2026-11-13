# rust-chat
A simple chat app written in Rust using WebSockets. Built purely for educational purposes.

## Usage

Configure and start tor

```
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:8081
```

Start the server.

```bash
cargo run -p server
```

32 byte e2e.key needs to be in folder on all clients (pre shared)

Start the client.

```bash
cargo run -p client <username> <address>
```

Address is visible in /var/lib/tor/hidden_service/hostname
