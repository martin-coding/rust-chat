# rust-chat
A simple chat app written in Rust using WebSockets. Built purely for educational purposes.

## Usage

Start the server.

```bash
cargo run -p server
```

Start the clients.

```bash
cargo run -p client Alice
```

```bash
cargo run -p client Bob
```

Now both clients are connected to the server and can chat.