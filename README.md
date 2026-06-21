# SecureMC Proxy

SecureMC is a lightweight, cross-platform security proxy designed to prevent Man-in-the-Middle (MITM) attacks on offline-mode Minecraft servers by implementing a custom cryptographic handshake.

## Getting Started

### For Clients

1. Download the latest binary for your operating system (Windows or Linux) from the **Releases** tab under **Binaries 3.0**.
2. Run the executable; the built-in auto-updater will ensure you are running the latest version.
3. Launch SecureMC and enter the **Server Address** of the proxy you are connecting to.
4. Input your preferred **Local Port** (e.g., 25565).
5. Click **Start Proxy**.
6. Open your Minecraft client and connect to `localhost:[your port choice]`.

### For Servers

Run the server-side component with the following flags:

- `-p [port]`: The port you want the proxy to listen on.
- `-r [ip]:[port]`: The address of your offline-mode Minecraft server.

## Build Instructions

**Requirement:** Go 1.20+

1. Clone the repository and navigate to the directory.
2. Run `go mod tidy` to download all necessary dependencies.
3. Use the following `make` commands:
   - `make all`: Builds both the server and client components.
   - `make server`: Builds the server component only.
   - `make client`: Builds the client component only.

*Note: Client compilations may take significant time during the first build due to the GUI dependency graph.*

## How it Works

SecureMC adds a layer of security between your client and your Minecraft server. It validates server identity using RSA/OAEP to prevent unauthorized interception.

## Security Notice

This tool is intended to add an extra layer of protection to your Minecraft traffic. Always verify fingerprints when connecting to a proxy for the first time. If a "Critical Security Alert" is triggered, do not proceed unless you are certain the server identity has been rotated legitimately.
