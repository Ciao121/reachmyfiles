# reachmyfiles

**reachmyfiles** is a cross-platform, end-to-end encrypted desktop client that allows you to securely share folders from your computer and make them available for download via a web browser.  
No file or file list ever leaves your computer unencrypted — not even the server can decrypt your data.

## Features

- 🔒 End-to-end encryption (E2EE) for all communications and file transfers
- 🌍 Cross-platform: works on Windows, Linux, and macOS (Electron-based)
- 📂 Easy folder sharing: share any local folder with a single click
- ⚡ Modern and user-friendly interface
- 👥 Monitor active downloads and users
- 🛡️ No data is ever stored on the server, only relayed in encrypted form

## How it works

1. **Run the desktop client** on your computer.
2. **Select one or more folders** to share.
3. The app provides a **unique sharing link** for each folder.
4. Anyone with the link can access the folder’s content via a secure web page, and download files — but only when your desktop client is online.
5. **All file lists and file contents are encrypted** end-to-end.  
   The server only relays encrypted data and cannot decrypt anything.

## Why is a central server needed?

Although all file lists and file contents are encrypted end-to-end between your desktop and the browser client, a central relay server is required for communication.

- **No direct connection:** Most users are behind firewalls or NAT, which makes peer-to-peer connections unreliable or impossible.
- **Universal access:** The central server ensures anyone with the link can connect to your shared folder, from anywhere, without special setup.
- **Relay only:** The server only relays encrypted data and cannot decrypt or inspect your files.

In this way, reachmyfiles combines the privacy of end-to-end encryption with the convenience of easy, universal access.

## Requirements

- [Node.js](https://nodejs.org/) (version 16+ recommended)
- Windows, Linux, or macOS

## Installation

1. **Clone this repository**:
   ```sh
   git clone https://github.com/YOUR_USERNAME/reachmyfiles.git
   ```
2. **Install dependencies**:
   ```sh
   npm install
   ```
3. **Run the desktop client**:
   ```sh
   npm start
   ```
   or
   ```sh
   npx electron .
   ```
   *(You may need to install Electron globally: `npm install -g electron`)*

## Usage

- **Add a folder:** Click "Add Folder" in the desktop app and select a local folder to share.
- **Share the link:** Copy the provided link and send it to your recipient.
- **Manage shares:** Enable, disable, or remove shares directly from the desktop client.

> ⚠️ **Note:** For web downloads, the desktop client must remain online.  
> All data remains encrypted during transfer.

## Security

- Uses **ECDH (P256)** for key exchange.
- **AES-256-GCM** for encrypting file lists and file data.
- The server acts only as a relay and never has access to your decrypted files or keys.

For more details, see [SECURITY.md](SECURITY.md) _(or add further documentation here)_.

## License

MIT License (or specify your preferred license)

---

**This project is under active development. Feedback and contributions are welcome!**
