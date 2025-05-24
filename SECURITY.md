# Security Policy

## Overview

reachmyfiles uses strong end-to-end encryption (E2EE) for all communications and file transfers between the desktop client and the browser client.

- **Key exchange:** ECDH (P256 curve) is used to establish a shared secret between the desktop app and the web browser, with no prior knowledge required.
- **Data encryption:** All file lists and file chunks are encrypted using AES-256-GCM with a key derived from the ECDH handshake.
- **Relay server:** The server acts only as a relay, forwarding encrypted payloads. It never has access to any decrypted data, file contents, or user encryption keys.

## Reporting a Vulnerability

If you discover a security issue or vulnerability, **please open a private issue** or contact the maintainer directly by email at [your-email@example.com].  
(Replace this with your actual contact email if you want.)

Please provide as many details as possible so we can resolve the issue quickly and safely.

## Can the server see my files?

**No.**  
- All file lists, file names, and file contents are always encrypted between your device and the recipient’s browser.
- The server only forwards encrypted data and never stores it.

## Security best practices

- Always download the desktop client from the official repository.
- Review the source code if you have concerns about privacy or data handling.
- Keep your Node.js and dependencies up to date for the best security.

---

Thank you for helping keep reachmyfiles secure!
