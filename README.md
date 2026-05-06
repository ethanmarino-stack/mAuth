# mAuth — Self-Hosted Authentication & Licensing System

A lightweight, self-hosted authentication and licensing system designed specifically for **desktop applications**.

mAuth provides **HWID-based locking**, **license key management**, **session validation**, and **version enforcement** — all in a simple, deployable stack using Flask and a native C++ client.

---

## 🚀 Why mAuth?

Most authentication systems are built for web apps (OAuth, Firebase, Auth0).
mAuth is built for a completely different problem:

> **Protecting and distributing desktop software.**

### What makes it different:

* 🔒 **HWID binding** — lock accounts to a specific machine
* 🎫 **Built-in license system** — no external service needed
* ⚡ **Real-time session validation** — prevent bypassing auth
* 📦 **Version enforcement** — force updates when needed
* 🧠 **Self-hosted** — no third-party dependencies
* 💻 **Native C++ client** included

---

## 📌 Use Cases

* Software licensing / activation systems
* Indie developer tools
* Private or paid desktop applications
* Internal tools requiring access control

---

## 🧩 Features

* 🔐 User registration & login with HWID binding
* 🎫 License key generation and tracking
* 💓 Session heartbeat (anti-timeout / anti-bypass)
* 📦 Version control with forced updates
* 🖥️ Local admin panel
* 🔒 HWID lock to prevent account sharing
* 🌐 Cloudflare Tunnel support for external access

---

## 🏗️ Architecture Overview

```
Client (C++)
   ↓
Flask API (Auth Server)
   ↓
SQLite Database
```

**Flow:**

1. User registers with license key
2. HWID is stored and locked
3. Client authenticates → receives session token
4. Heartbeat maintains session
5. Server validates session + version continuously

---

## 📁 Project Structure

```
mAuth/
├── backend/
│   └── mAuthBE/
│       ├── app.py              # Flask auth server
│       ├── requirements.txt    # Python dependencies
│       └── database.db         # SQLite database (auto-created)
└── frontend/
    └── mAuthFE/
        ├── auth.cpp            # C++ client implementation
        ├── auth.h
        ├── auth_state.h
        └── main.cpp            # Example usage
```

---

## ⚙️ Quick Start

### 1. Start the Server

```bash
cd mAuth/backend/mAuthBE
pip install flask flask-cors bcrypt
python app.py
```

Server output:

```
mAuth - Authentication Server
Admin Panel: http://127.0.0.1:5000/admin
```

---

### 2. Expose to Internet (Optional)

```bash
cloudflared tunnel --url http://localhost:5000
```

You’ll get a public URL like:

```
https://example.trycloudflare.com
```

---

### 3. Configure the Client

Edit `auth.cpp`:

```cpp
const wchar_t* SERVER_HOST = L"your-cloudflare-url.trycloudflare.com";
const int SERVER_PORT = 443;
```

---

### 4. Build Client

* Open in Visual Studio
* Build → Release x64

---

### 5. Generate License Keys

* Go to: `http://127.0.0.1:5000/admin`
* Generate keys
* Distribute to users

---

## 🛠️ Admin Panel

Accessible at:

```
http://127.0.0.1:5000/admin
```

### Capabilities:

* License generation & tracking
* User management (reset HWID, delete users)
* Session monitoring and termination
* Version control (force updates)

> ⚠️ Admin panel is restricted to localhost.
> For production environments, additional authentication is recommended.

---

## 🔌 API Endpoints

| Endpoint       | Method | Description               |
| -------------- | ------ | ------------------------- |
| `/login`       | POST   | Authenticate user         |
| `/register`    | POST   | Register with license key |
| `/heartbeat`   | POST   | Maintain session          |
| `/validate`    | POST   | Validate session          |
| `/logout`      | POST   | End session               |
| `/get_version` | GET    | Get version info          |

---

## 🗄️ Database Schema

* **users** — credentials, HWID, license
* **sessions** — tokens, expiry, activity
* **licenses** — keys, usage status
* **version** — version + force update flag

---

## ⚡ Configuration

### Update Version

```bash
sqlite3 database.db "UPDATE version SET version='1.0.1' WHERE id=1;"
```

### Reset HWID

Use admin panel → User Management

---

## 🧪 Troubleshooting

**Connection issues**

* Ensure Flask server is running
* Ensure Cloudflare tunnel is active
* Verify client URL matches server

**HWID mismatch**

* Reset HWID in admin panel

**License errors**

* Ensure key is valid and unused

**Version mismatch**

* Update client or server version

---

## 🔐 Security Notes

* Passwords hashed with bcrypt
* Sessions expire after inactivity
* Heartbeat required for persistence
* HWIDs normalized and enforced

> ⚠️ This system is designed for lightweight protection.
> It is not a replacement for enterprise-grade security.

---

## 📦 Requirements

### Server

* Python 3.8+
* SQLite3
* Flask

### Client

* Windows 7/10/11
* Visual Studio 2019+

---

## 📜 License

This project is licensed under the
**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**.

* Free for personal and non-commercial use
* Commercial use requires permission

Full license:
https://creativecommons.org/licenses/by-nc/4.0/

---

## 🧠 Final Notes

mAuth is built to be:

* Simple to deploy
* Easy to integrate
* Hard to bypass (for its scope)

If you’re building a desktop application and need **basic licensing + authentication**, this gives you a complete starting point.

---

## 👤 Author

Created by Ethan
mAuth Authentication System
