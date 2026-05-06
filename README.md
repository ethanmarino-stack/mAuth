# mAuth - Authentication System for Programs

A lightweight, self-hosted authentication system for programs with HWID binding, license keys, session management, and version control.

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**.

You are free to:
- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

Under the following terms:
- Attribution — You must give appropriate credit, provide a link to the license
- NonCommercial — You may not use the material for commercial purposes

For commercial use, please contact the author.

Full license: https://creativecommons.org/licenses/by-nc/4.0/

## Features

- 🔐 User registration and login with HWID binding
- 🎫 License key system (generate and manage keys)
- 💓 Session heartbeat to keep users authenticated
- 📦 Version control and enforcement
- 🖥️ Web-based admin panel (localhost only)
- 🔒 HWID lock to prevent account sharing
- 🚀 Cloudflare Tunnel support for external access

## Project Structure

```
mAuth/
├── backend/
│   └── mAuthBE/
│       ├── app.py              # Flask server (auth backend)
│       ├── requirements.txt    # Python dependencies
│       └── database.db         # SQLite database (auto-created)
└── frontend/
    └── mAuthFE/
        ├── auth.cpp            # C++ client implementation
        ├── auth.h              # Client headers
        ├── auth_state.h        # Client state variables
        └── main.cpp            # Example client usage
```

## Prerequisites

### Server Requirements (where you host the auth server)
- Python 3.8+
- SQLite3
- Cloudflared (for external access)

### Client Requirements
- Windows 7/10/11
- Visual Studio 2019+ (for compilation)

## Quick Start

### Server Setup (Your Machine)

1. **Navigate to the backend folder**
```bash
cd mAuth/backend/mAuthBE
```

2. **Install Python dependencies**
```bash
pip install flask flask-cors bcrypt
```

3. **Run the Flask server**
```bash
python app.py
```

You should see:
```
==================================================
mAuth - Authentication Server
Admin Panel: http://127.0.0.1:5000/admin
==================================================
```

4. **Expose the server to the internet (for friends to connect)**

Using Cloudflare Tunnel (recommended):
```bash
cloudflared tunnel --url http://localhost:5000
```

This will give you a URL like: `https://random-name.trycloudflare.com`

> **Note:** Keep both the Flask server and Cloudflare tunnel running in separate terminals.

### Client Setup (Your Program)

1. **Navigate to the frontend folder**
```bash
cd mAuth/frontend/mAuthFE
```

2. **Update the server URL in `auth.cpp`**
```cpp
// Change this to your Cloudflare URL
const wchar_t* SERVER_HOST = L"your-cloudflare-url.trycloudflare.com";
const int SERVER_PORT = 443;
```

3. **Update the version number (if needed)**
```cpp
// In check_version() function
std::string current_version = "1.0.0";
```

4. **Compile the client**
   - Open in Visual Studio
   - Build as Release x64
   - The executable will be generated

5. **Generate license keys**
   - Open admin panel: `http://127.0.0.1:5000/admin`
   - Go to "License Management"
   - Click "Generate" to create keys
   - Share keys with your users

6. **Distribute your program**
   - Give users the compiled `.exe`
   - Give them a license key
   - They can now register/login

## Admin Panel

Access the admin panel at: `http://127.0.0.1:5000/admin`

### Features:
- **License Management** - Generate new license keys, view unused/used keys
- **User Management** - Reset HWIDs, delete users
- **Version Control** - Update version number, set force update
- **Session Management** - View active sessions, kill sessions
- **User List** - View all registered users with their HWIDs and license keys

> **Security Note:** The admin panel is only accessible from localhost (your machine). No password needed - physical access is the security.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | POST | Authenticate user and create session |
| `/register` | POST | Register new user with license key |
| `/heartbeat` | POST | Keep session alive (call every 30 seconds) |
| `/validate` | POST | Check if session is still valid |
| `/logout` | POST | End a session |
| `/get_version` | GET | Get current version info |

## Database Structure

The system creates a `database.db` file with these tables:

- `users` - User accounts (username, password hash, HWID, license key)
- `sessions` - Active sessions (tokens, expiry, last seen)
- `licenses` - License keys (key, used status, used by)
- `version` - Version information (version number, force update flag)

## Configuration

### Changing Default Version

Edit the version in the admin panel or directly in the database:
```bash
sqlite3 database.db "UPDATE version SET version='1.0.1' WHERE id=1;"
```

### Making Update Mandatory

In admin panel, check "Force update" when changing version. Users on old versions will be blocked.

### Resetting a User's HWID

In admin panel → User Management → Enter username → Click "Reset HWID"

This allows a user to use a different computer.

## Troubleshooting

### "Failed to connect to server"
- Make sure Flask server is running (`python app.py`)
- Make sure Cloudflare tunnel is running (`cloudflared tunnel --url http://localhost:5000`)
- Check if the URL in `auth.cpp` matches your current Cloudflare URL
- Verify your friend can reach the URL in their browser

### "Version mismatch"
- Update `current_version` in `auth.cpp` to match the server version
- Or update the version in the admin panel

### "Invalid or already used license key"
- License key is already used or doesn't exist
- Generate a new key in the admin panel

### "HWID mismatch"
- User's HWID doesn't match the one on their account
- Reset their HWID in the admin panel

### Cloudflare tunnel URL changed
- Free Cloudflare tunnels give a new random URL each restart
- Update `SERVER_HOST` in `auth.cpp` and recompile
- Or set up a named tunnel with a Cloudflare account for a permanent URL

## File Structure Details

```
mAuth/
├── backend/
│   └── mAuthBE/
│       ├── app.py              # Flask server (auth backend)
│       ├── requirements.txt    # Python dependencies
│       └── database.db         # SQLite database (auto-created)
└── frontend/
    └── mAuthFE/
        ├── auth.cpp            # C++ client implementation
        ├── auth.h              # Client headers
        ├── auth_state.h        # Client state variables
        └── main.cpp            # Example client usage
```

## Requirements File

Create `mAuth/backend/mAuthBE/requirements.txt`:

```txt
Flask
flask-cors
bcrypt
```

## Security Notes

- Admin panel is only accessible from localhost for security
- Passwords are hashed using bcrypt
- HWIDs are normalized and case-insensitive
- Sessions expire after 1 hour of inactivity
- Heartbeat required every 30 seconds to keep session alive

## License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**.

You are free to:
- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

Under the following terms:
- Attribution — You must give appropriate credit, provide a link to the license
- NonCommercial — You may not use the material for commercial purposes

For commercial use, please contact the author.

Full license: https://creativecommons.org/licenses/by-nc/4.0/

## Quick Commands Reference

```bash
# Start Flask server (from backend/mAuthBE)
python app.py

# Start Cloudflare tunnel
cloudflared tunnel --url http://localhost:5000

# View database (for debugging)
sqlite3 database.db "SELECT * FROM users;"
sqlite3 database.db "SELECT * FROM sessions;"
sqlite3 database.db "SELECT * FROM licenses;"

# Reset database (delete and restart server)
rm database.db
python app.py
```

## Credits

Created by Ethan - mAuth Authentication System
```

