# SATRK — Teammate Local Setup Guide

Welcome to **SATRK**! This guide contains step-by-step instructions for teammates setting up the project locally for the first time. Follow these steps sequentially to run the backend, frontend, and Android app on your machine.

---

## 📋 Prerequisites Checklist

Ensure your local machine has the following tools installed:
- **Git**: [git-scm.com](https://git-scm.com/)
- **Python**: 3.11 or 3.12 ([python.org](https://www.python.org/))
- **Node.js**: 18.x or higher ([nodejs.org](https://nodejs.org/))
- **Android Studio** (optional, only if building the Android app from source): [developer.android.com/studio](https://developer.android.com/studio)

---

## 1. 🐙 Clone Repository & Fetch Latest Code

Open your terminal or PowerShell and run:

```bash
# Clone the repository
git clone https://github.com/riteshchaudhari1407-tech/SATRK-apk-.git

# Navigate into the project folder
cd SATRK-apk-

# Pull the latest code on main branch
git pull origin main
```

---

## 2. 🔑 Environment Configuration (.env)

Create a `.env` file in the root workspace directory (`SATRK-apk-/.env`) and inside `backend/` (`SATRK-apk-/backend/.env`).

### Copy Template:
```bash
# Create .env from template
cp .env.example .env
cp .env.example backend/.env
```

### Fill in Credentials in `.env`:
```env
# ==========================================
# SATRK ENVIRONMENT CONFIGURATION
# ==========================================

# --- Groq AI API Key (REQUIRED for STT Translation & LLM Threat Analysis) ---
# Get your free key at: https://console.groq.com/
GROQ_API_KEY=gsk_your_groq_api_key_here

# --- Google Safe Browsing API Key (Optional: Required for Link Scanner) ---
GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy_your_google_safe_browsing_key_here

# --- Resemble AI API Key (Optional: Required for Voice Clone Detection) ---
RESEMBLE_API_KEY=your_resemble_api_key_here

# --- Backend Server Port & CORS Configuration ---
PORT=8000
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000
```

> 💡 **Note**: Ask the team lead if you need access to the shared development Groq API key!

---

## 3. 🐍 Backend Setup (FastAPI Server)

```bash
# Navigate to backend directory
cd backend

# Create Python Virtual Environment
python -m venv venv

# Activate Virtual Environment
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# Upgrade pip & install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Start the FastAPI Uvicorn Server (Accessible to local network devices)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

When successfully started, you will see:
```text
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Services ready — groq_configured=True semantic_available=True ...
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

Interactive API documentation will be available in your browser at: [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 4. ⚛️ Frontend Setup (React + Vite Web App)

Open a **new terminal tab/window**:

```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```

The Web Dashboard will launch at: [http://localhost:5173](http://localhost:5173).

---

## 5. 📱 Android App Setup & Installation

### Option A: Use the Pre-Built Debug APK (Recommended)
You do **not** need Android Studio to test the app. The repository includes a pre-built APK file located at:

```
android/app/build/outputs/apk/debug/app-debug.apk
```

#### How to Install on Your Android Device:
1. **Transfer the APK**: Copy `app-debug.apk` to your phone via USB cable, Google Drive, or messaging apps.
2. **Enable Unknown Sources**: On your Android phone, go to **Settings > Security** (or Privacy) and enable *"Install unknown apps"* for your File Manager/Browser.
3. **Install**: Tap `app-debug.apk` on your phone and press **Install**.

### Option B: Build APK from Source (Android Studio)
If you want to modify Kotlin code or build manually:

```bash
cd android

# Build debug APK
./gradlew assembleDebug

# Install via USB ADB (if phone connected with USB Debugging enabled)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 6. 🌐 Critical Network & WebSocket Configuration

To stream live call audio from your Android phone to your laptop's backend, **both devices must be on the same network**.

### Step 1: Connect to Same Network
Connect your **laptop** and **Android phone** to the **same Wi-Fi network** (or connect your laptop to your phone's Mobile Hotspot).

---

### Step 2: Find Your Laptop's Local IPv4 Address

#### On Windows (PowerShell / Command Prompt):
```powershell
ipconfig
```
Look for `IPv4 Address` under your Wi-Fi adapter (e.g., `192.168.1.15` or `192.168.29.104`).

#### On macOS / Linux:
```bash
ifconfig
# or
ip a
```
Look for `inet` address under `en0` or `wlan0` (e.g., `192.168.1.15`).

---

### Step 3: Configure Mobile App Connection

1. Open the **SATRK** app on your Android phone.
2. In the **Server IP / Host** input field at the top of the app, enter your laptop's local IPv4 address (e.g., `192.168.1.15`).
3. Set Port to `8000`.
4. Tap **"START CALL MONITORING"**.

#### Optional Codebase Default Update:
If you want your local IP to be default when building the Android app, update line 34 in `android/app/src/main/java/com/satrk/app/network/CallWebSocketClient.kt`:

```kotlin
// Replace 192.168.1.15 with your local laptop IPv4 address
const val DEFAULT_SERVER_IP = "YOUR_LAPTOP_IP_HERE"
```

---

## 🚀 Testing the Full Pipeline

1. **Verify Backend**: Ensure Uvicorn is running on `0.0.0.0:8000`.
2. **Open Dashboard**: Open `http://localhost:5173` on your laptop. Select the **"Android Phone"** tab.
3. **Simulate a Call**: On your Android phone, place a phone call or use two phones. Tap **"START CALL MONITORING"** in the SATRK mobile app.
4. **Observe Real-Time Shield**: As speech occurs on the call, observe live English transcripts, percentage risk scores, and deepfake signals appearing on your laptop dashboard in real-time!

---

## ❓ Troubleshooting & Common Issues

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| **Android app shows WebSocket connection error** | Phone and laptop on different Wi-Fi networks OR wrong IP entered. | Connect phone & laptop to same Wi-Fi. Verify IPv4 address using `ipconfig`. Ensure backend is running with `--host 0.0.0.0`. |
| **Backend error: `GROQ_API_KEY not found`** | `.env` file missing or invalid API key. | Ensure `.env` exists in root and `backend/` directory with a valid key from `console.groq.com`. |
| **Frontend shows Network Error on Link Scanner** | Backend server not running or CORS blocked. | Ensure `python -m uvicorn app.main:app` is running on port 8000. |

---

Need help? Contact the repo owner or drop a message in the team group!
