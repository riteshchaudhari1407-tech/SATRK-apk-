# SATRK

**Satrk: One step ahead of every scam.**

*Built for Smart India Hackathon (SIH) 2026*

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React_18_|_TypeScript-61DAFB?style=flat-square&logo=react)](https://reactjs.org/)
[![Android](https://img.shields.io/badge/Mobile-Android_|_Kotlin-3DDC84?style=flat-square&logo=android)](https://developer.android.com/)
[![Groq](https://img.shields.io/badge/AI_Engine-Groq_Llama_|_Whisper-f46800?style=flat-square)](https://groq.com/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.style=flat-square)](LICENSE)

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Solution Overview](#solution-overview)
- [System Architecture](#system-architecture)
- [Low-Latency Optimizations](#low-latency-optimizations)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Local Setup & Deployment](#local-setup--deployment)
- [Environment Configuration](#environment-configuration)
- [Challenges Overcome](#challenges-overcome)
- [License](#license)

---

## Problem Statement

Telecommunication and online financial scams in India have evolved from simple phishing calls to orchestrated multi-stage extortion ops. Scammers frequently operate in regional Indian languages (Hindi, Marathi, Gujarati, etc.) using high-pressure tactics, including:

1. **Digital Arrest Simulation**: Impersonating Police, CBI, Supreme Court, or Cyber Cell officers to force victims onto video calls and isolate them.
2. **Regulatory Threats**: Simulating TRAI SIM disconnections, customs parcel seizures (purported drug contraband), or immediate bank account freezes.
3. **AI Voice Cloning**: Synthesizing deepfake audio of relatives or authority figures to demand immediate ransom or transfer fees.

Victims typically lack real-time automated assistance during active phone calls, leading to financial loss before an incident is reported.

---

## Solution Overview

**SATRK** is an end-to-end cyber defense system that intercepts active call audio, streams raw chunks to a high-throughput backend, translates multi-lingual Indian speech into English, and performs concurrent contextual fraud and deepfake voice detection in **under 500 milliseconds**.

### Core Capabilities
- **Automated Call Lifecycle Triggering**: Monitors phone calls via Android `TelephonyManager` state (`CALL_STATE_OFFHOOK`) without record-on-idle battery drain.
- **Multi-lingual Real-time Translation**: Auto-detects spoken Indian languages (Hindi, Marathi, Gujarati) and translates audio streams into English using Groq Whisper.
- **Context-Aware Fraud Reasoning**: Evaluates live transcripts against Indian scam typologies using low-latency LLM inference and a fast rule engine.
- **Deepfake Voice Verification**: Runs parallel acoustic checks to detect voice cloning during high-risk calls.
- **Zero-Trust Link Scanner**: Verifies URLs extracted from SMS or chat messages against Google Safe Browsing API v4.

---

## System Architecture

```
                                  SATRK CORE PIPELINE
                                  
 [ Android App ] --- (PCM Audio / WS) ---> [ FastAPI WebSockets Router ]
   - TelephonyManager                        |
   - AudioRecord Fallback                    +---> [ STTService (AsyncGroq Whisper) ]
                                             |       - RMS Energy Noise Filter
                                             |       - Indian Lang -> English Translation
                                             |
                                             +---> [ Rule Engine ] (Instant Regex Match)
                                             |
                                             +---> [ asyncio.gather (Parallel Execution) ]
                                                     |
                                                     +-- (3.5s Timeout) --> [ Groq LLM Engine ]
                                                     |                      - Indian Scam Prompt
                                                     |                      - Risk Score & Verdict
                                                     |
                                                     +-- (3.5s Timeout) --> [ Resemble AI API ]
                                                                            - Voice Clone Detection
                                             |
                                             v
 [ Dashboard UI ] <--- (Broadcast JSON) ---- [ Unified Event Stream ]
```

---

## Low-Latency Optimizations

To keep the WebSocket processing cycle below the live audio streaming chunk interval (2.5–5.0 seconds), SATRK uses the following backend optimizations:

1. **Non-Blocking Async Pipeline**: All external AI calls (Whisper STT, Groq LLM, Resemble AI) utilize `AsyncGroq` and `httpx.AsyncClient` within an `asyncio` event loop.
2. **Concurrent Task Gathering**: Groq LLM contextual analysis and Resemble AI voice clone detection execute concurrently via `asyncio.gather(..., return_exceptions=True)`.
3. **Strict Execution Timeouts**: Both external AI requests are wrapped with `asyncio.wait_for(..., timeout=3.5)`. If an upstream API stalls, the pipeline gracefully degrades using the Rule Engine output without dropping WebSocket frames.
4. **Energy Energy Pre-Filtering**: Raw 16-bit PCM buffers are pre-evaluated for Root Mean Square (RMS) energy. Silent or background noise chunks below `RMS < 10.0` are dropped before calling Whisper API endpoints.

---

## Key Features

### 1. Active Call Interception (`android/app/src/main/java/com/satrk/app/service/CallMonitorService.kt`)
- Listens to `TelephonyManager` call state transitions.
- Activates `AudioRecord` streaming only when `CALL_STATE_OFFHOOK` is detected; automatically disconnects on `CALL_STATE_IDLE`.
- Implements active silence detection fallback: if primary `MediaRecorder.AudioSource.VOICE_CALL` returns zeroed buffers, it dynamically re-initializes to `MediaRecorder.AudioSource.MIC` or `VOICE_COMMUNICATION`.

### 2. Multi-lingual Speech Translation (`backend/app/services/stt_service.py`)
- Leverages `whisper-large-v3` via Groq's `translations` endpoint (`temperature=0.0`).
- Translates Hindi, Marathi, Gujarati, and Hinglish speech directly into structured English text.
- Applies regex post-filtering to prune common Whisper hallucination artifacts (`"you you you"`, subtitle noise).

### 3. Contextual Scam Engine (`backend/app/services/groq_service.py`)
- Runs prompt-engineered LLM reasoning tailored specifically for Indian fraud categories:
  - Digital Arrest & Virtual Isolation
  - CBI / Police / Cyber Cell / Supreme Court Impersonation
  - TRAI SIM Disconnection Notices
  - Customs & FedEx Drug Seizure Threats
  - Impending Bank Account / UPI / KYC Blockades
- Returns a structured JSON payload containing a definitive verdict (`SAFE`, `WARNING`, `SCAM`), percentage risk score, and bulleted defensive advice.

### 4. Voice Authenticity Detection (`backend/app/services/voice_authenticity_service.py`)
- Triggers acoustic analysis when call risk crosses `THREAT_THRESHOLD >= 50.0`.
- Sends audio buffers to Resemble AI detection endpoint (`https://app.resemble.ai/api/v2/detect`).
- Appends `possible_voice_clone` signals and boosts overall risk score by +10% if deepfake cloning is detected.

### 5. Malicious Link Scanner (`backend/app/services/analysis_service.py` & `routers/analysis.py`)
- Interrogates suspicious URLs against Google Safe Browsing API v4.
- Evaluates URLs against `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, and `POTENTIALLY_HARMFUL_APPLICATION` threat databases.

### 6. Adaptive Feedback Loop (`routers/analysis.py` & `UnifiedCallProtection.tsx`)
- Provides human-in-the-loop feedback actions (`Yes / No` correct alert buttons on high-risk alerts).
- Logs feedback payloads to fine-tune rule weights and prompt calibrations over time.

---

## Tech Stack

| Domain | Technologies |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons, WebSocket Web API |
| **Backend** | Python 3.12, FastAPI, Uvicorn, Pydantic v2, `httpx`, Asyncio, SentenceTransformers |
| **Mobile (Android)** | Kotlin, Android SDK (API 26+), `TelephonyManager`, `AudioRecord`, OkHttp WebSockets |
| **AI Services & APIs** | AsyncGroq SDK (`whisper-large-v3`, `openai/gpt-oss-20b`), Resemble AI API, Google Safe Browsing API v4 |

---

## Repository Structure

```
SATRK-apk-/
├── android/                        # Native Android Kotlin Application
│   ├── app/src/main/java/com/satrk/app/
│   │   ├── MainActivity.kt         # Mobile UI Controls & Permission Handling
│   │   ├── service/
│   │   │   └── CallMonitorService.kt # TelephonyManager & AudioRecord Service
│   │   └── network/
│   │       └── CallWebSocketClient.kt # Async OkHttp WebSocket Client
│   └── app/src/main/res/           # Android Views, Styles & XML Configs
│
├── backend/                        # FastAPI High-Throughput Server
│   ├── app/
│   │   ├── main.py                 # FastAPI Gateway & CORS Configuration
│   │   ├── config.py               # Pydantic Settings & Environment Variables
│   │   ├── container.py            # Singleton Dependency Injection Container
│   │   ├── routers/                # API & WebSocket Route Handlers
│   │   │   ├── calls.py            # Live Call WS & Audio Upload Endpoints
│   │   │   ├── analysis.py         # Text/Image Analysis & Link Scanner Endpoints
│   │   │   └── scans.py            # Persistent Scan Logging Router
│   │   └── services/               # Core AI & Rule Engine Business Logic
│   │       ├── stt_service.py      # AsyncGroq Whisper Speech-to-Text & Translation
│   │       ├── groq_service.py     # LLM Scam Analysis & Structured Reasoning
│   │       ├── rule_engine_service.py # Deterministic Keyword & Regex Engine
│   │       ├── voice_authenticity_service.py # Resemble AI Deepfake Detection
│   │       ├── semantic_service.py # Embedding Vector Matcher (SentenceTransformers)
│   │       └── analysis_service.py # Aggregated Pipeline Coordinator
│   └── requirements.txt            # Backend Python Dependencies
│
├── frontend/                       # React + Vite Web Application
│   ├── src/
│   │   ├── App.tsx                 # Navigation & View Router Layout
│   │   ├── components/             # Cyber Shield & Threat Scanner UI Components
│   │   │   ├── UnifiedCallProtection.tsx # Real-Time Audio Shield & Live Call Dashboard
│   │   │   ├── ThreatScanner.tsx   # Text & Link Threat Scanner Component
│   │   │   └── CommandCenter.tsx   # System Metrics & Live Threat Log View
│   │   └── services/               # Axios API Client & WebSocket Service
│   │       ├── api.ts              # REST API Service Calls
│   │       └── callSocket.ts       # Browser WebSocket Client Wrapper
│   └── package.json
│
├── .env.example                    # Sample Environment Template
└── README.md                       # Documentation
```

---

## Local Setup & Deployment

### Prerequisites
- **Node.js**: v18.x or higher
- **Python**: v3.11 or v3.12
- **Android Studio**: Jellyfish | 2024.1.1+ (for Android APK compilation)
- **Groq API Key**: Obtainable from [console.groq.com](https://console.groq.com/)

---

### 1. Environment Setup

Create a `.env` file in the root workspace directory or inside `backend/`:

```bash
cp .env.example .env
```

Fill in required credentials (see [Environment Configuration](#environment-configuration)).

---

### 2. Backend Setup (FastAPI)

```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start Uvicorn development server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Backend server will run at `http://localhost:8000`. Interactive OpenAPI documentation will be accessible at `http://localhost:8000/docs`.

---

### 3. Frontend Setup (React + Vite)

```bash
# Navigate to frontend directory
cd frontend

# Install Node modules
npm install

# Start Vite dev server
npm run dev
```

Frontend application will open at `http://localhost:5173`.

---

### 4. Native Android App Build

```bash
# Navigate to android directory
cd android

# Grant execution permissions (Linux/macOS)
chmod +x gradlew

# Build Debug APK using Gradle Wrapper
./gradlew assembleDebug

# Output APK path: android/app/build/outputs/apk/debug/app-debug.apk
```

To install on a connected Android test device via ADB:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Environment Configuration

The application reads configuration parameters from `.env`:

```env
# --- Groq AI API Key (Required for STT Translation & LLM Threat Analysis) ---
GROQ_API_KEY=gsk_your_groq_api_key_here

# --- Google Safe Browsing API Key (Optional: Required for Link Scanner) ---
GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy_your_google_safe_browsing_key_here

# --- Resemble AI API Key (Optional: Required for Deepfake Detection) ---
RESEMBLE_API_KEY=your_resemble_api_key_here

# --- Server & CORS Config ---
PORT=8000
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

---

## Challenges Overcome

### 1. Hardware-Specific Call Audio Inaccessibility on Android
- **Challenge**: Newer Android versions restrict access to `AudioSource.VOICE_CALL` for non-system apps, causing `AudioRecord` to read empty/zeroed buffers.
- **Solution**: Developed an dynamic fallback engine inside `CallMonitorService.kt` that measures incoming PCM buffer energy. If consecutive silent frames are read from `VOICE_CALL`, it automatically re-initializes `AudioRecord` using `AudioSource.MIC` or `VOICE_COMMUNICATION`.

### 2. Preventing Live Stream Stalls During External API Spikes
- **Challenge**: Network latency from sequential LLM and Voice Auth HTTP calls blocked FastAPI's WebSocket event loop, causing live streams to drop frames.
- **Solution**: Re-architected the analysis pipeline using `AsyncGroq` and `asyncio.gather()` with a hard `3.5s` `asyncio.wait_for()` timeout, ensuring WebSocket message delivery within sub-second thresholds.

### 3. Whisper Hallucination Loops on Dead Air Audio
- **Challenge**: Low-energy ambient audio during call pauses led Whisper STT models to output repetitive artifacts (e.g., `"you you you"` or `"thank you for watching"`).
- **Solution**: Implemented a two-stage pre/post-filter: an RMS energy threshold check (`is_pcm_silent`) before sending audio, followed by regex pattern matching and token-repetition ratio evaluation (`filter_hallucinations`) to discard unverified outputs.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.

---

*SATRK — Developed for Smart India Hackathon (SIH) 2026.*
