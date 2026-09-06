# SATRK (SIH 2026) — Cyber Threat Intelligence & Live Scam Shield

> **One Step Ahead of Every Scam** — AI-Powered Real-Time Detection Against Digital Arrest, Authority Impersonation, and Social Engineering Frauds.

---

## 🛡️ Overview

**SATRK** is a comprehensive hybrid AI cyber-defense platform designed for **Smart India Hackathon (SIH) 2026** to protect citizens against rapidly rising **Digital Arrest**, **CBI / Police / Customs / ED Impersonation**, and **Financial Phishing** scams across India.

The platform provides multi-layered threat detection across Web and Native Mobile platforms:
1. **Live Call Cyber Shield**: Live audio streaming via WebSockets with real-time Speech-to-Text (STT), deterministic threat category rule matching, and LLM validation.
2. **AI Threat Scanner**: Multilingual text message & screenshot OCR analysis (Hindi, Marathi, English) with instant risk scoring.
3. **Android Native Client**: Kotlin-based foreground service using `AudioRecord` (16kHz PCM) and OkHttp WebSockets for background live call monitoring.
4. **Hybrid AI Engine**: Layered combination of deterministic keyword rules, sentence-embedding semantic analysis, and Groq LLM deep reasoning.

---

## 🏗️ System Architecture

```
                               ┌─────────────────────────────┐
                               │  Frontend (React / Vite)    │
                               │  Android Client (Kotlin)    │
                               └──────────────┬──────────────┘
                                              │ (WebSocket / HTTP)
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SATRK BACKEND                                        │
│                                                                                        │
│  ┌───────────────────────┐   ┌────────────────────────┐   ┌─────────────────────────┐  │
│  │   Phase 1: STT        │   │  Phase 2: Deterministic│   │  Phase 3: Deep AI       │  │
│  │   Groq Whisper        ├──►│  Rule Engine Service   ├──►│  Groq LLM Analysis      │  │
│  │   Auto WAV/WebM/PCM   │   │  Linguistic & Category │   │  Threat Explainability  │  │
│  └───────────────────────┘   └────────────────────────┘   └─────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

- 🎙️ **Real-Time Live Call Protection**: Streams live microphone audio chunks every 2.5s to FastAPI via WebSockets (`/calls/ws/{call_id}`).
- ⚠️ **Instant Warning System**: Dynamic 0–100% Risk Gauge & glowing threat warning banner when risk score crosses threshold (>= 50%).
- 📱 **Android Native Background Service**: Foreground service keeping audio recording active during ongoing phone calls with persistent alert notifications.
- 🌐 **Multilingual & Context-Aware**: Analyzes Hindi, Marathi, and English legal threat keywords directly without translation loss.
- 📄 **I4C Cyber Crime Reporting & PDF Export**: Instant official report generation and downloadable threat intelligence summary reports.

---

## 💻 Tech Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, WebSockets, Groq API (Whisper-large-v3, LLM), Sentence Transformers.
- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, Feather Icons, Recharts, jsPDF.
- **Android**: Kotlin, OkHttp WebSockets, `AudioRecord` API, Android Foreground Service.

---

## ⚡ Quick Start

### 1. Backend Setup
```bash
cd backend
# Create and activate virtual environment
python -m venv venv
# Windows: venv\Scripts\activate

pip install -r requirements.txt
py -m uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### 3. Android Native App Setup
1. Open the `android/` directory in Android Studio.
2. Sync Gradle dependencies.
3. Build and deploy to an Android device or emulator (`DEFAULT_SERVER_IP` is configured to your host IP `10.57.107.249`).

---

## 📝 License
Developed for Smart India Hackathon (SIH) 2026. All rights reserved.
