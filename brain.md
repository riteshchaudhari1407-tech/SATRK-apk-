# SATRK Second Brain: Core Architecture & Constraints

**Target Audience:** Future AI Agents, Core Contributors, Maintainers.
**Purpose:** A strict technical context guide, logic map, and architectural ledger. This is *not* an end-user guide. Read this document to understand the "Why" and "How" before modifying core logic.

---

## 1. System Core

SATRK is an ultra-low latency, hybrid fraud detection platform designed to intercept real-time telecommunication and digital threats (Digital Arrest, Phishing, Deepfake audio). 

The platform operates on a decentralized processing model:
- **Frontend/Mobile**: Dumb clients handling only raw media extraction (PCM audio streaming, image capture, WebSocket forwarding).
- **Backend (FastAPI)**: Heavy-lifting orchestrator acting as an async event loop, piping data concurrently through various internal and external AI engines, resolving threats via a deterministic Ensemble Risk Engine.

---

## 2. Architecture & Logic Flow

The threat detection pipeline is compartmentalized into discrete layers to ensure speed and fallback resilience.

### Layer A: Semantic AI (MiniLM / SentenceTransformers)
- **Role**: High-speed, local embedding-based context understanding.
- **Mechanism**: Converts text/transcripts into vector embeddings and calculates cosine similarity against known scam typologies. 
- **Characteristics**: Fast, deterministic, and acts as a safety net if external LLMs fail.

### Layer B: Groq LLM Reasoning (`whisper-large-v3` & `llama`)
- **Role**: Deep contextual analysis and reasoning.
- **Mechanism**: Analyzes complete transcripts using strict prompt engineering to identify complex extortion psychology (e.g., isolation tactics, authority impersonation).
- **Characteristics**: Heavily weighted but network-dependent. Wrapped in strict async timeouts (e.g., `MAX_AI_TIMEOUT = 3.5s`) to prevent blocking the WebSocket event loop.

### Layer C: Regex/Technical Signals & Financial Scanner
- **Role**: Deterministic pattern matching.
- **Mechanism**: Scans for exact structural formats (e.g., IFSC, NPCI UPI IDs, PAN Cards, 10-digit mobiles, 9-18 digit bank accounts with proximity context words).
- **Characteristics**: Supports context disambiguation (upgrading a string of numbers to a "Bank Account" only if words like "account" or "transfer" appear nearby).

### Ensemble Risk Engine
The final risk score is **not** randomly generated. It is calculated via a mathematically sound, weighted ensemble approach:
- **Base Scoring (Analysis Service)**: Weights are statically defined (e.g., Groq `0.90`, Semantic `0.05`, Technical `0.05`). 
- **Dynamic Renormalization**: If Groq timeouts or fails, its weight is dropped, and the remaining engines are renormalized to sum to `1.0`. The engine evaluates what actually ran.
- **Additive Boosts**: Absolute evidence (like deepfake voices or known scam registry hits) applies additive risk boosts on top of the base score.

---

## 3. Data & State Management

**Philosophy**: Avoid heavy relational databases (PostgreSQL/MySQL) during the hackathon phase to minimize local setup friction, eliminate connection pooling bottlenecks, and keep the application strictly memory-bound.

**Scam Registry Persistence (`data/scam_registry.json`)**:
- Uses local flat-file JSON for crowdsourced reports.
- **Concurrency Safety**: Implements strict atomic writes via Python's `tempfile` and `os.replace`. This prevents JSON corruption when multiple WebSocket instances or API calls attempt to write to the registry simultaneously.
- State is primarily handled in memory (e.g., `active_phone_calls` dicts) and broadcasted dynamically via WebSockets, completely negating the need for a persistent database for real-time operation.

---

## 4. Engineering Principles & Constraints (CRITICAL)

Agents and developers MUST adhere to the following non-negotiable rules:

### A. The 'Zero Fabrication' Principle
- **Rule**: NEVER hallucinate risk scores, verdicts, or explanations. 
- **Action**: If an AI module is offline, clearly state it in the `engines_unavailable` array and use the fallback deterministic rules. Never pretend an unavailable engine analyzed the text.
- **Action**: Renormalize weights accurately. Do not invent a fake 0-100 score.

### B. Hard-Capped Scoring Limits
To prevent runaway scoring and maintain nuanced threat evaluation, deterministic layers are strictly capped:
- **Financial Scanner (Layer C)**: Maximum risk contribution is hard-capped at **`40`**.
- **Crowdsourced Registry**: Maximum risk boost is hard-capped at **`50`** (e.g., 10 points per report, maxing out at 5 reports).
- **Voice Cloning**: Deepfake detection appends a flat **`+10`** boost and forces the `possible_voice_clone` tag.

### C. Async Non-Blocking Main Thread
- **Rule**: All external HTTP calls (Groq, Resemble AI, Google Safe Browsing) MUST use `httpx.AsyncClient` or async SDKs.
- **Rule**: Concurrent tasks MUST be grouped using `asyncio.gather(..., return_exceptions=True)` and wrapped with strict `asyncio.wait_for` timeouts to protect the main WebSocket stream.

---

## 5. Network & Client-Server Quirks

Due to the nature of local cross-device streaming (Android -> PC), network configuration is the highest point of failure:

- **Host Binding**: The backend FastAPI server MUST run on `--host 0.0.0.0` to expose the port to the Local Area Network (LAN).
- **Subnet Matching**: The Android device and backend PC MUST be on the same subnet (connected to the same Wi-Fi or via Mobile Hotspot).
- **Client Isolation**: Public or university Wi-Fi networks often have "AP Isolation" or "Client Isolation" enabled, which blocks P2P traffic. In these cases, a Mobile Hotspot must be used.
- **Android IP Sync**: The IPv4 address of the backend machine MUST precisely match the `DEFAULT_SERVER_IP` in `CallWebSocketClient.kt` or be manually inputted in the Android app UI prior to triggering a call.

---

## 6. Feature Roadmap & Technical Debt

**Pending Architecture Enhancements (Future Agents):**

- [ ] **Dynamic IP Discovery**: Build a dynamic IP input screen on the mobile frontend (or use mDNS/ZeroConf for automatic local discovery) to eliminate manual IPv4 entry and recompilation.
- [ ] **Streaming STT Refactoring**: Transition from chunk-based Whisper STT (Groq) to a true real-time streaming WebSocket STT (like Deepgram) to reduce the 2.5s-5s chunking latency.
- [ ] **SQLite Migration**: Transition the local JSON registry to SQLite using `aiosqlite` if concurrency scaling requires row-level locking rather than full-file atomic replacements.
- [ ] **Persistent User Sessions**: Add JWT authentication and persistent user configurations for the frontend dashboard once a real database is integrated.
