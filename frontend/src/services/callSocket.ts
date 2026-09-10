import { getApiBaseUrl } from './api';

export interface DetectedSignal {
    signal: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    evidence: string;
}

export interface VoiceAuthenticity {
    is_likely_cloned?: boolean | null;
    confidence?: number | null;
}

export interface CallAnalysisResult {
    event?: 'phone_connected' | 'call_analysis' | 'phone_disconnected';
    call_id?: string;
    latest_chunk?: string;
    transcript?: string;
    risk_score?: number;
    verdict?: 'SAFE' | 'WARNING' | 'SCAM' | 'DANGER';
    alert?: boolean;
    explanation?: string;
    scam_category?: string;
    hits?: string[];
    detected_signals?: DetectedSignal[];
    voice_authenticity?: VoiceAuthenticity;
    connected_at?: string;
    phone_status?: 'ACTIVE' | 'DISCONNECTED';
}

export type MessageCallback = (data: CallAnalysisResult) => void;

export const getWsBaseUrl = (): string => {
    const envWsUrl = import.meta.env?.VITE_WS_BASE_URL;
    if (envWsUrl && typeof envWsUrl === 'string' && envWsUrl.trim() !== '') {
        return envWsUrl.trim().replace(/\/$/, '');
    }
    const httpBaseUrl = getApiBaseUrl();
    return httpBaseUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
};

export class CallSocketService {
    private socket: WebSocket | null = null;
    private onMessageCallback: MessageCallback | null = null;

    connect(callId: string, onMessage: MessageCallback) {
        // Close existing connection if open
        if (this.socket) {
            this.disconnect();
        }

        this.onMessageCallback = onMessage;
        const wsBaseUrl = getWsBaseUrl();
        const wsUrl = `${wsBaseUrl}/calls/ws/${callId}`;
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log(`[CallSocketService] Connected to ${wsUrl}`);
        };

        this.socket.onmessage = (event) => {
            try {
                const data: CallAnalysisResult = JSON.parse(event.data);
                if (this.onMessageCallback) {
                    this.onMessageCallback(data);
                }
            } catch (err) {
                console.error('[CallSocketService] Failed to parse WebSocket JSON payload:', err);
            }
        };

        this.socket.onerror = (error) => {
            console.error('[CallSocketService] WebSocket error:', error);
        };

        this.socket.onclose = () => {
            console.log('[CallSocketService] WebSocket connection closed.');
        };
    }

    sendAudioChunk(audioBlob: Blob) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(audioBlob);
        } else {
            console.warn('[CallSocketService] Socket is not open. Unable to send audio chunk.');
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.onMessageCallback = null;
    }
}

export const callSocketService = new CallSocketService();
