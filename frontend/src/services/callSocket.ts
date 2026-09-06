export interface CallAnalysisResult {
    call_id?: string;
    latest_chunk?: string;
    transcript: string;
    risk_score: number;
    alert: boolean;
    hits?: string[];
}

export type MessageCallback = (data: CallAnalysisResult) => void;

export class CallSocketService {
    private socket: WebSocket | null = null;
    private onMessageCallback: MessageCallback | null = null;

    connect(callId: string, onMessage: MessageCallback) {
        // Close existing connection if open
        if (this.socket) {
            this.disconnect();
        }

        this.onMessageCallback = onMessage;
        const wsUrl = `ws://localhost:8000/calls/ws/${callId}`;
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
