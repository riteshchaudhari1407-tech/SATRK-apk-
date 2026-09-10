import React, { useState, useEffect, useRef } from 'react';
import {
    FiAlertTriangle,
    FiShield,
    FiActivity,
    FiCheckCircle,
    FiRadio,
    FiZap,
    FiSmartphone,
    FiPhoneOff
} from 'react-icons/fi';
import { getWsBaseUrl } from '../services/callSocket';
import type { CallAnalysisResult } from '../services/callSocket';

export const LivePhoneLogs: React.FC = () => {
    // Dashboard ↔ Backend WS status
    const [isDashboardConnected, setIsDashboardConnected] = useState<boolean>(false);

    // Phone ↔ Backend status (set by server events, NOT by local socket state)
    const [phoneStatus, setPhoneStatus] = useState<'IDLE' | 'ACTIVE' | 'DISCONNECTED'>('IDLE');
    const [connectedAt, setConnectedAt] = useState<string>('');

    // Call data
    const [callId, setCallId] = useState<string>('');
    const [transcript, setTranscript] = useState<string>('');
    const [latestChunk, setLatestChunk] = useState<string>('');
    const [riskScore, setRiskScore] = useState<number>(0);
    const [isAlert, setIsAlert] = useState<boolean>(false);
    const [hits, setHits] = useState<string[]>([]);
    const [chunkCount, setChunkCount] = useState<number>(0);

    const socketRef = useRef<WebSocket | null>(null);
    const transcriptEndRef = useRef<HTMLDivElement | null>(null);
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Auto-scroll transcript
    useEffect(() => {
        transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [transcript, latestChunk]);

    // WebSocket lifecycle
    useEffect(() => {
        const connectWs = () => {
            const wsBaseUrl = getWsBaseUrl();
            const wsUrl = `${wsBaseUrl}/calls/ws-frontend`;
            const ws = new WebSocket(wsUrl);
            socketRef.current = ws;

            ws.onopen = () => {
                console.log(`[LivePhoneLogs] Dashboard connected to ${wsUrl}`);
                setIsDashboardConnected(true);
            };

            ws.onmessage = (event) => {
                try {
                    const data: CallAnalysisResult = JSON.parse(event.data);

                    switch (data.event) {
                        case 'phone_connected':
                            setPhoneStatus('ACTIVE');
                            if (data.call_id) setCallId(data.call_id);
                            if (data.connected_at) setConnectedAt(data.connected_at);
                            // Reset analysis state for the new call
                            setTranscript('');
                            setLatestChunk('');
                            setRiskScore(0);
                            setIsAlert(false);
                            setHits([]);
                            setChunkCount(0);
                            break;

                        case 'call_analysis':
                            setPhoneStatus('ACTIVE');
                            if (data.call_id) setCallId(data.call_id);
                            if (data.transcript !== undefined) setTranscript(data.transcript);
                            if (data.latest_chunk !== undefined) setLatestChunk(data.latest_chunk);
                            if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                            if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                            if (data.hits) setHits(data.hits);
                            setChunkCount((prev) => prev + 1);
                            break;

                        case 'phone_disconnected':
                            setPhoneStatus('DISCONNECTED');
                            break;

                        default:
                            // Legacy or untyped payload — treat as analysis
                            if (data.call_id) setCallId(data.call_id);
                            if (data.transcript !== undefined) setTranscript(data.transcript);
                            if (data.latest_chunk !== undefined) setLatestChunk(data.latest_chunk);
                            if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                            if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                            if (data.hits) setHits(data.hits);
                            break;
                    }
                } catch (err) {
                    console.error('[LivePhoneLogs] Failed to parse WS payload:', err);
                }
            };

            ws.onclose = () => {
                console.log('[LivePhoneLogs] Dashboard WS closed — reconnecting in 3s');
                setIsDashboardConnected(false);
                reconnectTimerRef.current = setTimeout(connectWs, 3000);
            };

            ws.onerror = () => {
                ws.close();
            };
        };

        connectWs();

        return () => {
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
            if (socketRef.current) {
                socketRef.current.onclose = null; // prevent auto-reconnect on unmount
                socketRef.current.close();
            }
        };
    }, []);

    // ── helpers ──────────────────────────────────────────────────────
    const getRiskColor = (score: number) => {
        if (score >= 50) return 'text-red-400 border-red-500/50 bg-red-500/10';
        if (score >= 30) return 'text-amber-400 border-amber-500/50 bg-amber-500/10';
        return 'text-emerald-400 border-emerald-500/50 bg-emerald-500/10';
    };

    const getProgressBg = (score: number) => {
        if (score >= 50) return 'bg-gradient-to-r from-amber-500 to-red-500';
        if (score >= 30) return 'bg-gradient-to-r from-emerald-500 to-amber-500';
        return 'bg-emerald-400';
    };

    const phoneIsLive = phoneStatus === 'ACTIVE';

    // ── phone status badge ──────────────────────────────────────────
    const phoneBadge = () => {
        if (phoneStatus === 'ACTIVE') {
            return (
                <div className="flex items-center gap-3 rounded-2xl px-6 py-4 text-xs font-black uppercase tracking-wider bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    <span className="relative flex h-3 w-3">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500" />
                    </span>
                    Phone Connected — LIVE
                </div>
            );
        }
        if (phoneStatus === 'DISCONNECTED') {
            return (
                <div className="flex items-center gap-3 rounded-2xl px-6 py-4 text-xs font-black uppercase tracking-wider bg-amber-500/20 text-amber-400 border border-amber-500/30">
                    <FiPhoneOff className="text-lg" />
                    Phone Disconnected
                </div>
            );
        }
        return (
            <div className="flex items-center gap-3 rounded-2xl px-6 py-4 text-xs font-black uppercase tracking-wider bg-[#1d312d]/50 text-[#82938e] border border-[#1d312d]">
                <FiSmartphone className="text-lg" />
                Waiting for Phone...
            </div>
        );
    };

    // ── render ───────────────────────────────────────────────────────
    return (
        <div className="w-full space-y-6">
            {/* TOP HEADER */}
            <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-2xl shadow-black/30">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                        <div className="flex items-center gap-2">
                            <span className={`h-2.5 w-2.5 rounded-full ${isDashboardConnected ? 'bg-emerald-400 animate-ping' : 'bg-red-500'}`} />
                            <span className="font-mono text-[10px] font-bold tracking-[0.2em] text-emerald-400 uppercase">
                                {isDashboardConnected ? 'DASHBOARD STREAM CONNECTED' : 'DASHBOARD STREAM OFFLINE'}
                            </span>
                        </div>
                        <h2 className="mt-2 text-2xl font-black text-[#e8eeea] tracking-tight">
                            Live Mobile Call Monitor
                        </h2>
                        <p className="mt-1 text-xs text-[#82938e]">
                            Real-time visibility into active phone calls from the Satrk Android App.
                        </p>
                    </div>

                    <div className="flex items-center gap-3">
                        {phoneBadge()}
                    </div>
                </div>
            </div>

            {/* CRITICAL ALERT BANNER */}
            {isAlert && (
                <div className="relative overflow-hidden rounded-3xl border-2 border-red-500 bg-red-950/40 p-6 shadow-2xl shadow-red-500/20 backdrop-blur-xl animate-pulse">
                    <div className="absolute top-0 right-0 p-8 opacity-10">
                        <FiAlertTriangle className="text-9xl text-red-500" />
                    </div>
                    <div className="relative z-10 flex items-start gap-4">
                        <div className="rounded-2xl bg-red-500 p-3 text-black">
                            <FiAlertTriangle className="text-3xl animate-bounce" />
                        </div>
                        <div>
                            <span className="font-mono text-[10px] font-bold tracking-[0.25em] text-red-400 uppercase">
                                CRITICAL SCAM THREAT DETECTED ON MOBILE
                            </span>
                            <h3 className="mt-1 text-xl font-black text-white">
                                HIGH RISK COERCION / IMPERSONATION PATTERN DETECTED
                            </h3>
                            <p className="mt-2 text-xs leading-relaxed text-red-200/90 max-w-2xl">
                                The caller exhibits classic signs of digital arrest or authority impersonation.
                            </p>
                            {hits.length > 0 && (
                                <div className="mt-3 flex flex-wrap gap-2">
                                    {hits.map((category, idx) => (
                                        <span
                                            key={idx}
                                            className="rounded-lg bg-red-500/20 border border-red-500/40 px-2.5 py-1 font-mono text-[10px] font-bold text-red-300"
                                        >
                                            ⚠️ {category}
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* MAIN GRID */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* LEFT — TRANSCRIPT */}
                <div className="lg:col-span-2 rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl flex flex-col justify-between min-h-[420px]">
                    <div>
                        <div className="flex items-center justify-between border-b border-[#1d312d] pb-4 mb-4">
                            <div className="flex items-center gap-2">
                                <FiRadio className={`text-lg ${phoneIsLive ? 'text-emerald-400 animate-pulse' : 'text-[#53645e]'}`} />
                                <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                    Live Audio Stream & Speech Transcript
                                </h3>
                            </div>
                            {phoneIsLive && chunkCount > 0 && (
                                <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 font-mono text-[10px] font-bold text-emerald-400 flex items-center gap-1.5">
                                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
                                    {chunkCount} CHUNKS PROCESSED
                                </span>
                            )}
                        </div>

                        <div className="rounded-2xl border border-[#1a2b27] bg-[#050c0a] p-5 h-[280px] overflow-y-auto font-sans text-sm leading-relaxed text-[#c0cfc9] space-y-3 shadow-inner scrollbar-thin">
                            {transcript ? (
                                <p className="whitespace-pre-wrap">{transcript}</p>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-center text-[#53645e]">
                                    {phoneIsLive ? (
                                        <>
                                            <FiActivity className="text-3xl mb-2 animate-spin" />
                                            <p className="text-xs">Phone connected — listening for speech...</p>
                                        </>
                                    ) : (
                                        <>
                                            <FiActivity className="text-3xl mb-2 animate-pulse" />
                                            <p className="text-xs">
                                                {phoneStatus === 'DISCONNECTED'
                                                    ? 'Phone disconnected. Waiting for reconnection...'
                                                    : 'Waiting for an active call from the Android App...'}
                                            </p>
                                        </>
                                    )}
                                </div>
                            )}
                            <div ref={transcriptEndRef} />
                        </div>
                    </div>

                    {latestChunk && (
                        <div className="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 flex items-center gap-3 text-xs text-emerald-300">
                            <FiZap className="text-emerald-400 shrink-0" />
                            <span className="font-semibold text-emerald-400 shrink-0">Latest Chunk:</span>
                            <span className="truncate text-[#a2b5ae]">"{latestChunk}"</span>
                        </div>
                    )}
                </div>

                {/* RIGHT — RISK GAUGE & METADATA */}
                <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl flex flex-col justify-between">
                    <div>
                        <div className="flex items-center gap-2 border-b border-[#1d312d] pb-4 mb-5">
                            <FiShield className="text-lg text-emerald-400" />
                            <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                Real-Time Risk Score
                            </h3>
                        </div>

                        <div className="text-center py-4">
                            <div className={`inline-flex flex-col items-center justify-center w-36 h-36 rounded-full border-4 shadow-2xl transition-all duration-500 ${getRiskColor(riskScore)}`}>
                                <span className="text-4xl font-black tracking-tight">
                                    {Math.round(riskScore)}%
                                </span>
                                <span className="text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">
                                    {riskScore >= 50 ? 'DANGER' : riskScore >= 30 ? 'MEDIUM RISK' : 'SAFE / LOW'}
                                </span>
                            </div>

                            <div className="mt-6 w-full bg-[#050c0a] rounded-full h-3 p-0.5 border border-[#1d312d] overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all duration-500 ${getProgressBg(riskScore)}`}
                                    style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
                                />
                            </div>
                        </div>
                    </div>

                    {/* METADATA */}
                    <div className="mt-6 space-y-3 border-t border-[#1d312d] pt-5">
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Phone Status</span>
                            <span className={`font-mono font-bold flex items-center gap-1.5 ${phoneIsLive ? 'text-emerald-400' : phoneStatus === 'DISCONNECTED' ? 'text-amber-400' : 'text-[#53645e]'}`}>
                                {phoneIsLive && <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />}
                                {phoneIsLive ? 'ACTIVE' : phoneStatus === 'DISCONNECTED' ? 'DISCONNECTED' : 'IDLE'}
                            </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Call ID</span>
                            <span className="font-mono text-[#e8eeea] font-semibold truncate max-w-[180px]">{callId || '—'}</span>
                        </div>
                        {connectedAt && (
                            <div className="flex items-center justify-between text-xs">
                                <span className="text-[#82938e]">Connected Since</span>
                                <span className="font-mono text-[#e8eeea] font-semibold">
                                    {new Date(connectedAt).toLocaleTimeString()}
                                </span>
                            </div>
                        )}
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Categories Flagged</span>
                            <span className="font-mono text-emerald-400 font-bold">{hits.length}</span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Chunks Analyzed</span>
                            <span className="font-mono text-emerald-400 font-bold">{chunkCount}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};
