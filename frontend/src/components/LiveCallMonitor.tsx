import React, { useState, useRef, useEffect } from 'react';
import {
    FiMic,
    FiMicOff,
    FiAlertTriangle,
    FiShield,
    FiActivity,
    FiCheckCircle,
    FiRadio,
    FiZap
} from 'react-icons/fi';
import { callSocketService, type CallAnalysisResult } from '../services/callSocket';

export const LiveCallMonitor: React.FC = () => {
    const [isCallActive, setIsCallActive] = useState<boolean>(false);
    const [callId, setCallId] = useState<string>('');
    const [transcript, setTranscript] = useState<string>('');
    const [latestChunk, setLatestChunk] = useState<string>('');
    const [riskScore, setRiskScore] = useState<number>(0);
    const [isAlert, setIsAlert] = useState<boolean>(false);
    const [hits, setHits] = useState<string[]>([]);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    const mediaRecorderRef = useRef<MediaRecorder | null>(null);
    const mediaStreamRef = useRef<MediaStream | null>(null);
    const transcriptEndRef = useRef<HTMLDivElement | null>(null);

    // Auto scroll transcript to bottom on new updates
    useEffect(() => {
        transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [transcript, latestChunk]);

    // Cleanup on unmount
    useEffect(() => {
        return () => {
            stopCall();
        };
    }, []);

    const startCall = async () => {
        try {
            setErrorMsg(null);
            const newCallId = `call_${Date.now()}`;
            setCallId(newCallId);
            setTranscript('');
            setLatestChunk('');
            setRiskScore(0);
            setIsAlert(false);
            setHits([]);

            // Step 1: Connect WebSocket
            callSocketService.connect(newCallId, (data: CallAnalysisResult) => {
                if (data.transcript) setTranscript(data.transcript);
                if (data.latest_chunk) setLatestChunk(data.latest_chunk);
                if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                if (data.hits) setHits(data.hits);
            });

            // Step 2: Access Microphone
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaStreamRef.current = stream;

            // Step 3: Instantiate MediaRecorder with 2.5s timeslice
            let mimeType = 'audio/webm';
            if (!MediaRecorder.isTypeSupported(mimeType)) {
                mimeType = 'audio/mp4';
                if (!MediaRecorder.isTypeSupported(mimeType)) {
                    mimeType = ''; // browser default
                }
            }

            const options = mimeType ? { mimeType } : undefined;
            const recorder = new MediaRecorder(stream, options);

            recorder.ondataavailable = (event: BlobEvent) => {
                if (event.data && event.data.size > 0) {
                    callSocketService.sendAudioChunk(event.data);
                }
            };

            recorder.start(2500); // 2.5 seconds chunk interval
            mediaRecorderRef.current = recorder;
            setIsCallActive(true);

        } catch (err: any) {
            console.error('Failed to start microphone or call recorder:', err);
            setErrorMsg(err.message || 'Microphone access denied or audio recording failed.');
            callSocketService.disconnect();
            setIsCallActive(false);
        }
    };

    const stopCall = () => {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
            mediaRecorderRef.current.stop();
            mediaRecorderRef.current = null;
        }

        if (mediaStreamRef.current) {
            mediaStreamRef.current.getTracks().forEach((track) => track.stop());
            mediaStreamRef.current = null;
        }

        callSocketService.disconnect();
        setIsCallActive(false);
    };

    // Color theme based on risk score
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

    return (
        <div className="w-full space-y-6">

            {/* TOP CONTROLS & HEADER */}
            <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-2xl shadow-black/30">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                        <div className="flex items-center gap-2">
                            <span className={`h-2.5 w-2.5 rounded-full ${isCallActive ? 'bg-red-500 animate-ping' : 'bg-emerald-400'}`} />
                            <span className="font-mono text-[10px] font-bold tracking-[0.2em] text-emerald-400 uppercase">
                                REAL-TIME CALL PROTECTION
                            </span>
                        </div>
                        <h2 className="mt-2 text-2xl font-black text-[#e8eeea] tracking-tight">
                            Live Call Cyber Shield
                        </h2>
                        <p className="mt-1 text-xs text-[#82938e]">
                            Streams live microphone audio via WebSockets to detect digital arrest & authority impersonation scams instantly.
                        </p>
                    </div>

                    <div className="flex items-center gap-3">
                        {!isCallActive ? (
                            <button
                                onClick={startCall}
                                className="flex items-center gap-3 rounded-2xl bg-emerald-400 px-6 py-4 text-xs font-black text-[#06100d] uppercase tracking-wider transition hover:bg-emerald-300 shadow-lg shadow-emerald-500/20 active:scale-95"
                            >
                                <FiMic className="text-lg animate-bounce" />
                                Start Live Call Protection
                            </button>
                        ) : (
                            <button
                                onClick={stopCall}
                                className="flex items-center gap-3 rounded-2xl bg-red-500 px-6 py-4 text-xs font-black text-white uppercase tracking-wider transition hover:bg-red-600 shadow-lg shadow-red-500/30 active:scale-95 animate-pulse"
                            >
                                <FiMicOff className="text-lg" />
                                End Live Call Monitoring
                            </button>
                        )}
                    </div>
                </div>

                {errorMsg && (
                    <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-xs text-red-300 flex items-center gap-3">
                        <FiAlertTriangle className="text-lg shrink-0 text-red-400" />
                        <span>{errorMsg}</span>
                    </div>
                )}
            </div>

            {/* CRITICAL WARNING BANNER IF RISK >= 50 */}
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
                                CRITICAL SCAM THREAT DETECTED
                            </span>
                            <h3 className="mt-1 text-xl font-black text-white">
                                HIGH RISK COERCION / IMPERSONATION PATTERN DETECTED
                            </h3>
                            <p className="mt-2 text-xs leading-relaxed text-red-200/90 max-w-2xl">
                                The caller exhibits classic signs of digital arrest or authority impersonation. Do NOT transfer money, do NOT share OTP/UPI PINs, and do NOT stay isolated on this video/audio call.
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

            {/* DASHBOARD GRID */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* LEFT 2 COLS: LIVE TRANSCRIPT & AUDIO FEED */}
                <div className="lg:col-span-2 rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl flex flex-col justify-between min-h-[420px]">
                    <div>
                        <div className="flex items-center justify-between border-b border-[#1d312d] pb-4 mb-4">
                            <div className="flex items-center gap-2">
                                <FiRadio className={`text-lg ${isCallActive ? 'text-emerald-400 animate-pulse' : 'text-[#53645e]'}`} />
                                <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                    Live Audio Stream & Speech Transcript
                                </h3>
                            </div>
                            {isCallActive && (
                                <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 font-mono text-[10px] font-bold text-emerald-400 flex items-center gap-1.5">
                                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
                                    STREAMING CHUNKS (2.5s)
                                </span>
                            )}
                        </div>

                        {/* TRANSCRIPT CONTAINER */}
                        <div className="rounded-2xl border border-[#1a2b27] bg-[#050c0a] p-5 h-[280px] overflow-y-auto font-sans text-sm leading-relaxed text-[#c0cfc9] space-y-3 shadow-inner scrollbar-thin">
                            {transcript ? (
                                <p className="whitespace-pre-wrap">{transcript}</p>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-center text-[#53645e]">
                                    <FiActivity className="text-3xl mb-2 animate-spin" />
                                    <p className="text-xs">
                                        {isCallActive
                                            ? 'Listening to live audio... Speak or play sample call audio.'
                                            : 'Click "Start Live Call Protection" to begin capturing microphone audio.'}
                                    </p>
                                </div>
                            )}
                            <div ref={transcriptEndRef} />
                        </div>
                    </div>

                    {/* LATEST CHUNK MONITOR */}
                    {latestChunk && (
                        <div className="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 flex items-center gap-3 text-xs text-emerald-300">
                            <FiZap className="text-emerald-400 shrink-0" />
                            <span className="font-semibold text-emerald-400 shrink-0">Latest Chunk:</span>
                            <span className="truncate text-[#a2b5ae]">"{latestChunk}"</span>
                        </div>
                    )}
                </div>

                {/* RIGHT COL: REAL-TIME RISK GAUGE & METRICS */}
                <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl flex flex-col justify-between">
                    <div>
                        <div className="flex items-center gap-2 border-b border-[#1d312d] pb-4 mb-5">
                            <FiShield className="text-lg text-emerald-400" />
                            <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                Real-Time Risk Score
                            </h3>
                        </div>

                        {/* GAUGE & SCORE */}
                        <div className="text-center py-4">
                            <div className={`inline-flex flex-col items-center justify-center w-36 h-36 rounded-full border-4 shadow-2xl transition-all duration-500 ${getRiskColor(riskScore)}`}>
                                <span className="text-4xl font-black tracking-tight">
                                    {Math.round(riskScore)}%
                                </span>
                                <span className="text-[10px] font-bold uppercase tracking-widest mt-1 opacity-80">
                                    {riskScore >= 50 ? 'DANGER' : riskScore >= 30 ? 'MEDIUM RISK' : 'SAFE / LOW'}
                                </span>
                            </div>

                            {/* PROGRESS BAR */}
                            <div className="mt-6 w-full bg-[#050c0a] rounded-full h-3 p-0.5 border border-[#1d312d] overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all duration-500 ${getProgressBg(riskScore)}`}
                                    style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
                                />
                            </div>
                        </div>
                    </div>

                    {/* METRICS & STATUS */}
                    <div className="mt-6 space-y-3 border-t border-[#1d312d] pt-5">
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Call ID</span>
                            <span className="font-mono text-[#e8eeea] font-semibold">{callId || 'N/A'}</span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">AI Threat Guard</span>
                            <span className="flex items-center gap-1 font-semibold text-emerald-400">
                                <FiCheckCircle className="text-emerald-400" /> Active
                            </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Categories Flagged</span>
                            <span className="font-mono text-emerald-400 font-bold">{hits.length}</span>
                        </div>
                    </div>
                </div>

            </div>

        </div>
    );
};
