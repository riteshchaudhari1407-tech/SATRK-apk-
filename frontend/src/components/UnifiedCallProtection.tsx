import React, { useState, useEffect, useRef } from 'react';
import {
    FiMic,
    FiMicOff,
    FiSmartphone,
    FiUploadCloud,
    FiFileText,
    FiAlertTriangle,
    FiShield,
    FiActivity,
    FiCheckCircle,
    FiRadio,
    FiZap,
    FiTrash2,
    FiRefreshCw,
    FiInfo,
    FiCpu,
    FiThumbsUp,
    FiThumbsDown,
} from 'react-icons/fi';
import { callSocketService, getWsBaseUrl } from '../services/callSocket';
import type { CallAnalysisResult, DetectedSignal, VoiceAuthenticity } from '../services/callSocket';
import { uploadAudioFile, submitFeedback } from '../services/api';

type InputMode = 'phone' | 'mic' | 'file';

export const UnifiedCallProtection: React.FC = () => {
    // ── Input Mode State ──
    const [activeMode, setActiveMode] = useState<InputMode>('phone');

    // ── Phone Stream WS State ──
    const [isDashboardConnected, setIsDashboardConnected] = useState<boolean>(false);
    const [phoneStatus, setPhoneStatus] = useState<'IDLE' | 'ACTIVE' | 'DISCONNECTED'>('IDLE');
    const [connectedAt, setConnectedAt] = useState<string>('');

    // ── Browser Mic State ──
    const [isMicActive, setIsMicActive] = useState<boolean>(false);
    const mediaRecorderRef = useRef<MediaRecorder | null>(null);
    const mediaStreamRef = useRef<MediaStream | null>(null);

    // ── Audio File Upload State ──
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [isUploading, setIsUploading] = useState<boolean>(false);
    const fileInputRef = useRef<HTMLInputElement | null>(null);

    // ── Shared Analysis Visualization State ──
    const [activeSourceLabel, setActiveSourceLabel] = useState<string>('Android Phone Stream');
    const [callId, setCallId] = useState<string>('');
    const [transcript, setTranscript] = useState<string>('');
    const [latestChunk, setLatestChunk] = useState<string>('');
    const [riskScore, setRiskScore] = useState<number>(0);
    const [verdict, setVerdict] = useState<'SAFE' | 'WARNING' | 'SCAM' | 'DANGER'>('SAFE');
    const [isAlert, setIsAlert] = useState<boolean>(false);
    const [explanation, setExplanation] = useState<string>('');
    const [scamCategory, setScamCategory] = useState<string>('');
    const [hits, setHits] = useState<string[]>([]);
    const [detectedSignals, setDetectedSignals] = useState<DetectedSignal[]>([]);
    const [voiceAuthenticity, setVoiceAuthenticity] = useState<VoiceAuthenticity | null>(null);
    const [chunkCount, setChunkCount] = useState<number>(0);
    const [errorMsg, setErrorMsg] = useState<string | null>(null);

    // ── Feedback Loop UI State ──
    const [feedbackState, setFeedbackState] = useState<'idle' | 'submitting' | 'submitted'>('idle');
    const [feedbackChoice, setFeedbackChoice] = useState<boolean | null>(null);

    const socketRef = useRef<WebSocket | null>(null);
    const transcriptEndRef = useRef<HTMLDivElement | null>(null);
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // Auto-scroll transcript to bottom
    useEffect(() => {
        transcriptEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [transcript, latestChunk]);

    // ── 1. Phone WS Subscription (passive background listener) ──
    useEffect(() => {
        const connectWs = () => {
            const wsBaseUrl = getWsBaseUrl();
            const wsUrl = `${wsBaseUrl}/calls/ws-frontend`;
            const ws = new WebSocket(wsUrl);
            socketRef.current = ws;

            ws.onopen = () => {
                console.log(`[UnifiedCallProtection] Dashboard connected to ${wsUrl}`);
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
                            setActiveSourceLabel('Android Mobile App');
                            // Reset state for new call session
                            setTranscript('');
                            setLatestChunk('');
                            setRiskScore(0);
                            setVerdict('SAFE');
                            setIsAlert(false);
                            setExplanation('');
                            setScamCategory('');
                            setHits([]);
                            setDetectedSignals([]);
                            setVoiceAuthenticity(null);
                            setFeedbackState('idle');
                            setFeedbackChoice(null);
                            setChunkCount(0);
                            break;

                        case 'call_analysis':
                            setPhoneStatus('ACTIVE');
                            if (data.call_id) setCallId(data.call_id);
                            if (data.transcript !== undefined) setTranscript(data.transcript);
                            if (data.latest_chunk !== undefined) setLatestChunk(data.latest_chunk);
                            if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                            if (data.verdict) setVerdict(data.verdict);
                            if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                            if (data.explanation) setExplanation(data.explanation);
                            if (data.scam_category) setScamCategory(data.scam_category);
                            if (data.hits) setHits(data.hits);
                            if (data.detected_signals) setDetectedSignals(data.detected_signals);
                            if (data.voice_authenticity !== undefined) setVoiceAuthenticity(data.voice_authenticity);
                            setChunkCount((prev) => prev + 1);
                            break;

                        case 'phone_disconnected':
                            setPhoneStatus('DISCONNECTED');
                            break;

                        default:
                            if (data.call_id) setCallId(data.call_id);
                            if (data.transcript !== undefined) setTranscript(data.transcript);
                            if (data.latest_chunk !== undefined) setLatestChunk(data.latest_chunk);
                            if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                            if (data.verdict) setVerdict(data.verdict);
                            if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                            if (data.explanation) setExplanation(data.explanation);
                            if (data.scam_category) setScamCategory(data.scam_category);
                            if (data.hits) setHits(data.hits);
                            if (data.detected_signals) setDetectedSignals(data.detected_signals);
                            if (data.voice_authenticity !== undefined) setVoiceAuthenticity(data.voice_authenticity);
                            break;
                    }
                } catch (err) {
                    console.error('[UnifiedCallProtection] WS parse error:', err);
                }
            };

            ws.onclose = () => {
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
                socketRef.current.onclose = null;
                socketRef.current.close();
            }
        };
    }, []);

    // Cleanup mic recorder on unmount
    useEffect(() => {
        return () => {
            stopMicRecording();
        };
    }, []);

    // ── 2. Browser Mic Controls ──
    const startMicRecording = async () => {
        try {
            setErrorMsg(null);
            const newCallId = `mic_${Date.now()}`;
            setCallId(newCallId);
            setActiveSourceLabel('Browser Microphone');
            setTranscript('');
            setLatestChunk('');
            setRiskScore(0);
            setVerdict('SAFE');
            setIsAlert(false);
            setExplanation('');
            setScamCategory('');
            setHits([]);
            setDetectedSignals([]);
            setVoiceAuthenticity(null);
            setFeedbackState('idle');
            setFeedbackChoice(null);
            setChunkCount(0);

            // Connect WebSocket for live mic stream
            callSocketService.connect(newCallId, (data: CallAnalysisResult) => {
                if (data.transcript) setTranscript(data.transcript);
                if (data.latest_chunk) setLatestChunk(data.latest_chunk);
                if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                if (data.verdict) setVerdict(data.verdict);
                if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                if (data.explanation) setExplanation(data.explanation);
                if (data.scam_category) setScamCategory(data.scam_category);
                if (data.hits) setHits(data.hits);
                if (data.detected_signals) setDetectedSignals(data.detected_signals);
                if (data.voice_authenticity !== undefined) setVoiceAuthenticity(data.voice_authenticity);
                setChunkCount((prev) => prev + 1);
            });

            // Access Microphone
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaStreamRef.current = stream;

            let mimeType = 'audio/webm';
            if (!MediaRecorder.isTypeSupported(mimeType)) {
                mimeType = 'audio/mp4';
                if (!MediaRecorder.isTypeSupported(mimeType)) {
                    mimeType = '';
                }
            }

            const options = mimeType ? { mimeType } : undefined;
            const recorder = new MediaRecorder(stream, options);

            recorder.ondataavailable = (event: BlobEvent) => {
                if (event.data && event.data.size > 0) {
                    callSocketService.sendAudioChunk(event.data);
                }
            };

            recorder.start(2500); // Send 2.5 second audio chunks
            mediaRecorderRef.current = recorder;
            setIsMicActive(true);

        } catch (err: any) {
            console.error('Failed to start microphone recording:', err);
            setErrorMsg(err.message || 'Microphone access denied or recording failed.');
            callSocketService.disconnect();
            setIsMicActive(false);
        }
    };

    const stopMicRecording = () => {
        if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
            mediaRecorderRef.current.stop();
            mediaRecorderRef.current = null;
        }

        if (mediaStreamRef.current) {
            mediaStreamRef.current.getTracks().forEach((track) => track.stop());
            mediaStreamRef.current = null;
        }

        callSocketService.disconnect();
        setIsMicActive(false);
    };

    // ── 3. Audio File Upload Handler ──
    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setSelectedFile(e.target.files[0]);
            setErrorMsg(null);
        }
    };

    const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
        e.preventDefault();
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            setSelectedFile(e.dataTransfer.files[0]);
            setErrorMsg(null);
        }
    };

    const processAudioFile = async () => {
        if (!selectedFile) return;

        try {
            setIsUploading(true);
            setErrorMsg(null);
            setActiveSourceLabel(`File: ${selectedFile.name}`);
            setTranscript('Uploading and processing audio file through Satrk AI STT & Threat Engine...');
            setLatestChunk('File uploaded — analyzing...');
            setRiskScore(0);
            setVerdict('SAFE');
            setIsAlert(false);
            setExplanation('Processing file through Satrk AI Threat Detection Engine...');
            setScamCategory('Processing');
            setHits([]);
            setDetectedSignals([]);
            setVoiceAuthenticity(null);
            setFeedbackState('idle');
            setFeedbackChoice(null);
            setChunkCount(1);

            const res = await uploadAudioFile(selectedFile);

            if (res.success && res.data) {
                const data = res.data;
                if (data.call_id) setCallId(data.call_id);
                if (data.transcript !== undefined) setTranscript(data.transcript || '(No speech detected in audio file)');
                if (data.latest_chunk !== undefined) setLatestChunk(data.latest_chunk || 'Complete file analyzed');
                if (typeof data.risk_score === 'number') setRiskScore(data.risk_score);
                if (data.verdict) setVerdict(data.verdict);
                if (typeof data.alert === 'boolean') setIsAlert(data.alert);
                if (data.explanation) setExplanation(data.explanation);
                if (data.scam_category) setScamCategory(data.scam_category);
                if (data.hits) setHits(data.hits);
                if (data.detected_signals) setDetectedSignals(data.detected_signals);
                if (data.voice_authenticity !== undefined) setVoiceAuthenticity(data.voice_authenticity);
            } else {
                setErrorMsg(res.error || 'Audio processing failed');
                setTranscript('Failed to process audio file.');
            }
        } catch (err: any) {
            setErrorMsg(err.message || 'Failed to upload audio file');
        } finally {
            setIsUploading(false);
        }
    };

    const clearAnalysis = () => {
        setTranscript('');
        setLatestChunk('');
        setRiskScore(0);
        setVerdict('SAFE');
        setIsAlert(false);
        setExplanation('');
        setScamCategory('');
        setHits([]);
        setDetectedSignals([]);
        setVoiceAuthenticity(null);
        setFeedbackState('idle');
        setFeedbackChoice(null);
        setChunkCount(0);
        setCallId('');
        setSelectedFile(null);
        setErrorMsg(null);
    };

    // ── 4. Feedback Handler ──
    const handleFeedbackSubmit = async (wasCorrect: boolean) => {
        try {
            setFeedbackState('submitting');
            setFeedbackChoice(wasCorrect);
            const snippet = transcript ? transcript.slice(-200) : 'Live call alert feedback';
            const activeCallId = callId || `call_${Date.now()}`;
            await submitFeedback(activeCallId, wasCorrect, snippet);
            setFeedbackState('submitted');
        } catch (err) {
            console.error('Feedback submit error:', err);
            setFeedbackState('submitted');
        }
    };

    // Helper functions for styling
    const getVerdictBadge = () => {
        if (verdict === 'SCAM' || verdict === 'DANGER' || isAlert || riskScore >= 50) {
            return {
                label: 'SCAM DETECTED',
                badgeStyle: 'bg-red-500/20 text-red-400 border-red-500/50 shadow-red-500/30 animate-pulse',
                icon: <FiShield className="text-xl text-red-400 animate-bounce" />,
                bannerBg: 'border-red-500/50 bg-red-950/40 shadow-red-500/20'
            };
        }
        if (verdict === 'WARNING' || riskScore >= 30) {
            return {
                label: 'WARNING / SUSPICIOUS',
                badgeStyle: 'bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-amber-500/20',
                icon: <FiAlertTriangle className="text-xl text-amber-400" />,
                bannerBg: 'border-amber-500/40 bg-amber-950/30 shadow-amber-500/10'
            };
        }
        return {
            label: 'COMMUNICATION VERDICT: SAFE',
            badgeStyle: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40 shadow-emerald-500/10',
            icon: <FiCheckCircle className="text-xl text-emerald-400" />,
            bannerBg: 'border-emerald-500/30 bg-emerald-950/20 shadow-emerald-500/5'
        };
    };

    const getRiskColor = (score: number) => {
        if (score >= 50) return 'text-red-400 border-red-500/50 bg-red-500/10 shadow-red-500/20';
        if (score >= 30) return 'text-amber-400 border-amber-500/50 bg-amber-500/10 shadow-amber-500/20';
        return 'text-emerald-400 border-emerald-500/50 bg-emerald-500/10 shadow-emerald-500/20';
    };

    const getProgressBg = (score: number) => {
        if (score >= 50) return 'bg-gradient-to-r from-amber-500 to-red-500';
        if (score >= 30) return 'bg-gradient-to-r from-emerald-500 to-amber-500';
        return 'bg-emerald-400';
    };

    const currentVerdict = getVerdictBadge();

    return (
        <div className="w-full space-y-6 font-sans">

            {/* ── HEADER CARD WITH MULTI-INPUT TAB SELECTOR ── */}
            <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-2xl shadow-black/30">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    <div>
                        <div className="flex items-center gap-2">
                            <span className={`h-2.5 w-2.5 rounded-full ${
                                isMicActive || phoneStatus === 'ACTIVE' ? 'bg-red-500 animate-ping' : 'bg-emerald-400'
                            }`} />
                            <span className="font-mono text-[10px] font-bold tracking-[0.2em] text-emerald-400 uppercase">
                                UNIFIED LIVE CALL PROTECTION & MONITORING
                            </span>
                        </div>
                        <h2 className="mt-2 text-2xl font-black text-[#e8eeea] tracking-tight">
                            Live Cyber Shield & Audio Inspector
                        </h2>
                        <p className="mt-1 text-xs text-[#82938e] max-w-xl">
                            Real-time AI threat analysis powered by Satrk AI Speech-to-Text & Threat Engine supporting Android phone call streaming, browser mic capture, and audio files.
                        </p>
                    </div>

                    {/* MODE SELECTOR TABS */}
                    <div className="flex items-center gap-2 bg-[#050c0a] p-1.5 rounded-2xl border border-[#1d312d]">
                        <button
                            onClick={() => setActiveMode('phone')}
                            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-mono text-xs font-bold transition-all ${
                                activeMode === 'phone'
                                    ? 'bg-[#1d312d] text-emerald-400 border border-emerald-500/30 shadow-lg'
                                    : 'text-[#82938e] hover:text-[#e8eeea]'
                            }`}
                        >
                            <FiSmartphone className={`text-base ${phoneStatus === 'ACTIVE' ? 'text-emerald-400 animate-bounce' : ''}`} />
                            <span>Android Phone</span>
                            {phoneStatus === 'ACTIVE' && (
                                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                            )}
                        </button>

                        <button
                            onClick={() => setActiveMode('mic')}
                            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-mono text-xs font-bold transition-all ${
                                activeMode === 'mic'
                                    ? 'bg-[#1d312d] text-emerald-400 border border-emerald-500/30 shadow-lg'
                                    : 'text-[#82938e] hover:text-[#e8eeea]'
                            }`}
                        >
                            <FiMic className={`text-base ${isMicActive ? 'text-red-400 animate-pulse' : ''}`} />
                            <span>Browser Mic</span>
                            {isMicActive && (
                                <span className="h-2 w-2 rounded-full bg-red-400 animate-ping" />
                            )}
                        </button>

                        <button
                            onClick={() => setActiveMode('file')}
                            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-mono text-xs font-bold transition-all ${
                                activeMode === 'file'
                                    ? 'bg-[#1d312d] text-emerald-400 border border-emerald-500/30 shadow-lg'
                                    : 'text-[#82938e] hover:text-[#e8eeea]'
                            }`}
                        >
                            <FiUploadCloud className="text-base" />
                            <span>Audio File</span>
                        </button>
                    </div>
                </div>

                {/* MODE ACTION CONTROLS PANEL */}
                <div className="mt-6 border-t border-[#1d312d] pt-5">
                    {activeMode === 'phone' && (
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#050c0a] p-4 rounded-2xl border border-[#1a2b27]">
                            <div className="flex items-center gap-3">
                                <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    <FiSmartphone className="text-xl" />
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <h4 className="text-xs font-bold text-[#e8eeea] uppercase tracking-wider">
                                            Android App Call Monitor
                                        </h4>
                                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                                            phoneStatus === 'ACTIVE' 
                                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' 
                                                : phoneStatus === 'DISCONNECTED'
                                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                                                : 'bg-zinc-800 text-zinc-400'
                                        }`}>
                                            {phoneStatus}
                                        </span>
                                    </div>
                                    <p className="text-[11px] text-[#82938e] mt-0.5">
                                        {phoneStatus === 'ACTIVE'
                                            ? 'Receiving encrypted audio chunks live from Satrk Android App.'
                                            : 'Open the Satrk Android app & tap "START CALL MONITORING" during an active call.'}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className="font-mono text-[10px] text-[#82938e] flex items-center gap-2">
                                    <span className={`h-2 w-2 rounded-full ${isDashboardConnected ? 'bg-emerald-400 animate-ping' : 'bg-red-500'}`} />
                                    WS Status: {isDashboardConnected ? 'Connected' : 'Offline'}
                                </span>
                            </div>
                        </div>
                    )}

                    {activeMode === 'mic' && (
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#050c0a] p-4 rounded-2xl border border-[#1a2b27]">
                            <div className="flex items-center gap-3">
                                <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    <FiMic className="text-xl" />
                                </div>
                                <div>
                                    <h4 className="text-xs font-bold text-[#e8eeea] uppercase tracking-wider">
                                        Browser Microphone Stream
                                    </h4>
                                    <p className="text-[11px] text-[#82938e] mt-0.5">
                                        Streams live audio from your computer microphone to analyze incoming call audio.
                                    </p>
                                </div>
                            </div>
                            <div>
                                {!isMicActive ? (
                                    <button
                                        onClick={startMicRecording}
                                        className="flex items-center gap-2.5 rounded-xl bg-emerald-400 px-5 py-3 text-xs font-black text-[#06100d] uppercase tracking-wider transition hover:bg-emerald-300 shadow-lg shadow-emerald-500/20 active:scale-95"
                                    >
                                        <FiMic className="text-base animate-bounce" />
                                        Start Mic Protection
                                    </button>
                                ) : (
                                    <button
                                        onClick={stopMicRecording}
                                        className="flex items-center gap-2.5 rounded-xl bg-red-500 px-5 py-3 text-xs font-black text-white uppercase tracking-wider transition hover:bg-red-600 shadow-lg shadow-red-500/30 active:scale-95 animate-pulse"
                                    >
                                        <FiMicOff className="text-base" />
                                        Stop Mic Recording
                                    </button>
                                )}
                            </div>
                        </div>
                    )}

                    {activeMode === 'file' && (
                        <div className="bg-[#050c0a] p-4 rounded-2xl border border-[#1a2b27] space-y-4">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                                <div className="flex items-center gap-3">
                                    <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                        <FiFileText className="text-xl" />
                                    </div>
                                    <div>
                                        <h4 className="text-xs font-bold text-[#e8eeea] uppercase tracking-wider">
                                            Audio Recording File Inspector
                                        </h4>
                                        <p className="text-[11px] text-[#82938e] mt-0.5">
                                            Upload call recordings (.wav, .mp3, .webm, .m4a, .ogg) for full scam detection scan.
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-3">
                                    <input
                                        type="file"
                                        ref={fileInputRef}
                                        onChange={handleFileSelect}
                                        accept="audio/*,video/webm,.wav,.mp3,.webm,.m4a,.ogg,.mp4,.aac"
                                        className="hidden"
                                    />
                                    <button
                                        onClick={() => fileInputRef.current?.click()}
                                        className="flex items-center gap-2 rounded-xl bg-[#1d312d] px-4 py-2.5 text-xs font-bold text-emerald-400 border border-emerald-500/30 hover:bg-[#26413c] transition"
                                    >
                                        <FiUploadCloud className="text-base" />
                                        Choose File
                                    </button>

                                    {selectedFile && (
                                        <button
                                            onClick={processAudioFile}
                                            disabled={isUploading}
                                            className="flex items-center gap-2 rounded-xl bg-emerald-400 px-5 py-2.5 text-xs font-black text-[#06100d] uppercase tracking-wider transition hover:bg-emerald-300 disabled:opacity-50 shadow-lg shadow-emerald-500/20"
                                        >
                                            {isUploading ? (
                                                <>
                                                    <FiRefreshCw className="text-base animate-spin" />
                                                    Processing...
                                                </>
                                            ) : (
                                                <>
                                                    <FiZap className="text-base" />
                                                    Analyze File
                                                </>
                                            )}
                                        </button>
                                    )}
                                </div>
                            </div>

                            {/* FILE DROP ZONE */}
                            <div
                                onDragOver={(e) => e.preventDefault()}
                                onDrop={handleFileDrop}
                                onClick={() => !selectedFile && fileInputRef.current?.click()}
                                className={`border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-colors ${
                                    selectedFile
                                        ? 'border-emerald-500/50 bg-emerald-500/5'
                                        : 'border-[#1d312d] hover:border-emerald-500/30 bg-[#071310]'
                                }`}
                            >
                                {selectedFile ? (
                                    <div className="flex items-center justify-between text-xs">
                                        <div className="flex items-center gap-2 font-mono text-emerald-300">
                                            <FiFileText className="text-lg text-emerald-400" />
                                            <span className="font-bold">{selectedFile.name}</span>
                                            <span className="text-[#82938e]">({(selectedFile.size / 1024 / 1024).toFixed(2)} MB)</span>
                                        </div>
                                        <button
                                            onClick={(e) => {
                                                e.stopPropagation();
                                                setSelectedFile(null);
                                            }}
                                            className="p-1 text-red-400 hover:text-red-300 transition"
                                        >
                                            <FiTrash2 className="text-base" />
                                        </button>
                                    </div>
                                ) : (
                                    <div className="text-xs text-[#82938e]">
                                        Drag & drop call recording here or <span className="text-emerald-400 underline font-semibold">browse files</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {errorMsg && (
                        <div className="mt-3 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300 flex items-center gap-3">
                            <FiAlertTriangle className="text-lg shrink-0 text-red-400" />
                            <span>{errorMsg}</span>
                        </div>
                    )}
                </div>
            </div>

            {/* ── REAL-TIME VERDICT HERO HEADER BANNER ── */}
            <div className={`relative overflow-hidden rounded-3xl border p-6 backdrop-blur-xl transition-all duration-500 ${currentVerdict.bannerBg}`}>
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-5">
                    <div className="flex items-center gap-4">
                        <div className={`p-3.5 rounded-2xl border ${currentVerdict.badgeStyle}`}>
                            {currentVerdict.icon}
                        </div>
                        <div>
                            <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-[10px] font-bold tracking-[0.2em] text-[#82938e] uppercase">
                                    REAL-TIME AI VERDICT
                                </span>
                                {scamCategory && (
                                    <span className="rounded-lg bg-[#1d312d] border border-emerald-500/30 px-2.5 py-0.5 font-mono text-[10px] font-bold text-emerald-400">
                                        🏷️ {scamCategory}
                                    </span>
                                )}
                                {voiceAuthenticity?.is_likely_cloned === true && (
                                    <span className="flex items-center gap-1.5 rounded-lg bg-red-600/90 border border-red-400 px-3 py-0.5 font-mono text-[10px] font-black text-white uppercase shadow-lg shadow-red-600/50 animate-pulse">
                                        <FiAlertTriangle className="text-amber-300 animate-bounce text-xs" />
                                        DEEPFAKE / VOICE CLONE DETECTED
                                    </span>
                                )}
                            </div>
                            <h3 className="text-xl font-black text-white tracking-tight mt-0.5">
                                {currentVerdict.label}
                            </h3>
                        </div>
                    </div>

                    <div className="flex items-center gap-3">
                        <div className="text-right hidden sm:block">
                            <p className="text-[10px] font-mono text-[#82938e] uppercase">Threat Score</p>
                            <p className="text-xl font-black font-mono text-emerald-400">{Math.round(riskScore)}%</p>
                        </div>
                        <div className={`px-4 py-2 rounded-xl font-mono text-xs font-black border uppercase tracking-wider ${currentVerdict.badgeStyle}`}>
                            {verdict || 'SAFE'}
                        </div>
                    </div>
                </div>
            </div>

            {/* ── FEEDBACK UI PROMPT FOR LIVE THREAT ALERTS ── */}
            {(riskScore >= 50 || isAlert) && (
                <div className="rounded-3xl border border-amber-500/40 bg-amber-950/30 p-5 shadow-xl flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                        <div className="p-3 rounded-2xl bg-amber-500/20 text-amber-400 border border-amber-500/30">
                            <FiInfo className="text-xl" />
                        </div>
                        <div>
                            <h4 className="text-xs font-bold text-[#e8eeea] tracking-wider uppercase">
                                Was this alert correct?
                            </h4>
                            <p className="text-[11px] text-[#a2b5ae] mt-0.5">
                                Help calibrate Satrk AI for call <span className="font-mono text-emerald-400 font-bold">{callId || 'active_session'}</span>.
                            </p>
                        </div>
                    </div>

                    <div className="flex items-center gap-2.5">
                        {feedbackState === 'submitted' ? (
                            <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-bold font-mono">
                                <FiCheckCircle className="text-base text-emerald-400" />
                                <span>Feedback Recorded ({feedbackChoice ? 'Correct Alert' : 'False Positive'})</span>
                            </div>
                        ) : (
                            <>
                                <button
                                    onClick={() => handleFeedbackSubmit(true)}
                                    disabled={feedbackState === 'submitting'}
                                    className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-xs font-bold transition disabled:opacity-50 active:scale-95 shadow-md shadow-emerald-500/10"
                                >
                                    <FiThumbsUp className="text-sm text-emerald-400" />
                                    <span>Yes</span>
                                </button>
                                <button
                                    onClick={() => handleFeedbackSubmit(false)}
                                    disabled={feedbackState === 'submitting'}
                                    className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 text-xs font-bold transition disabled:opacity-50 active:scale-95 shadow-md shadow-red-500/10"
                                >
                                    <FiThumbsDown className="text-sm text-red-400" />
                                    <span>No</span>
                                </button>
                            </>
                        )}
                    </div>
                </div>
            )}

            {/* ── GROQ AI THREAT EXPLANATION CARD ── */}
            {explanation && (
                <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl space-y-4">
                    <div className="flex items-center justify-between border-b border-[#1d312d] pb-4">
                        <div className="flex items-center gap-2">
                            <FiCpu className="text-lg text-emerald-400" />
                            <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                SATRK AI THREAT EXPLANATION & TRIGGER BREAKDOWN
                            </h3>
                        </div>
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-full font-bold">
                            🧠 SATRK AI REASONING
                        </span>
                    </div>

                    <div className="rounded-2xl border border-[#1a2b27] bg-[#050c0a] p-4 text-xs leading-relaxed text-[#c0cfc9]">
                        <p className="font-sans leading-relaxed text-sm">{explanation}</p>
                    </div>

                    {/* DETECTED SIGNALS / TRIGGER KEYWORDS GRID */}
                    {(detectedSignals.length > 0 || hits.length > 0) && (
                        <div className="pt-2">
                            <h4 className="text-[11px] font-mono font-bold text-[#82938e] uppercase tracking-wider mb-2.5">
                                Flagged Coercion & Impersonation Trigger Signals ({detectedSignals.length || hits.length}):
                            </h4>
                            <div className="flex flex-wrap gap-2">
                                {detectedSignals.length > 0 ? (
                                    detectedSignals.map((sig, idx) => (
                                        <div
                                            key={idx}
                                            className={`rounded-xl border px-3 py-2 text-xs flex flex-col gap-1 ${
                                                sig.severity === 'HIGH'
                                                    ? 'border-red-500/40 bg-red-500/10 text-red-300'
                                                    : 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                                            }`}
                                        >
                                            <div className="flex items-center gap-2 font-mono font-bold text-[11px]">
                                                <span>⚠️ {sig.signal}</span>
                                                <span className="text-[9px] px-1.5 py-0.2 rounded bg-black/40 uppercase">
                                                    {sig.severity}
                                                </span>
                                            </div>
                                            {sig.evidence && (
                                                <p className="text-[10px] text-[#a2b5ae] italic">
                                                    "{sig.evidence}"
                                                </p>
                                            )}
                                        </div>
                                    ))
                                ) : (
                                    hits.map((category, idx) => (
                                        <span
                                            key={idx}
                                            className="rounded-lg bg-red-500/20 border border-red-500/40 px-3 py-1.5 font-mono text-[11px] font-bold text-red-300"
                                        >
                                            ⚠️ {category}
                                        </span>
                                    ))
                                )}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── UNIFIED VISUALIZATION DASHBOARD GRID ── */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* LEFT 2 COLS: TRANSCRIPT & SPEECH STREAM */}
                <div className="lg:col-span-2 rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 shadow-xl flex flex-col justify-between min-h-[440px]">
                    <div>
                        <div className="flex items-center justify-between border-b border-[#1d312d] pb-4 mb-4">
                            <div className="flex items-center gap-2">
                                <FiRadio className={`text-lg ${
                                    isMicActive || phoneStatus === 'ACTIVE' ? 'text-emerald-400 animate-pulse' : 'text-[#53645e]'
                                }`} />
                                <h3 className="text-sm font-bold text-[#e8eeea] tracking-wider uppercase">
                                    Live Audio Speech Transcript
                                </h3>
                            </div>

                            <div className="flex items-center gap-2">
                                {(transcript || hits.length > 0) && (
                                    <button
                                        onClick={clearAnalysis}
                                        className="text-[11px] font-mono text-[#82938e] hover:text-red-400 transition flex items-center gap-1 mr-2"
                                    >
                                        <FiTrash2 /> Clear
                                    </button>
                                )}
                                {chunkCount > 0 && (
                                    <span className="rounded-full bg-emerald-500/10 border border-emerald-500/30 px-3 py-1 font-mono text-[10px] font-bold text-emerald-400 flex items-center gap-1.5">
                                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
                                        {chunkCount} CHUNKS PROCESSED
                                    </span>
                                )}
                            </div>
                        </div>

                        {/* TRANSCRIPT BOX */}
                        <div className="rounded-2xl border border-[#1a2b27] bg-[#050c0a] p-5 h-[300px] overflow-y-auto font-sans text-sm leading-relaxed text-[#c0cfc9] space-y-3 shadow-inner scrollbar-thin">
                            {transcript ? (
                                <p className="whitespace-pre-wrap leading-relaxed">{transcript}</p>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center text-center text-[#53645e]">
                                    <FiActivity className="text-3xl mb-2 animate-spin" />
                                    <p className="text-xs">
                                        {isMicActive
                                            ? 'Listening to live microphone audio...'
                                            : phoneStatus === 'ACTIVE'
                                            ? 'Phone connected — streaming speech...'
                                            : 'Select an input mode (Android Phone, Browser Mic, or Audio File) to start scanning.'}
                                    </p>
                                </div>
                            )}
                            <div ref={transcriptEndRef} />
                        </div>
                    </div>

                    {/* LATEST CHUNK TICKER */}
                    {latestChunk && (
                        <div className="mt-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 flex items-center gap-3 text-xs text-emerald-300">
                            <FiZap className="text-emerald-400 shrink-0" />
                            <span className="font-semibold text-emerald-400 shrink-0">Latest Chunk:</span>
                            <span className="truncate text-[#a2b5ae]">"{latestChunk}"</span>
                        </div>
                    )}
                </div>

                {/* RIGHT COL: REAL-TIME RISK SCORE GAUGE & METRICS */}
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
                                    {verdict || (riskScore >= 50 ? 'DANGER' : riskScore >= 30 ? 'MEDIUM RISK' : 'SAFE / LOW')}
                                </span>
                            </div>

                            {/* PROGRESS BAR */}
                            <div className="mt-6 w-full bg-[#050c0a] rounded-full h-3 p-0.5 border border-[#1d312d] overflow-hidden">
                                <div
                                    className={`h-full rounded-full transition-all duration-500 ${getProgressBg(riskScore)}`}
                                    style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
                                />
                            </div>

                            {/* DEEPFAKE DETECTED SCORE BADGE */}
                            {voiceAuthenticity?.is_likely_cloned === true && (
                                <div className="mt-4 flex items-center justify-center gap-2 rounded-xl bg-red-600/20 border border-red-500/50 px-3 py-2 text-xs font-black font-mono text-red-400 shadow-md shadow-red-500/20 animate-pulse">
                                    <FiAlertTriangle className="text-amber-400 animate-bounce text-sm shrink-0" />
                                    <span>DEEPFAKE / VOICE CLONE DETECTED</span>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* METADATA SUMMARY */}
                    <div className="mt-6 space-y-3 border-t border-[#1d312d] pt-5">
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Active Source</span>
                            <span className="font-mono text-emerald-400 font-bold truncate max-w-[150px]">
                                {activeSourceLabel}
                            </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                            <span className="text-[#82938e]">Call / Session ID</span>
                            <span className="font-mono text-[#e8eeea] font-semibold truncate max-w-[160px]">
                                {callId || '—'}
                            </span>
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
                            <span className="text-[#82938e]">AI Threat Guard</span>
                            <span className="flex items-center gap-1 font-semibold text-emerald-400">
                                <FiCheckCircle className="text-emerald-400" /> Satrk AI Active
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
