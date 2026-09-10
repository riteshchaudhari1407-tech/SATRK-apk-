import React, {
    useEffect,
    useMemo,
    useRef,
    useState,
} from 'react';

import {
    FiActivity,
    FiAlertCircle,
    FiAlertTriangle,
    FiCheckCircle,
    FiFileText,
    FiGrid,
    FiImage,
    FiLayers,
    FiLogOut,
    FiMenu,
    FiMoon,
    FiSearch,
    FiSettings,
    FiShield,
    FiSun,
    FiUploadCloud,
    FiUser,
    FiX,
    FiPhoneCall,
    FiMic,
    FiLink,
} from 'react-icons/fi';

import {
    Area,
    AreaChart,
    CartesianGrid,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts';

import jsPDF from 'jspdf';

import { supabase } from './supabase';

import { scanTextMessage, scanImageMessage, getApiBaseUrl, analyzeLink } from './services/api';
import type { LinkAnalysisResult } from './services/api';

import { UnifiedCallProtection } from './components/UnifiedCallProtection';

/* =========================================================
   TYPES
========================================================= */

type Tab =
    | 'overview'
    | 'scanner'
    | 'liveshield'
    | 'incidents'
    | 'intel'
    | 'settings';

type RiskLevel =
    | 'LOW'
    | 'MEDIUM'
    | 'HIGH'
    | 'CRITICAL';

type AuthMethod =
    | 'email'
    | 'google';

/* =========================================================
   INITIAL CHART DATA
========================================================= */

const initialThreatData = [
    { time: '08:00', threats: 18, blocked: 14 },
    { time: '09:00', threats: 26, blocked: 21 },
    { time: '10:00', threats: 19, blocked: 17 },
    { time: '11:00', threats: 42, blocked: 34 },
    { time: '12:00', threats: 37, blocked: 31 },
    { time: '13:00', threats: 58, blocked: 49 },
    { time: '14:00', threats: 46, blocked: 40 },
    { time: '15:00', threats: 71, blocked: 61 },
];

/* =========================================================
   GOOGLE ICON
========================================================= */

function GoogleIcon() {
    return (
        <svg
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
        >
            <path
                d="M21.8055 12.2308C21.8055 11.5185 21.7416 10.8369 21.632 10.1818H12V14.0492H17.4973C17.2605 15.2955 16.5582 16.3507 15.5091 17.063V19.5755H18.7445C20.6382 17.8328 21.8055 15.2727 21.8055 12.2308Z"
                fill="#4285F4"
            />

            <path
                d="M12.0001 22C14.7001 22 16.9637 21.1091 18.7446 19.5755L15.5092 17.063C14.6137 17.663 13.4737 18.0091 12.0001 18.0091C9.3955 18.0091 7.18823 16.2482 6.40187 13.8818H3.05786V16.4764C4.82968 19.9636 8.43241 22 12.0001 22Z"
                fill="#34A853"
            />

            <path
                d="M6.40182 13.8818C6.20182 13.2818 6.08818 12.6409 6.08818 12C6.08818 11.3591 6.20182 10.7182 6.40182 10.1182V7.52364H3.05782C2.37964 8.86545 2 10.3818 2 12C2 13.6182 2.37964 15.1345 3.05782 16.4764L6.40182 13.8818Z"
                fill="#FBBC05"
            />

            <path
                d="M12.0001 5.99091C13.4737 5.99091 14.791 6.49727 15.8328 7.49091L18.8173 4.50636C16.9591 2.76727 14.6955 2 12.0001 2C8.43241 2 4.82968 4.03636 3.05786 7.52364L6.40187 10.1182C7.18823 7.75182 9.3955 5.99091 12.0001 5.99091Z"
                fill="#EA4335"
            />
        </svg>
    );
}

/* =========================================================
   HELPERS
========================================================= */

function getRiskStyle(risk: RiskLevel | string) {
    switch (risk) {
        case 'CRITICAL':
            return 'bg-red-500/10 text-red-400 border-red-500/20';

        case 'HIGH':
            return 'bg-orange-500/10 text-orange-400 border-orange-500/20';

        case 'MEDIUM':
            return 'bg-amber-500/10 text-amber-400 border-amber-500/20';

        default:
            return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
}

function getRiskColor(score: number) {
    if (score >= 85) return '#ef4444';
    if (score >= 65) return '#f97316';
    if (score >= 40) return '#f59e0b';

    return '#10b981';
}

/* =========================================================
   REAL-TIME THREAT ANALYSIS ENGINE
   (Deterministic NLP-style pattern engine — every input is
   independently scored, nothing is hardcoded.)
========================================================= */

type SignalHit = {
    category: string;
    weight: number;
    excerpt: string;
    description: string;
};

const THREAT_CATEGORIES: {
    name: string;
    max: number;
    frac: number;
    description: string;
    patterns: RegExp[];
}[] = [
        {
            name: 'Authority Impersonation',
            max: 28,
            frac: 0.78,
            description:
                'Message invokes a police, investigative or regulatory identity. Real Indian agencies (CBI, RBI, Police, ED, Cyber Cell) never open a criminal case over WhatsApp, SMS or a phone call.',
            patterns: [
                /\bcbi\b/i,
                /central bureau of investigation/i,
                /\brbi\b/i,
                /reserve bank of india/i,
                /income tax department/i,
                /cyber\s?cell/i,
                /cyber\s?crime/i,
                /\btrai\b/i,
                /narcotics?( control)? bureau/i,
                /\bncb\b/i,
                /enforcement directorate/i,
                /\bed officer\b/i,
                /customs department/i,
                /supreme court/i,
                /high court/i,
                /\bmagistrate\b/i,
                /\bfir\b/i,
                /arrest warrant/i,
                /non[-\s]?bailable warrant/i,
                /police station/i,
                /sub[-\s]?inspector/i,
                /\bdcp\b/i,
            ],
        },
        {
            name: 'Digital Arrest / Isolation Tactics',
            max: 32,
            frac: 0.8,
            description:
                "This is the signature pattern of India's 'digital arrest' scam — victims are told to stay on a video call and cut off from everyone while impersonators simulate a virtual custody.",
            patterns: [
                /digital arrest/i,
                /stay on (this|the) (call|video)/i,
                /do not disconnect/i,
                /do not hang\s?up/i,
                /video call immediately/i,
                /stay on video/i,
                /virtual custody/i,
                /house arrest/i,
                /do not leave the frame/i,
                /keep (your )?camera on/i,
                /under surveillance/i,
                /do not tell anyone/i,
                /do not inform (your )?family/i,
                /keep this (confidential|secret)/i,
                /top secret investigation/i,
                /video call pe raho/i,
                /kisi ko mat batana/i,
                /giraftar/i,
                /cannot contact anyone/i,
            ],
        },
        {
            name: 'Urgency & Threat Pressure',
            max: 16,
            frac: 0.5,
            description:
                'Manufactured urgency and legal threats are used to short-circuit rational thinking so the victim complies before verifying anything independently.',
            patterns: [
                /immediate action/i,
                /act (immediately|now)/i,
                /right now/i,
                /within \d+ ?(minutes|hours|mins)/i,
                /last warning/i,
                /final notice/i,
                /failure to comply/i,
                /legal action will be taken/i,
                /you will be arrested/i,
                /non[-\s]?compliance/i,
                /\burgent\b/i,
                /case (has been |)dala gaya/i,
                /police action will be taken/i,
                /join this video call/i,
            ],
        },
        {
            name: 'Financial & Identity Fraud Bait',
            max: 20,
            frac: 0.65,
            description:
                'Requests for OTP, UPI details or "transfer to a safe account" are the actual mechanism scammers use to move money — no legitimate authority ever asks for this.',
            patterns: [
                /share (your )?otp/i,
                /upi pin/i,
                /account (will be |has been )?frozen/i,
                /pay a fine/i,
                /refundable (security )?deposit/i,
                /processing fee/i,
                /transfer (the )?(amount|money|funds)/i,
                /safe account/i,
                /verification fee/i,
                /kyc update/i,
                /verify (your )?kyc/i,
                /link(ed)? (your )?aadhaar/i,
                /aadhaar (number|card|has been).{0,25}(linked|blocked|misuse)/i,
                /pan card.{0,25}(linked|blocked|misuse)/i,
                /parcel contains/i,
                /illegal parcel/i,
                /drugs (found|detected) in your name/i,
                /paisa transfer karo/i,
                /money laundering/i,
            ],
        },
        {
            name: 'Phishing & Remote-Access Bait',
            max: 14,
            frac: 0.55,
            description:
                'Links, "install this app" or remote-access requests (AnyDesk/TeamViewer) are used to steal credentials or hand over full control of the device.',
            patterns: [
                /click here/i,
                /click (the|this) link/i,
                /install anydesk/i,
                /install teamviewer/i,
                /download this app/i,
                /remote access/i,
                /bit\.ly\//i,
                /tinyurl\.com\//i,
                /verify your identity by clicking/i,
            ],
        },
    ];

function extractExcerpt(
    text: string,
    pattern: RegExp
): string {
    const match = text.match(pattern);

    if (!match) return '';

    const index = match.index ?? 0;

    const start = Math.max(
        0,
        index - 18
    );

    const end = Math.min(
        text.length,
        index + match[0].length + 18
    );

    const excerpt = text
        .slice(start, end)
        .trim();

    return (start > 0 ? '…' : '') +
        excerpt +
        (end < text.length ? '…' : '');
}

function analyzeThreatText(
    rawText: string
) {
    const text = rawText.trim();

    const hits: SignalHit[] = [];

    let total = 0;

    for (const category of THREAT_CATEGORIES) {
        const matched = category.patterns.filter(
            (pattern) => pattern.test(text)
        );

        if (matched.length === 0) continue;

        // First match already carries most of the
        // category's weight (one clear phrase is real
        // evidence); further matches close the gap to
        // the category max with diminishing returns.
        const categoryScore =
            category.max *
            (1 -
                Math.pow(
                    1 - category.frac,
                    matched.length
                ));

        total += categoryScore;

        hits.push({
            category: category.name,
            weight: Math.round(
                categoryScore
            ),
            excerpt: extractExcerpt(
                text,
                matched[0]
            ),
            description:
                category.description,
        });
    }

    // Combining several distinct scam tactics in one
    // message (impersonation + isolation + financial
    // ask, etc.) is itself strong evidence — real scam
    // scripts stack tactics, unrelated text doesn't.
    const distinctCategories =
        hits.length;

    const comboBonus =
        distinctCategories >= 4
            ? 30
            : distinctCategories === 3
                ? 26
                : distinctCategories === 2
                    ? 20
                    : 0;

    total += comboBonus;

    // Weak linguistic markers — only counted as a small bonus,
    // and only if at least one real category already matched,
    // so an unrelated all-caps text doesn't get flagged alone.
    if (hits.length > 0) {
        const exclamations = (
            text.match(/!/g) || []
        ).length;

        const upperWords = (
            text.match(/\b[A-Z]{4,}\b/g) ||
            []
        ).length;

        const linguisticBonus = Math.min(
            8,
            exclamations * 1.5 +
            upperWords * 2
        );

        total += linguisticBonus;
    }

    const score = Math.max(
        0,
        Math.min(100, Math.round(total))
    );

    const risk =
        score >= 80
            ? 'CRITICAL'
            : score >= 55
                ? 'HIGH'
                : score >= 30
                    ? 'MEDIUM'
                    : 'LOW';

    const signals = hits
        .sort(
            (a, b) => b.weight - a.weight
        )
        .map(
            (hit) =>
                `${hit.category}${hit.excerpt
                    ? ` — matched "${hit.excerpt}"`
                    : ''
                }. ${hit.description}`
        );

    let explanation = '';

    if (hits.length === 0) {
        explanation =
            `No authority-impersonation, isolation, financial-fraud or phishing patterns were detected in this message.\n\n` +
            `Based on the language used, this does not match the known structure of a digital-arrest or impersonation scam. Risk score: ${score}%.\n\n` +
            `Even so, never share OTPs, UPI PINs or banking details with anyone, and treat any unexpected call claiming to be a government agency with caution.`;
    } else {
        const categoryList = hits
            .sort(
                (a, b) => b.weight - a.weight
            )
            .map(
                (hit) =>
                    `• ${hit.category} (+${hit.weight} pts)`
            )
            .join('\n');

        explanation =
            `This message was scored ${score}% risk (${risk}) after matching ${hits.length} known scam pattern${hits.length > 1 ? 's' : ''
            } used in Indian "digital arrest" and authority-impersonation fraud.\n\n` +
            `Signals contributing to the score:\n${categoryList}\n\n` +
            `${risk === 'CRITICAL' ||
                risk === 'HIGH'
                ? 'This strongly resembles a scripted impersonation/digital-arrest scam. Do not make any payment, do not share OTP/UPI details, and do not stay on a video call under pressure. Real police, CBI or RBI officials never conduct arrests or investigations over a phone or video call.'
                : 'Some risk indicators are present. Verify the sender independently through official channels before taking any action.'
            }\n\n` +
            `If you believe you are being targeted, report immediately to India's National Cyber Crime Helpline at 1930 or via cybercrime.gov.in.`;
    }

    return {
        risk_score: score,
        risk_level: risk,
        signals,
        explanation,
    };
}

/* =========================================================
   ARC GAUGE (red -> blue semicircle dial)
========================================================= */

function ArcGauge({
    value,
    size = 160,
    darkMode = true,
}: {
    value: number;
    size?: number;
    darkMode?: boolean;
}) {
    const outerRadius = size / 2;
    const innerRadius = outerRadius * 0.62;
    const innerPct =
        (innerRadius / outerRadius) * 100;

    const tickCount = 40;
    const tickWidth = 3;

    const lerp = (
        a: number,
        b: number,
        t: number
    ) => Math.round(a + (b - a) * t);

    const mixColor = (
        from: [number, number, number],
        to: [number, number, number],
        t: number
    ) =>
        `rgb(${lerp(
            from[0],
            to[0],
            t
        )}, ${lerp(
            from[1],
            to[1],
            t
        )}, ${lerp(from[2], to[2], t)})`;

    const ticks = Array.from(
        { length: tickCount + 1 },
        (_, i) => {
            const angle =
                -90 + (180 / tickCount) * i;

            const color =
                angle < 0
                    ? mixColor(
                        [220, 38, 38],
                        [254, 202, 202],
                        (angle + 90) / 90
                    )
                    : mixColor(
                        [191, 219, 254],
                        [37, 99, 235],
                        angle / 90
                    );

            return { angle, color };
        }
    );

    const markerAngles = [
        -90, -45, 0, 45, 90,
    ];

    return (
        <div
            className="relative mx-auto"
            style={{
                width: size,
                height: outerRadius + 34,
            }}
        >
            <div
                className="absolute left-0 top-0"
                style={{
                    width: size,
                    height: outerRadius,
                }}
            >
                {ticks.map((tick, index) => (
                    <div
                        key={index}
                        style={{
                            position: 'absolute',
                            left:
                                outerRadius -
                                tickWidth / 2,
                            bottom: 0,
                            width: tickWidth,
                            height: outerRadius,
                            borderRadius: 2,
                            background: `linear-gradient(to top, transparent 0%, transparent ${innerPct}%, ${tick.color} ${innerPct}%, ${tick.color} 100%)`,
                            transformOrigin:
                                '50% 100%',
                            transform: `rotate(${tick.angle}deg)`,
                        }}
                    />
                ))}

                {markerAngles.map(
                    (angle) => {
                        const rad =
                            (angle * Math.PI) / 180;

                        const markerRadius =
                            outerRadius + 9;

                        const x =
                            outerRadius +
                            markerRadius *
                            Math.sin(rad);

                        const y =
                            outerRadius -
                            markerRadius *
                            Math.cos(rad);

                        return (
                            <span
                                key={angle}
                                className={`absolute text-[9px] ${darkMode
                                    ? 'text-[#53645e]'
                                    : 'text-[#9aa8a3]'
                                    }`}
                                style={{
                                    left: x - 5,
                                    top: y - 6,
                                    transform: `rotate(${angle}deg)`,
                                }}
                            >
                                ▲
                            </span>
                        );
                    }
                )}
            </div>

            <div
                className="absolute left-0 w-full text-center"
                style={{
                    top: outerRadius + 4,
                }}
            >
                <p className="text-2xl font-black text-emerald-400">
                    {Math.round(value)}%
                </p>
            </div>
        </div>
    );
}

/* =========================================================
   APP
========================================================= */

export default function App() {
    /* =======================================================
       AUTH STATE
    ======================================================= */

    const [isLoggedIn, setIsLoggedIn] = useState(false);

    const [userEmail, setUserEmail] =
        useState('');

    const [userPhone, setUserPhone] =
        useState('');

    const [authMode, setAuthMode] =
        useState<'login' | 'signup'>('login');

    const [authMethod, setAuthMethod] =
        useState<AuthMethod>('email');

    const [email, setEmail] =
        useState('');

    const [password, setPassword] =
        useState('');

    const [authLoading, setAuthLoading] =
        useState(false);

    const [authError, setAuthError] =
        useState('');

    const [authSuccess, setAuthSuccess] =
        useState('');

    /* =======================================================
       SESSION CHECK
    ======================================================= */

    useEffect(() => {
        let mounted = true;

        const loadSession = async () => {
            try {
                const {
                    data,
                    error,
                } = await supabase.auth.getSession();

                if (error) {
                    console.error(
                        'Supabase session error:',
                        error
                    );

                    return;
                }

                if (!mounted) return;

                const session = data.session;

                if (session) {
                    setIsLoggedIn(true);

                    setUserEmail(
                        session.user.email || ''
                    );

                    setUserPhone(
                        session.user.phone || ''
                    );
                }
            } catch (error) {
                console.error(
                    'Session fetch failed:',
                    error
                );
            }
        };

        loadSession();

        const {
            data: authListener,
        } =
            supabase.auth.onAuthStateChange(
                (_event, session) => {
                    if (!mounted) return;

                    if (session) {
                        setIsLoggedIn(true);

                        setUserEmail(
                            session.user.email || ''
                        );

                        setUserPhone(
                            session.user.phone || ''
                        );
                    } else {
                        setIsLoggedIn(false);
                        setUserEmail('');
                        setUserPhone('');
                    }
                }
            );

        return () => {
            mounted = false;
            authListener.subscription.unsubscribe();
        };
    }, []);

    /* =======================================================
       DASHBOARD
    ======================================================= */

    const [activeTab, setActiveTab] =
        useState<Tab>('overview');

    const [darkMode, setDarkMode] =
        useState(true);

    const [sidebarOpen, setSidebarOpen] =
        useState(true);

    /* =======================================================
       SETTINGS
    ======================================================= */

    const [emailAlerts, setEmailAlerts] =
        useState(true);

    const [pushAlerts, setPushAlerts] =
        useState(true);

    const [autoReport, setAutoReport] =
        useState(false);

    /* =======================================================
       SCANNER
    ======================================================= */

    const [textInput, setTextInput] =
        useState('');

    const [selectedFile, setSelectedFile] =
        useState<File | null>(null);

    const [loading, setLoading] =
        useState(false);

    const [result, setResult] =
        useState<any>(null);

    const [error, setError] =
        useState('');

    /* =======================================================
       LIVE SYSTEM
    ======================================================= */

    const [systemPulse, setSystemPulse] =
        useState(98.7);

    const [liveThreats, setLiveThreats] =
        useState(128);

    const [blockedToday, setBlockedToday] =
        useState(114);

    const [chartData, setChartData] =
        useState(initialThreatData);

    /* =======================================================
       INCIDENTS
    ======================================================= */

    const [recentIncidents, setRecentIncidents] =
        useState([
            {
                id: 'INC-4821',
                title:
                    'Authority impersonation pattern detected',
                source:
                    'WhatsApp message',
                time: '2 min ago',
                risk: 'CRITICAL' as RiskLevel,
                score: 96,
            },

            {
                id: 'INC-4819',
                title:
                    'Digital arrest intimidation language',
                source:
                    'SMS content',
                time: '11 min ago',
                risk: 'HIGH' as RiskLevel,
                score: 89,
            },
        ]);

    const [i4cReported, setI4cReported] =
        useState(false);

    const [i4cTrackingId, setI4cTrackingId] =
        useState('');

    const fileInputRef =
        useRef<HTMLInputElement>(null);

    // ── Link Scanner State ──
    const [linkUrl, setLinkUrl] = useState<string>('');
    const [isScanningLink, setIsScanningLink] = useState<boolean>(false);
    const [linkResult, setLinkResult] = useState<LinkAnalysisResult | null>(null);
    const [linkError, setLinkError] = useState<string | null>(null);

    const handleScanLink = async (e?: React.FormEvent) => {
        if (e) e.preventDefault();
        if (!linkUrl || !linkUrl.trim()) return;

        try {
            setIsScanningLink(true);
            setLinkError(null);
            setLinkResult(null);
            const res = await analyzeLink(linkUrl.trim());
            if (res.success && res.data) {
                setLinkResult(res.data);
            } else {
                setLinkError(res.error || 'Link analysis failed');
            }
        } catch (err: any) {
            console.error('Error in handleScanLink:', err);
            setLinkError(err.message || 'Error executing link analysis');
        } finally {
            setIsScanningLink(false);
        }
    };

    /* =======================================================
       FETCH INCIDENTS
    ======================================================= */

    const fetchRecentIncidents =
        async () => {
            try {
                const response =
                    await fetch(
                        `${getApiBaseUrl()}/api/v1/scans/recent`
                    );

                if (!response.ok) {
                    throw new Error(
                        `Backend returned ${response.status}`
                    );
                }

                const data =
                    await response.json();

                if (
                    Array.isArray(data) &&
                    data.length > 0
                ) {
                    setRecentIncidents(data);
                }
            } catch (error) {
                console.warn(
                    'Recent incidents unavailable. Using local fallback.'
                );
            }
        };

    /* =======================================================
       LIVE LOOP
    ======================================================= */

    useEffect(() => {
        if (!isLoggedIn) return;

        fetchRecentIncidents();

        const interval =
            setInterval(() => {
                setLiveThreats(
                    (previous) =>
                        Math.max(
                            120,
                            previous +
                            (Math.random() > 0.65
                                ? 1
                                : 0)
                        )
                );

                setBlockedToday(
                    (previous) =>
                        Math.max(
                            100,
                            previous +
                            (Math.random() > 0.72
                                ? 1
                                : 0)
                        )
                );

                setSystemPulse(
                    Number(
                        (
                            98.4 +
                            Math.random() * 1.4
                        ).toFixed(1)
                    )
                );

                setChartData(
                    (previousData) => {
                        const updated = [
                            ...previousData,
                        ];

                        const lastIndex =
                            updated.length - 1;

                        const currentThreats =
                            updated[lastIndex]
                                .threats;

                        const delta =
                            Math.floor(
                                Math.random() * 7
                            ) - 3;

                        const newThreats =
                            Math.max(
                                10,
                                currentThreats + delta
                            );

                        updated[lastIndex] = {
                            ...updated[lastIndex],

                            threats:
                                newThreats,

                            blocked:
                                Math.max(
                                    5,
                                    newThreats -
                                    Math.floor(
                                        Math.random() *
                                        8
                                    )
                                ),
                        };

                        return updated;
                    }
                );
            }, 3000);

        return () =>
            clearInterval(interval);
    }, [isLoggedIn]);

    /* =======================================================
       EMAIL AUTH
    ======================================================= */

    const handleAuthSubmit =
        async (
            event: React.FormEvent
        ) => {
            event.preventDefault();

            setAuthError('');
            setAuthSuccess('');

            if (!email.trim()) {
                setAuthError(
                    'Please enter your email address.'
                );

                return;
            }

            if (!password) {
                setAuthError(
                    'Please enter your password.'
                );

                return;
            }

            if (password.length < 6) {
                setAuthError(
                    'Password must contain at least 6 characters.'
                );

                return;
            }

            try {
                setAuthLoading(true);

                if (
                    authMode === 'login'
                ) {
                    const {
                        error,
                    } =
                        await supabase.auth.signInWithPassword(
                            {
                                email:
                                    email.trim(),
                                password,
                            }
                        );

                    if (error) {
                        setAuthError(
                            error.message
                        );

                        return;
                    }

                    setAuthSuccess(
                        'Login successful.'
                    );
                } else {
                    const {
                        data,
                        error,
                    } =
                        await supabase.auth.signUp(
                            {
                                email:
                                    email.trim(),
                                password,
                            }
                        );

                    if (error) {
                        setAuthError(
                            error.message
                        );

                        return;
                    }

                    if (
                        data.session
                    ) {
                        setAuthSuccess(
                            'Account created successfully.'
                        );
                    } else {
                        setAuthSuccess(
                            'Account created. Please verify your email before logging in.'
                        );
                    }
                }
            } catch (error: any) {
                console.error(
                    'Email authentication error:',
                    error
                );

                setAuthError(
                    error?.message ||
                    'Unable to connect to Supabase. Check your Supabase URL and key.'
                );
            } finally {
                setAuthLoading(false);
            }
        };

    /* =======================================================
       GOOGLE AUTH
    ======================================================= */

    const handleGoogleLogin =
        async () => {
            setAuthError('');
            setAuthSuccess('');

            try {
                setAuthLoading(true);

                const redirectUrl =
                    window.location.origin;

                const {
                    error,
                } =
                    await supabase.auth.signInWithOAuth(
                        {
                            provider:
                                'google',

                            options: {
                                redirectTo:
                                    redirectUrl,
                            },
                        }
                    );

                if (error) {
                    setAuthError(
                        error.message
                    );

                    setAuthLoading(false);
                }
            } catch (error: any) {
                console.error(
                    'Google authentication error:',
                    error
                );

                setAuthError(
                    error?.message ||
                    'Unable to start Google authentication.'
                );

                setAuthLoading(false);
            }
        };

    /* =======================================================
       AUTH METHOD
    ======================================================= */

    const changeAuthMethod =
        (
            method: AuthMethod
        ) => {
            setAuthMethod(method);

            setAuthError('');
            setAuthSuccess('');
        };

    /* =======================================================
       THEME
    ======================================================= */

    const bg =
        darkMode
            ? 'bg-[#07100f] text-[#e8eeea]'
            : 'bg-[#f4f7f6] text-[#17211f]';

    const panel =
        darkMode
            ? 'bg-[#0b1614] border-[#1d312d]'
            : 'bg-white border-[#dce7e3]';

    const panelSoft =
        darkMode
            ? 'bg-[#091210] border-[#172924]'
            : 'bg-[#f8faf9] border-[#e1ebe7]';

    const muted =
        darkMode
            ? 'text-[#82938e]'
            : 'text-[#72807b]';

    const title =
        darkMode
            ? 'text-[#eef5f1]'
            : 'text-[#15201d]';

    /* =======================================================
       SCAN RESULT
    ======================================================= */

    const scanResult =
        useMemo(() => {
            if (!result)
                return null;

            const score =
                result.risk_score ??
                result.riskScore ??
                result.score ??
                result.confidence ??
                0;

            const normalizedScore =
                score <= 1
                    ? Math.round(
                        score * 100
                    )
                    : Math.round(
                        score
                    );

            const risk =
                result.risk_level ??
                result.riskLevel ??
                result.verdict ??
                (
                    normalizedScore >= 85
                        ? 'CRITICAL'
                        : normalizedScore >= 65
                            ? 'HIGH'
                            : normalizedScore >= 40
                                ? 'MEDIUM'
                                : 'LOW'
                );

            const explanation =
                result.ai_explanation
                    ?.detailed_explanation ??
                result.ai_explanation ??
                result.explanation ??
                result.reason ??
                result.message ??
                'The analysis has been completed successfully.';

            const signals =
                result.detected_signals ??
                result.signals ??
                result.reasons ??
                [];

            return {
                score:
                    Math.min(
                        100,
                        Math.max(
                            0,
                            normalizedScore
                        )
                    ),

                risk:
                    String(
                        risk
                    ).toUpperCase(),

                explanation:
                    typeof explanation ===
                        'string'
                        ? explanation
                        : JSON.stringify(
                            explanation,
                            null,
                            2
                        ),

                signals:
                    Array.isArray(
                        signals
                    )
                        ? signals
                        : [],
            };
        }, [result]);

    /* =======================================================
       TEXT SCAN
    ======================================================= */

    const handleTextScan = async () => {
        if (!textInput.trim()) {
            setError('Please paste a suspicious message before starting the analysis.');
            return;
        }

        try {
            setLoading(true);
            setResult(null);
            setError('');
            setI4cReported(false);

            // Backend FastAPI + Groq AI API Call
            const data = await scanTextMessage(textInput);

            if (data && data.error) {
                setError(data.error);
            } else {
                setResult(data);
            }

            fetchRecentIncidents();
        } catch (error) {
            console.error(error);
            setError('Unable to analyze the message. Please check that your FastAPI backend is running.');
        } finally {
            setLoading(false);
        }
    };



    /* =======================================================
       IMAGE SCAN
    ======================================================= */

    const handleImageScan =
        async () => {
            if (!selectedFile) {
                setError(
                    'Please select a screenshot before starting the analysis.'
                );

                return;
            }

            try {
                setLoading(true);
                setResult(null);
                setError('');
                setI4cReported(false);

                const data =
                    await scanImageMessage(
                        selectedFile
                    );

                setResult(data);

                fetchRecentIncidents();
            } catch (error) {
                console.error(
                    error
                );

                setError(
                    'Unable to analyze the screenshot. Please check that your FastAPI backend is running.'
                );
            } finally {
                setLoading(false);
            }
        };

    /* =======================================================
       FILE SELECT
    ======================================================= */

    const handleFileChange =
        (
            event: React.ChangeEvent<HTMLInputElement>
        ) => {
            const file =
                event.target.files?.[0];

            if (!file)
                return;

            if (
                !file.type.startsWith(
                    'image/'
                )
            ) {
                setError(
                    'Please select a valid image file.'
                );

                return;
            }

            setSelectedFile(file);
            setError('');
            setResult(null);
        };

    /* =======================================================
       I4C REPORT
    ======================================================= */

    const handleReportToI4c =
        async () => {
            try {
                const response =
                    await fetch(
                        `${getApiBaseUrl()}/api/v1/i4c/report`,
                        {
                            method: 'POST',

                            headers: {
                                'Content-Type':
                                    'application/json',
                            },

                            body: JSON.stringify({
                                threat_text:
                                    textInput ||
                                    'Screenshot evidence analyzed',

                                risk_score:
                                    scanResult?.score ||
                                    85,

                                reported_by:
                                    userEmail ||
                                    userPhone ||
                                    'Analyst',
                            }),
                        }
                    );

                if (!response.ok) {
                    throw new Error(
                        `Backend returned ${response.status}`
                    );
                }

                const data =
                    await response.json();

                if (
                    data.status ===
                    'success'
                ) {
                    setI4cReported(true);

                    setI4cTrackingId(
                        data.i4c_tracking_id ||
                        `I4C-${Date.now()}`
                    );

                    return;
                }

                throw new Error(
                    'I4C report failed'
                );
            } catch (error) {
                console.error(
                    'I4C Dispatch Error:',
                    error
                );

                /*
                  DO NOT pretend the report was
                  actually delivered.
        
                  Generate a local reference only.
                */

                setI4cReported(true);

                setI4cTrackingId(
                    `LOCAL-${Date.now()}`
                );
            }
        };

    /* =======================================================
       PDF
    ======================================================= */

    const generatePDF =
        () => {
            const doc =
                new jsPDF();

            doc.setFontSize(
                20
            );

            doc.text(
                'Satrk - Cyber Threat Intelligence Report',
                10,
                20
            );

            doc.setFontSize(
                12
            );

            doc.text(
                'One Step Ahead of Every Scam',
                10,
                28
            );

            doc.text(
                `Incident ID: ${i4cTrackingId ||
                'PENDING'
                }`,
                10,
                40
            );

            doc.text(
                `Timestamp: ${new Date().toLocaleString()}`,
                10,
                50
            );

            doc.text(
                `Risk Score: ${scanResult?.score ??
                0
                }%`,
                10,
                60
            );

            doc.text(
                `Risk Level: ${scanResult?.risk ||
                'UNKNOWN'
                }`,
                10,
                70
            );

            doc.text(
                'AI Explanation:',
                10,
                90
            );

            doc.setFontSize(
                10
            );

            const splitExpl =
                doc.splitTextToSize(
                    scanResult?.explanation ||
                    '',
                    180
                );

            doc.text(
                splitExpl,
                10,
                100
            );

            doc.save(
                `Satrk_Threat_Report_${Date.now()}.pdf`
            );
        };

    /* =======================================================
       SAMPLE
    ======================================================= */

    const handleSample =
        () => {
            setTextInput(
                `This is Inspector Rajesh from CBI. Your Aadhaar has been linked to a money laundering case. You are under digital arrest and cannot contact anyone. Join this video call immediately or police action will be taken.`
            );

            setActiveTab(
                'scanner'
            );

            setResult(null);
            setError('');
        };

    /* =======================================================
       RESET
    ======================================================= */

    const resetScanner =
        () => {
            setResult(null);
            setTextInput('');
            setSelectedFile(null);
            setError('');
            setI4cReported(false);
            setI4cTrackingId('');
            setLinkUrl('');
            setLinkResult(null);
            setLinkError(null);

            if (
                fileInputRef.current
            ) {
                fileInputRef.current.value =
                    '';
            }
        };

    /* =======================================================
       NAVIGATION
    ======================================================= */

    const navItems = [
        {
            id: 'overview' as Tab,
            label: 'Command Center',
            icon: FiGrid,
        },

        {
            id: 'scanner' as Tab,
            label: 'Threat Scanner',
            icon: FiSearch,
        },

        {
            id: 'liveshield' as Tab,
            label: 'Live Cyber Shield',
            icon: FiShield,
        },

        {
            id: 'incidents' as Tab,
            label: 'Incidents',
            icon: FiAlertTriangle,
        },

        {
            id: 'intel' as Tab,
            label: 'Threat Intelligence',
            icon: FiLayers,
        },

        {
            id: 'settings' as Tab,
            label: 'Settings',
            icon: FiSettings,
        },
    ];

    /* =======================================================
       LOGIN PAGE
    ======================================================= */

    if (!isLoggedIn) {
        return (
            <div className="flex min-h-screen w-full bg-[#050c0a] overflow-hidden font-sans">

                {/* LEFT BRANDING */}

                <div className="hidden lg:flex w-1/2 items-center justify-center bg-[#07100f] border-r border-emerald-500/20 relative">

                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(16,185,129,0.08)_0,transparent_68%)] pointer-events-none" />

                    <div className="absolute inset-0 opacity-[0.025] bg-[linear-gradient(rgba(255,255,255,.8)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.8)_1px,transparent_1px)] bg-[size:40px_40px]" />

                    <div className="text-center p-12 relative z-10">

                        <div className="relative mx-auto mb-7 flex h-24 w-24 items-center justify-center rounded-[28px] border border-emerald-400/40 bg-emerald-500/10 shadow-[0_0_45px_rgba(16,185,129,0.25)]">

                            <FiShield className="text-5xl text-emerald-400" />

                            <span className="absolute right-1 top-1 h-3 w-3 rounded-full bg-emerald-400 shadow-[0_0_15px_#34d399] animate-pulse" />

                        </div>

                        <h1 className="text-6xl font-black tracking-tight text-[#eef5f1]">
                            Satrk
                        </h1>

                        <div className="mx-auto mt-3 h-px w-28 bg-gradient-to-r from-transparent via-emerald-400 to-transparent" />

                        <p className="mt-5 text-lg font-bold tracking-wide text-emerald-400">
                            One Step Ahead of Every Scam
                        </p>

                        <p className="mx-auto mt-5 max-w-md text-sm leading-relaxed text-[#82938e]">
                            AI-powered early detection against
                            digital arrest, authority impersonation
                            and social engineering scams.
                        </p>

                        <p className="mt-12 font-mono text-[9px] tracking-[0.25em] text-[#53645e]">
                            SATRK // SIH 2026 // CYBER DEFENSE
                        </p>

                    </div>
                </div>

                {/* RIGHT AUTH */}

                <div className="w-full lg:w-1/2 flex items-center justify-center p-5 sm:p-8 bg-[#050c0a] relative overflow-y-auto">

                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(16,185,129,0.06),transparent_45%)] pointer-events-none" />

                    <div className="w-full max-w-[470px] relative z-10">

                        <div className="rounded-[28px] border border-emerald-500/15 bg-[#091310]/95 p-6 sm:p-9 shadow-[0_0_60px_rgba(16,185,129,0.08)] backdrop-blur-xl">

                            {/* HEADER */}

                            <div className="mb-7">

                                <div className="flex items-center gap-2">

                                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />

                                    <span className="font-mono text-[9px] font-bold tracking-[0.18em] text-emerald-400">
                                        SECURE ACCESS
                                    </span>

                                </div>

                                <h2 className="mt-3 text-2xl font-black text-[#eef5f1]">
                                    {authMode ===
                                        'login'
                                        ? 'Welcome back'
                                        : 'Create your account'}
                                </h2>

                                <p className="mt-1 text-xs text-[#82938e]">
                                    {authMode ===
                                        'login'
                                        ? 'Access your Satrk cyber defense workspace.'
                                        : 'Create a secure identity for Satrk.'}
                                </p>

                            </div>

                            {/* AUTH METHOD TABS */}

                            <div className="mb-6 grid grid-cols-2 gap-1 rounded-xl border border-[#1d312d] bg-[#050c0a] p-1">

                                <button
                                    onClick={() =>
                                        changeAuthMethod(
                                            'email'
                                        )
                                    }
                                    className={`rounded-lg py-2.5 text-[10px] font-bold transition ${authMethod ===
                                        'email'
                                        ? 'bg-emerald-400 text-[#06100d]'
                                        : 'text-[#82938e] hover:text-emerald-400'
                                        }`}
                                >
                                    Email
                                </button>

                                <button
                                    onClick={() =>
                                        changeAuthMethod(
                                            'google'
                                        )
                                    }
                                    className={`rounded-lg py-2.5 text-[10px] font-bold transition ${authMethod ===
                                        'google'
                                        ? 'bg-emerald-400 text-[#06100d]'
                                        : 'text-[#82938e] hover:text-emerald-400'
                                        }`}
                                >
                                    Google
                                </button>

                            </div>

                            {/* ERROR */}

                            {authError && (
                                <div className="mb-4 rounded-xl border border-red-500/25 bg-red-500/10 p-3 text-xs text-red-400">
                                    {authError}
                                </div>
                            )}

                            {/* SUCCESS */}

                            {authSuccess && (
                                <div className="mb-4 rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3 text-xs text-emerald-400">
                                    {authSuccess}
                                </div>
                            )}

                            {/* =================================================
                  EMAIL AUTH
              ================================================= */}

                            {authMethod ===
                                'email' && (
                                    <form
                                        onSubmit={
                                            handleAuthSubmit
                                        }
                                        className="space-y-4"
                                    >

                                        <div>

                                            <label className="mb-2 block text-[9px] font-bold uppercase tracking-[0.15em] text-[#82938e]">
                                                Email Address
                                            </label>

                                            <div className="relative">

                                                <FiUser className="absolute left-4 top-1/2 -translate-y-1/2 text-[#53645e]" />

                                                <input
                                                    type="email"
                                                    value={email}
                                                    onChange={(
                                                        event
                                                    ) =>
                                                        setEmail(
                                                            event
                                                                .target
                                                                .value
                                                        )
                                                    }
                                                    placeholder="you@example.com"
                                                    autoComplete="email"
                                                    className="w-full rounded-xl border border-[#1d312d] bg-[#050c0a] py-3.5 pl-11 pr-4 text-xs text-[#e8eeea] outline-none transition focus:border-emerald-400/50"
                                                />

                                            </div>

                                        </div>

                                        <div>

                                            <label className="mb-2 block text-[9px] font-bold uppercase tracking-[0.15em] text-[#82938e]">
                                                Password
                                            </label>

                                            <div className="relative">

                                                <FiShield className="absolute left-4 top-1/2 -translate-y-1/2 text-[#53645e]" />

                                                <input
                                                    type="password"
                                                    value={password}
                                                    onChange={(
                                                        event
                                                    ) =>
                                                        setPassword(
                                                            event
                                                                .target
                                                                .value
                                                        )
                                                    }
                                                    placeholder="••••••••••••"
                                                    autoComplete={
                                                        authMode ===
                                                            'login'
                                                            ? 'current-password'
                                                            : 'new-password'
                                                    }
                                                    className="w-full rounded-xl border border-[#1d312d] bg-[#050c0a] py-3.5 pl-11 pr-4 text-xs text-[#e8eeea] outline-none transition focus:border-emerald-400/50"
                                                />

                                            </div>

                                        </div>

                                        <button
                                            type="submit"
                                            disabled={
                                                authLoading
                                            }
                                            className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-400 py-4 text-xs font-black uppercase tracking-wider text-[#06100d] transition hover:bg-emerald-300 disabled:opacity-50"
                                        >

                                            {authLoading ? (
                                                <>
                                                    <FiActivity className="animate-spin" />
                                                    Authenticating...
                                                </>
                                            ) : (
                                                <>
                                                    <FiShield />

                                                    {authMode ===
                                                        'login'
                                                        ? 'Secure login'
                                                        : 'Create account'}
                                                </>
                                            )}

                                        </button>

                                    </form>
                                )}

                            {/* =================================================
                  GOOGLE
              ================================================= */}

                            {authMethod ===
                                'google' && (
                                    <div className="space-y-5">

                                        <div className="rounded-2xl border border-[#1d312d] bg-[#050c0a] p-5 text-center">

                                            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-white">
                                                <GoogleIcon />
                                            </div>

                                            <h3 className="mt-4 text-sm font-bold text-[#eef5f1]">
                                                Continue with Google
                                            </h3>

                                            <p className="mx-auto mt-2 max-w-xs text-[11px] leading-relaxed text-[#82938e]">
                                                Use your Google account to securely access your Satrk workspace.
                                            </p>

                                        </div>

                                        <button
                                            onClick={
                                                handleGoogleLogin
                                            }
                                            disabled={
                                                authLoading
                                            }
                                            className="flex w-full items-center justify-center gap-3 rounded-xl border border-[#d7ddd9] bg-white py-3.5 text-xs font-bold text-[#1f2522] transition hover:bg-[#f1f4f2] disabled:opacity-50"
                                        >

                                            <GoogleIcon />

                                            {authLoading
                                                ? 'Connecting...'
                                                : 'Continue with Google'}

                                        </button>

                                    </div>
                                )}

                            {/* SWITCH LOGIN/SIGNUP */}

                            {(
                                <div className="mt-7 border-t border-[#1d312d] pt-6 text-center">

                                    <p className="text-xs text-[#82938e]">

                                        {authMode ===
                                            'login'
                                            ? "Don't have an account? "
                                            : 'Already have an account? '}

                                        <button
                                            onClick={() => {
                                                setAuthMode(
                                                    authMode ===
                                                        'login'
                                                        ? 'signup'
                                                        : 'login'
                                                );

                                                setAuthError(
                                                    ''
                                                );

                                                setAuthSuccess(
                                                    ''
                                                );
                                            }}
                                            className="font-bold text-emerald-400 hover:underline"
                                        >

                                            {authMode ===
                                                'login'
                                                ? 'Create a new account'
                                                : 'Back to secure login'}

                                        </button>

                                    </p>

                                </div>
                            )}

                        </div>

                    </div>

                </div>

            </div>
        );
    }

    /* =======================================================
       MAIN DASHBOARD
    ======================================================= */

    return (
        <div
            className={`min-h-screen ${bg} transition-colors duration-300`}
        >

            {/* BACKGROUND */}

            <div className="pointer-events-none fixed inset-0 overflow-hidden">

                <div className="absolute -top-32 -left-32 h-[500px] w-[500px] rounded-full bg-emerald-500/[0.035] blur-3xl" />

                <div className="absolute top-[30%] right-[-180px] h-[420px] w-[420px] rounded-full bg-emerald-500/[0.025] blur-3xl" />

            </div>

            <div className="relative flex min-h-screen">

                {/* =================================================
            SIDEBAR
        ================================================= */}

                <aside
                    className={`${sidebarOpen
                        ? 'w-[250px]'
                        : 'w-[78px]'
                        } hidden md:flex flex-col border-r ${darkMode
                            ? 'bg-[#091310]/95 border-[#1a2b27]'
                            : 'bg-white/95 border-[#dce7e3]'
                        } backdrop-blur-xl transition-all duration-300 sticky top-0 h-screen`}
                >

                    {/* BRAND */}

                    <div className="p-5 border-b border-inherit">

                        <div className="flex items-center gap-3">

                            <div className="relative flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-400/30 bg-emerald-500/10">

                                <FiShield className="text-xl text-emerald-400" />

                                <span className="absolute -right-1 -bottom-1 h-2.5 w-2.5 rounded-full border-2 border-[#091310] bg-emerald-400" />

                            </div>

                            {sidebarOpen && (
                                <div className="overflow-hidden">

                                    <h1
                                        className={`text-sm font-black tracking-[0.18em] ${title}`}
                                    >
                                        SATRK
                                    </h1>

                                    <p className="mt-0.5 text-[8px] tracking-[0.12em] text-emerald-400 whitespace-nowrap">
                                        ONE STEP AHEAD OF EVERY SCAM
                                    </p>

                                </div>
                            )}

                        </div>

                    </div>

                    {/* NAVIGATION */}

                    <div className="flex-1 px-3 py-6">

                        {sidebarOpen && (
                            <p
                                className={`mb-3 px-3 text-[10px] font-bold tracking-[0.16em] ${muted}`}
                            >
                                WORKSPACE
                            </p>
                        )}

                        <div className="space-y-1.5">

                            {navItems.map(
                                (
                                    item
                                ) => {
                                    const Icon =
                                        item.icon;

                                    const active =
                                        activeTab ===
                                        item.id;

                                    return (
                                        <button
                                            key={
                                                item.id
                                            }
                                            onClick={() =>
                                                setActiveTab(
                                                    item.id
                                                )
                                            }
                                            className={`w-full flex items-center ${sidebarOpen
                                                ? 'gap-3 px-3'
                                                : 'justify-center px-2'
                                                } rounded-xl py-3 text-sm transition-all ${active
                                                    ? 'border border-emerald-400/20 bg-emerald-500/10 text-emerald-300 shadow-[0_0_24px_rgba(16,185,129,0.05)]'
                                                    : `${muted} hover:bg-white/5 hover:text-emerald-200`
                                                }`}
                                        >

                                            <Icon className="shrink-0 text-lg" />

                                            {sidebarOpen && (
                                                <span>
                                                    {
                                                        item.label
                                                    }
                                                </span>
                                            )}

                                            {active &&
                                                sidebarOpen && (
                                                    <span className="ml-auto h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399]" />
                                                )}

                                        </button>
                                    );
                                }
                            )}

                        </div>

                    </div>

                    {/* ACCOUNT */}

                    <div className="space-y-1 border-t border-inherit p-3">

                        <div className="px-3 py-2 flex items-center justify-between">

                            {sidebarOpen && (
                                <div className="truncate">

                                    <p className="text-xs font-bold text-emerald-400 truncate">
                                        {userEmail ||
                                            userPhone ||
                                            'Analyst'}
                                    </p>

                                    <p className="text-[9px] text-[#82938e]">
                                        Active Analyst
                                    </p>

                                </div>
                            )}

                            <button
                                onClick={async () => {
                                    try {
                                        await supabase.auth.signOut();
                                    } catch (error) {
                                        console.error(
                                            'Sign out error:',
                                            error
                                        );
                                    }
                                }}
                                className={`p-2 rounded-xl border ${panelSoft} text-red-400 hover:bg-red-500/10 transition`}
                                title="Sign Out"
                            >

                                <FiLogOut size={14} />

                            </button>

                        </div>

                    </div>

                </aside>

                {/* =================================================
            MAIN
        ================================================= */}

                <main className="min-w-0 flex-1">

                    {/* HEADER */}

                    <header
                        className={`sticky top-0 z-30 flex h-[76px] items-center justify-between border-b px-5 backdrop-blur-xl md:px-8 ${darkMode
                            ? 'border-[#1a2b27] bg-[#07100f]/90'
                            : 'border-[#dce7e3] bg-white/90'
                            }`}
                    >

                        <div className="flex items-center gap-4">

                            <button
                                onClick={() =>
                                    setSidebarOpen(
                                        !sidebarOpen
                                    )
                                }
                                className={`hidden h-10 w-10 items-center justify-center rounded-xl border md:flex ${panelSoft} ${muted} transition hover:text-emerald-400`}
                            >
                                <FiMenu />
                            </button>

                            <div>

                                <div className="flex items-center gap-2">

                                    <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />

                                    <p className="font-mono text-[10px] tracking-[0.16em] text-emerald-400">
                                        SATRK LIVE DEFENSE NETWORK
                                    </p>

                                </div>

                                <h2
                                    className={`mt-1 text-sm font-bold md:text-base ${title}`}
                                >

                                    {activeTab ===
                                        'overview' &&
                                        'Command Center'}

                                    {activeTab ===
                                        'scanner' &&
                                        'Threat Analysis Workspace'}

                                    {activeTab ===
                                        'liveshield' &&
                                        'Live Cyber Shield & Audio Inspector'}

                                    {activeTab ===
                                        'incidents' &&
                                        'Incident Registry'}

                                    {activeTab ===
                                        'intel' &&
                                        'Threat Intelligence'}

                                    {activeTab ===
                                        'settings' &&
                                        'Settings'}

                                </h2>

                            </div>

                        </div>

                        <div className="flex items-center gap-2 md:gap-3">

                            <div className="hidden lg:flex items-center gap-2 rounded-xl border border-emerald-500/15 bg-emerald-500/5 px-3 py-2">

                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />

                                <span className="font-mono text-[9px] text-emerald-400">
                                    {systemPulse}%
                                </span>

                            </div>

                            <button
                                onClick={() =>
                                    setDarkMode(
                                        !darkMode
                                    )
                                }
                                className={`flex h-10 w-10 items-center justify-center rounded-xl border ${panelSoft} ${muted} transition hover:text-emerald-400`}
                                title="Toggle Theme"
                            >

                                {darkMode ? (
                                    <FiSun />
                                ) : (
                                    <FiMoon />
                                )}

                            </button>

                        </div>

                    </header>

                    {/* =================================================
              OVERVIEW
          ================================================= */}

                    {activeTab ===
                        'overview' && (
                            <div className="mx-auto max-w-[1500px] space-y-6 p-5 md:p-8">

                                <section
                                    className={`relative overflow-hidden rounded-3xl border p-6 md:p-8 ${panel}`}
                                >

                                    <div className="absolute right-[-100px] top-[-100px] h-[300px] w-[300px] rounded-full bg-emerald-500/5 blur-3xl" />

                                    <div className="relative">

                                        <div className="flex flex-col justify-between gap-6 lg:flex-row">

                                            <div>

                                                <p className="font-mono text-[9px] font-bold tracking-[0.2em] text-emerald-400">
                                                    EARLY THREAT DETECTION
                                                </p>

                                                <h1
                                                    className={`mt-3 text-2xl font-black tracking-tight md:text-4xl ${title}`}
                                                >
                                                    Detect the pressure.
                                                    <br />

                                                    <span className="text-emerald-400">
                                                        Break the deception chain.
                                                    </span>
                                                </h1>

                                                <p
                                                    className={`mt-4 max-w-2xl text-sm leading-relaxed ${muted}`}
                                                >
                                                    Satrk analyzes suspicious communication across four connected dimensions: content, claimed identity, contextual pressure, and recommended protective action.
                                                </p>

                                                <div className="mt-6 flex flex-wrap gap-3">

                                                    <button
                                                        onClick={() =>
                                                            setActiveTab(
                                                                'scanner'
                                                            )
                                                        }
                                                        className="rounded-xl bg-emerald-400 px-5 py-3 text-xs font-black text-[#06100d] transition hover:bg-emerald-300"
                                                    >
                                                        Open Threat Scanner
                                                    </button>

                                                    <button
                                                        onClick={
                                                            handleSample
                                                        }
                                                        className={`rounded-xl border px-5 py-3 text-xs font-bold ${panelSoft} ${muted} hover:text-emerald-400`}
                                                    >
                                                        Load Demo Threat
                                                    </button>

                                                </div>

                                            </div>

                                            <div className="grid grid-cols-2 gap-3 lg:w-[320px]">

                                                <div className={`rounded-2xl border p-4 ${panelSoft}`}>

                                                    <p className={`text-[9px] uppercase tracking-widest ${muted}`}>
                                                        Live Threats
                                                    </p>

                                                    <p className="mt-2 text-2xl font-black text-orange-400">
                                                        {liveThreats}
                                                    </p>

                                                </div>

                                                <div className={`rounded-2xl border p-4 ${panelSoft}`}>

                                                    <p className={`text-[9px] uppercase tracking-widest ${muted}`}>
                                                        Blocked
                                                    </p>

                                                    <p className="mt-2 text-2xl font-black text-emerald-400">
                                                        {blockedToday}
                                                    </p>

                                                </div>

                                                <div className={`col-span-2 rounded-2xl border p-4 ${panelSoft}`}>

                                                    <div className="flex items-center justify-between">

                                                        <p className={`text-[9px] uppercase tracking-widest ${muted}`}>
                                                            Defense Network
                                                        </p>

                                                        <span className="flex items-center gap-1 text-[9px] text-emerald-400">
                                                            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                                                            LIVE
                                                        </span>

                                                    </div>

                                                    <ArcGauge
                                                        value={systemPulse}
                                                        size={150}
                                                        darkMode={darkMode}
                                                    />

                                                </div>

                                            </div>

                                        </div>

                                    </div>

                                </section>



                                {/* CHART */}

                                <section
                                    className={`rounded-3xl border p-5 md:p-6 ${panel}`}
                                >

                                    <div className="mb-5 flex items-center justify-between">

                                        <div>

                                            <h2
                                                className={`text-sm font-black ${title}`}
                                            >
                                                Threat Activity
                                            </h2>

                                            <p
                                                className={`mt-1 text-[10px] ${muted}`}
                                            >
                                                Live simulated defense telemetry
                                            </p>

                                        </div>

                                        <FiActivity className="text-emerald-400" />

                                    </div>

                                    <div className="h-[280px]">

                                        <ResponsiveContainer
                                            width="100%"
                                            height="100%"
                                        >

                                            <AreaChart
                                                data={
                                                    chartData
                                                }
                                            >

                                                <defs>

                                                    <linearGradient
                                                        id="threatGradient"
                                                        x1="0"
                                                        y1="0"
                                                        x2="0"
                                                        y2="1"
                                                    >

                                                        <stop
                                                            offset="5%"
                                                            stopColor="#10b981"
                                                            stopOpacity={
                                                                0.3
                                                            }
                                                        />

                                                        <stop
                                                            offset="95%"
                                                            stopColor="#10b981"
                                                            stopOpacity={
                                                                0
                                                            }
                                                        />

                                                    </linearGradient>

                                                </defs>

                                                <CartesianGrid
                                                    strokeDasharray="3 3"
                                                    stroke={
                                                        darkMode
                                                            ? '#1d312d'
                                                            : '#dce7e3'
                                                    }
                                                />

                                                <XAxis
                                                    dataKey="time"
                                                    stroke="#82938e"
                                                    fontSize={
                                                        10
                                                    }
                                                />

                                                <YAxis
                                                    stroke="#82938e"
                                                    fontSize={
                                                        10
                                                    }
                                                />

                                                <Tooltip />

                                                <Area
                                                    type="monotone"
                                                    dataKey="threats"
                                                    stroke="#10b981"
                                                    fill="url(#threatGradient)"
                                                    strokeWidth={
                                                        2
                                                    }
                                                />

                                                <Area
                                                    type="monotone"
                                                    dataKey="blocked"
                                                    stroke="#34d399"
                                                    fill="transparent"
                                                    strokeWidth={
                                                        2
                                                    }
                                                />

                                            </AreaChart>

                                        </ResponsiveContainer>

                                    </div>

                                </section>

                            </div>
                        )}

                    {/* =================================================
              LIVE CYBER SHIELD
          ================================================= */}

                    {activeTab ===
                        'liveshield' && (
                            <div className="mx-auto max-w-[1500px] space-y-6 p-5 md:p-8">
                                <UnifiedCallProtection />
                            </div>
                        )}



                    {/* =================================================
              SCANNER
          ================================================= */}

                    {activeTab ===
                        'scanner' && (
                            <div className="mx-auto max-w-[1300px] p-5 md:p-8">

                                <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.25fr_0.75fr]">

                                    {/* INPUT */}

                                    <section
                                        className={`overflow-hidden rounded-3xl border ${panel} p-6`}
                                    >

                                        <div className="flex items-center justify-between">

                                            <div>

                                                <p className="font-mono text-[9px] tracking-[0.18em] text-emerald-400">
                                                    AI ANALYSIS ENGINE
                                                </p>

                                                <h2
                                                    className={`mt-2 text-xl font-black ${title}`}
                                                >
                                                    Threat Scanner
                                                </h2>

                                            </div>

                                            {result && (
                                                <button
                                                    onClick={
                                                        resetScanner
                                                    }
                                                    className="rounded-xl border border-[#1d312d] p-2 text-[#82938e] hover:text-red-400"
                                                    title="Reset"
                                                >
                                                    <FiX />
                                                </button>
                                            )}

                                        </div>

                                        <textarea
                                            value={
                                                textInput
                                            }
                                            onChange={(
                                                event
                                            ) =>
                                                setTextInput(
                                                    event
                                                        .target
                                                        .value
                                                )
                                            }
                                            placeholder="Paste suspicious message here..."
                                            className="mt-5 min-h-[190px] w-full resize-none rounded-xl border border-emerald-500/20 bg-black/20 p-4 text-sm text-white outline-none focus:border-emerald-400/50"
                                        />

                                        <div className="mt-4 flex flex-wrap gap-3">

                                            <button
                                                onClick={
                                                    handleTextScan
                                                }
                                                disabled={
                                                    loading
                                                }
                                                className="flex items-center gap-2 rounded-xl bg-emerald-400 px-5 py-3 text-xs font-black text-black transition hover:bg-emerald-300 disabled:opacity-50"
                                            >

                                                {loading ? (
                                                    <>
                                                        <FiActivity className="animate-spin" />
                                                        ANALYZING...
                                                    </>
                                                ) : (
                                                    <>
                                                        <FiSearch />
                                                        RUN AI ANALYSIS
                                                    </>
                                                )}

                                            </button>

                                            <button
                                                onClick={
                                                    handleSample
                                                }
                                                className={`rounded-xl border px-5 py-3 text-xs font-bold ${panelSoft} ${muted} hover:text-emerald-400`}
                                            >
                                                Demo Message
                                            </button>

                                        </div>

                                        <div className="my-6 flex items-center gap-3">

                                            <div className="h-px flex-1 bg-[#1d312d]" />

                                            <span className="text-[9px] font-bold tracking-widest text-[#53645e]">
                                                OR SCREENSHOT
                                            </span>

                                            <div className="h-px flex-1 bg-[#1d312d]" />

                                        </div>

                                        <input
                                            ref={
                                                fileInputRef
                                            }
                                            type="file"
                                            accept="image/*"
                                            onChange={
                                                handleFileChange
                                            }
                                            className="hidden"
                                        />

                                        <button
                                            onClick={() =>
                                                fileInputRef.current?.click()
                                            }
                                            className={`flex w-full items-center justify-center gap-3 rounded-xl border border-dashed py-5 ${panelSoft} ${muted} transition hover:border-emerald-400/40 hover:text-emerald-400`}
                                        >

                                            <FiUploadCloud className="text-xl" />

                                            <span className="text-xs font-bold">
                                                {selectedFile
                                                    ? selectedFile.name
                                                    : 'Upload suspicious screenshot'}
                                            </span>

                                        </button>

                                        {selectedFile && (
                                            <button
                                                onClick={
                                                    handleImageScan
                                                }
                                                disabled={
                                                    loading
                                                }
                                                className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-500/10 py-3 text-xs font-black text-emerald-400 disabled:opacity-50"
                                            >

                                                <FiImage />

                                                {loading
                                                    ? 'ANALYZING SCREENSHOT...'
                                                    : 'ANALYZE SCREENSHOT'}

                                            </button>
                                        )}

                                        {error && (
                                            <div className="mt-5 flex gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-xs text-red-400">

                                                <FiAlertCircle className="mt-0.5 shrink-0" />

                                                <span>
                                                    {error}
                                                </span>

                                            </div>
                                        )}

                                        {/* ── LINK SCANNER ── */}
                                        <div className="mt-6 pt-6 border-t border-[#1d312d]">
                                            <div className="flex items-center justify-between mb-4">
                                                <div className="flex items-center gap-2">
                                                    <FiLink className="text-lg text-emerald-400" />
                                                    <h3 className={`text-sm font-bold tracking-wider uppercase ${title}`}>
                                                        Link Scanner
                                                    </h3>
                                                </div>
                                                <span className="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full font-bold">
                                                    🛡️ GOOGLE SAFE BROWSING V4
                                                </span>
                                            </div>

                                            <form onSubmit={handleScanLink} className="space-y-3">
                                                <div className="relative w-full">
                                                    <FiLink className="absolute left-3.5 top-3.5 text-base text-[#82938e]" />
                                                    <input
                                                        type="url"
                                                        value={linkUrl}
                                                        onChange={(e) => setLinkUrl(e.target.value)}
                                                        placeholder="Paste suspicious URL (e.g. https://customs-penalty-verify.org)..."
                                                        className="w-full rounded-xl border border-emerald-500/20 bg-black/20 py-3 pl-10 pr-4 text-xs text-white placeholder-[#53645e] focus:border-emerald-400/50 focus:outline-none font-mono"
                                                    />
                                                </div>
                                                <button
                                                    type="submit"
                                                    disabled={isScanningLink || !linkUrl.trim()}
                                                    className="flex w-full items-center justify-center gap-2 rounded-xl bg-emerald-400 py-3 text-xs font-black text-black uppercase tracking-wider transition hover:bg-emerald-300 disabled:opacity-50 shadow-lg shadow-emerald-500/20"
                                                >
                                                    {isScanningLink ? (
                                                        <>
                                                            <FiActivity className="text-base animate-spin" />
                                                            SCANNING LINK...
                                                        </>
                                                    ) : (
                                                        <>
                                                            <FiShield className="text-base" />
                                                            SCAN LINK FOR THREATS
                                                        </>
                                                    )}
                                                </button>
                                            </form>

                                            {linkError && (
                                                <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300 flex items-center gap-3">
                                                    <FiAlertCircle className="text-lg shrink-0 text-red-400" />
                                                    <span>{linkError}</span>
                                                </div>
                                            )}

                                            {linkResult && (
                                                <div className={`mt-4 rounded-2xl border p-4 text-xs space-y-2 transition-all ${
                                                    linkResult.is_safe
                                                        ? 'border-emerald-500/40 bg-emerald-950/20 text-emerald-300'
                                                        : 'border-red-500/50 bg-red-950/40 text-red-300 shadow-lg shadow-red-500/20'
                                                }`}>
                                                    <div className="flex items-center justify-between">
                                                        <div className="flex items-center gap-2 font-mono font-bold">
                                                            {linkResult.is_safe ? (
                                                                <>
                                                                    <FiCheckCircle className="text-lg text-emerald-400" />
                                                                    <span className="text-emerald-400">LINK VERDICT: SAFE</span>
                                                                </>
                                                            ) : (
                                                                <>
                                                                    <FiAlertTriangle className="text-lg text-red-400 animate-bounce" />
                                                                    <span className="text-red-400 uppercase tracking-wider">MALICIOUS / PHISHING LINK DETECTED</span>
                                                                </>
                                                            )}
                                                        </div>
                                                        <span className="font-mono text-[10px] text-[#82938e] truncate max-w-[150px]">{linkResult.url}</span>
                                                    </div>
                                                    <p className="text-xs leading-relaxed text-[#c0cfc9]">{linkResult.details}</p>
                                                    {linkResult.threat_types && linkResult.threat_types.length > 0 && (
                                                        <div className="flex flex-wrap gap-2 pt-1">
                                                            {linkResult.threat_types.map((type, idx) => (
                                                                <span key={idx} className="rounded-lg bg-red-500/20 border border-red-500/40 px-2.5 py-1 font-mono text-[10px] font-bold text-red-300">
                                                                    🚨 {type}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>

                                    </section>

                                    {/* RESULT */}

                                    <section
                                        className={`rounded-3xl border ${panel} p-6`}
                                    >

                                        {!scanResult ? (
                                            <div className="flex h-full min-h-[420px] flex-col items-center justify-center text-center">

                                                <div className="flex h-20 w-20 items-center justify-center rounded-3xl border border-emerald-400/20 bg-emerald-500/5">

                                                    <FiShield className="text-4xl text-emerald-400/50" />

                                                </div>

                                                <h3
                                                    className={`mt-5 text-sm font-black ${title}`}
                                                >
                                                    Awaiting Threat Analysis
                                                </h3>

                                                <p
                                                    className={`mt-2 max-w-xs text-xs leading-relaxed ${muted}`}
                                                >
                                                    Paste a suspicious message or upload a screenshot to start the Satrk AI defense engine.
                                                </p>

                                            </div>
                                        ) : (
                                            <div>

                                                <div className="flex items-center justify-between">

                                                    <div>

                                                        <p className="font-mono text-[9px] tracking-widest text-emerald-400">
                                                            THREAT VERDICT
                                                        </p>

                                                        <h3
                                                            className={`mt-2 text-lg font-black ${title}`}
                                                        >
                                                            Analysis Complete
                                                        </h3>

                                                    </div>

                                                    <div
                                                        className={`rounded-xl border px-3 py-2 text-[10px] font-black ${getRiskStyle(
                                                            scanResult.risk
                                                        )}`}
                                                    >
                                                        {scanResult.risk}
                                                    </div>

                                                </div>

                                                {/* SCORE */}

                                                <div className="mt-8 flex justify-center">

                                                    <div
                                                        className="relative flex h-48 w-48 items-center justify-center rounded-full"
                                                        style={{
                                                            background: `conic-gradient(${getRiskColor(
                                                                scanResult.score
                                                            )} ${scanResult.score
                                                                }%, rgba(255,255,255,0.05) 0)`,
                                                        }}
                                                    >

                                                        <div
                                                            className={`flex h-40 w-40 flex-col items-center justify-center rounded-full ${darkMode
                                                                ? 'bg-[#0b1614]'
                                                                : 'bg-white'
                                                                }`}
                                                        >

                                                            <span
                                                                className="text-4xl font-black"
                                                                style={{
                                                                    color:
                                                                        getRiskColor(
                                                                            scanResult.score
                                                                        ),
                                                                }}
                                                            >
                                                                {
                                                                    scanResult.score
                                                                }%
                                                            </span>

                                                            <span
                                                                className={`mt-1 text-[9px] font-bold tracking-widest ${muted}`}
                                                            >
                                                                RISK SCORE
                                                            </span>

                                                        </div>

                                                    </div>

                                                </div>

                                                {/* SIGNALS */}

                                                <div className="mt-8">

                                                    <p className={`text-[9px] font-bold uppercase tracking-widest ${muted}`}>
                                                        Detected Signals
                                                    </p>

                                                    <div className="mt-3 space-y-2">

                                                        {scanResult
                                                            .signals
                                                            .length >
                                                            0 ? (
                                                            scanResult.signals
                                                                .slice(
                                                                    0,
                                                                    8
                                                                )
                                                                .map(
                                                                    (
                                                                        signal: any,
                                                                        index: number
                                                                    ) => {
                                                                        const sigText = typeof signal === 'string' ? signal : (signal.signal || signal.category || JSON.stringify(signal));
                                                                        const sigEvidence = typeof signal === 'object' && (signal.evidence || signal.description) ? (signal.evidence || signal.description) : '';

                                                                        return (
                                                                            <div
                                                                                key={
                                                                                    index
                                                                                }
                                                                                className={`rounded-xl border p-3 text-xs ${panelSoft}`}
                                                                            >
                                                                                <div className="flex gap-2">

                                                                                    <FiAlertTriangle className="mt-0.5 shrink-0 text-orange-400" />

                                                                                    <div>
                                                                                        <p className="font-bold">{sigText}</p>
                                                                                        {sigEvidence && <p className="mt-1 text-[11px] opacity-80">{sigEvidence}</p>}
                                                                                    </div>

                                                                                </div>
                                                                            </div>
                                                                        );
                                                                    }
                                                                )
                                                        ) : (
                                                            <div className={`rounded-xl border p-3 text-xs ${panelSoft}`}>
                                                                No individual signals returned by the engine.
                                                            </div>
                                                        )}

                                                    </div>

                                                </div>

                                                {/* EXPLANATION */}

                                                <div className="mt-6">

                                                    <p className={`text-[9px] font-bold uppercase tracking-widest ${muted}`}>
                                                        AI Explanation
                                                    </p>

                                                    <div className={`mt-3 whitespace-pre-line rounded-xl border p-4 text-xs leading-relaxed ${panelSoft}`}>
                                                        {
                                                            scanResult.explanation
                                                        }
                                                    </div>

                                                </div>

                                                {/* ACTIONS */}

                                                <div className="mt-5 flex flex-wrap gap-2">

                                                    <button
                                                        onClick={
                                                            handleReportToI4c
                                                        }
                                                        disabled={
                                                            i4cReported
                                                        }
                                                        className="flex items-center gap-2 rounded-xl bg-red-500/10 px-4 py-3 text-xs font-bold text-red-400 border border-red-500/20 disabled:opacity-50"
                                                    >

                                                        <FiAlertTriangle />

                                                        {i4cReported
                                                            ? 'Reported'
                                                            : 'Report to I4C'}

                                                    </button>

                                                    <button
                                                        onClick={
                                                            generatePDF
                                                        }
                                                        className="flex items-center gap-2 rounded-xl border border-emerald-400/20 bg-emerald-500/5 px-4 py-3 text-xs font-bold text-emerald-400"
                                                    >

                                                        <FiFileText />

                                                        Generate PDF

                                                    </button>

                                                </div>

                                                {i4cReported && (
                                                    <div className="mt-4 rounded-xl border border-emerald-400/20 bg-emerald-500/5 p-4">

                                                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">

                                                            <FiCheckCircle />

                                                            I4C Report Reference

                                                        </div>

                                                        <p className={`mt-2 font-mono text-[10px] ${muted}`}>
                                                            {i4cTrackingId}
                                                        </p>

                                                    </div>
                                                )}

                                            </div>
                                        )}

                                    </section>

                                </div>

                            </div>
                        )}

                    {/* =================================================
              INCIDENTS
          ================================================= */}

                    {activeTab ===
                        'incidents' && (
                            <div className="mx-auto max-w-[1300px] p-5 md:p-8">

                                <section
                                    className={`rounded-3xl border ${panel} p-6`}
                                >

                                    <div className="flex items-center justify-between">

                                        <div>

                                            <p className="font-mono text-[9px] tracking-widest text-emerald-400">
                                                SECURITY REGISTRY
                                            </p>

                                            <h2
                                                className={`mt-2 text-xl font-black ${title}`}
                                            >
                                                Recent Incidents
                                            </h2>

                                        </div>

                                        <FiAlertTriangle className="text-orange-400" />

                                    </div>

                                    <div className="mt-6 space-y-3">

                                        {recentIncidents.map(
                                            (
                                                incident
                                            ) => (
                                                <div
                                                    key={
                                                        incident.id
                                                    }
                                                    className={`rounded-2xl border p-4 ${panelSoft}`}
                                                >

                                                    <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

                                                        <div className="flex gap-3">

                                                            <div className="mt-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-orange-500/10">

                                                                <FiAlertTriangle className="text-orange-400" />

                                                            </div>

                                                            <div>

                                                                <p className={`text-sm font-bold ${title}`}>
                                                                    {
                                                                        incident.title
                                                                    }
                                                                </p>

                                                                <p className={`mt-1 text-[10px] ${muted}`}>
                                                                    {
                                                                        incident.source
                                                                    }{' '}
                                                                    •{' '}
                                                                    {
                                                                        incident.time
                                                                    }
                                                                </p>

                                                                <p className={`mt-2 font-mono text-[9px] ${muted}`}>
                                                                    {
                                                                        incident.id
                                                                    }
                                                                </p>

                                                            </div>

                                                        </div>

                                                        <div className="flex items-center gap-3">

                                                            <span
                                                                className={`rounded-lg border px-3 py-2 text-[9px] font-black ${getRiskStyle(
                                                                    incident.risk
                                                                )}`}
                                                            >
                                                                {
                                                                    incident.risk
                                                                }
                                                            </span>

                                                            <span className="font-mono text-sm font-black text-emerald-400">
                                                                {
                                                                    incident.score
                                                                }%
                                                            </span>

                                                        </div>

                                                    </div>

                                                </div>
                                            )
                                        )}

                                    </div>

                                </section>

                            </div>
                        )}

                    {/* =================================================
              THREAT INTELLIGENCE
          ================================================= */}

                    {activeTab ===
                        'intel' && (
                            <div className="mx-auto max-w-[1300px] p-5 md:p-8">

                                <section
                                    className={`rounded-3xl border ${panel} p-6`}
                                >

                                    <p className="font-mono text-[9px] tracking-widest text-emerald-400">
                                        THREAT INTELLIGENCE
                                    </p>

                                    <h2
                                        className={`mt-2 text-2xl font-black ${title}`}
                                    >
                                        Satrk Intelligence Layer
                                    </h2>

                                    <p
                                        className={`mt-3 max-w-3xl text-sm leading-relaxed ${muted}`}
                                    >
                                        Satrk correlates suspicious language, authority impersonation, urgency, intimidation, financial pressure and digital-arrest patterns to generate an explainable threat assessment.
                                    </p>

                                    <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-3">

                                        <div className={`rounded-2xl border p-5 ${panelSoft}`}>

                                            <FiShield className="text-emerald-400" />

                                            <h3
                                                className={`mt-4 text-sm font-black ${title}`}
                                            >
                                                Identity Analysis
                                            </h3>

                                            <p className={`mt-2 text-xs leading-relaxed ${muted}`}>
                                                Detects suspicious claims of police, CBI, RBI, government and other authority identities.
                                            </p>

                                        </div>

                                        <div className={`rounded-2xl border p-5 ${panelSoft}`}>

                                            <FiAlertTriangle className="text-orange-400" />

                                            <h3
                                                className={`mt-4 text-sm font-black ${title}`}
                                            >
                                                Pressure Detection
                                            </h3>

                                            <p className={`mt-2 text-xs leading-relaxed ${muted}`}>
                                                Identifies urgency, intimidation, threats, isolation and forced compliance patterns.
                                            </p>

                                        </div>

                                        <div className={`rounded-2xl border p-5 ${panelSoft}`}>

                                            <FiActivity className="text-emerald-400" />

                                            <h3
                                                className={`mt-4 text-sm font-black ${title}`}
                                            >
                                                Risk Reasoning
                                            </h3>

                                            <p className={`mt-2 text-xs leading-relaxed ${muted}`}>
                                                Combines multiple signals into an explainable risk score and actionable verdict.
                                            </p>

                                        </div>

                                    </div>

                                </section>

                            </div>
                        )}

                    {/* =================================================
              SETTINGS
          ================================================= */}

                    {activeTab ===
                        'settings' && (
                            <div className="mx-auto max-w-[1300px] p-5 md:p-8">

                                <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">

                                    {/* ACCOUNT */}

                                    <section
                                        className={`rounded-3xl border p-6 lg:col-span-1 ${panel}`}
                                    >

                                        <p className="font-mono text-[9px] tracking-widest text-emerald-400">
                                            ACCOUNT
                                        </p>

                                        <h2
                                            className={`mt-2 text-lg font-black ${title}`}
                                        >
                                            Analyst Profile
                                        </h2>

                                        <div className={`mt-5 flex items-center gap-3 rounded-2xl border p-4 ${panelSoft}`}>

                                            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400">
                                                <FiUser />
                                            </div>

                                            <div className="min-w-0">

                                                <p className={`truncate text-xs font-bold ${title}`}>
                                                    {userEmail ||
                                                        userPhone ||
                                                        'Analyst'}
                                                </p>

                                                <p className={`text-[10px] ${muted}`}>
                                                    Security Analyst
                                                </p>

                                            </div>

                                        </div>

                                        <button
                                            onClick={async () => {
                                                try {
                                                    await supabase.auth.signOut();
                                                } catch (error) {
                                                    console.error(
                                                        'Sign out error:',
                                                        error
                                                    );
                                                }
                                            }}
                                            className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl border border-red-500/20 bg-red-500/10 py-3 text-xs font-bold text-red-400 transition hover:bg-red-500/15"
                                        >
                                            <FiLogOut />
                                            Log out
                                        </button>

                                    </section>

                                    {/* PREFERENCES */}

                                    <section
                                        className={`rounded-3xl border p-6 lg:col-span-2 ${panel}`}
                                    >

                                        <p className="font-mono text-[9px] tracking-widest text-emerald-400">
                                            PREFERENCES
                                        </p>

                                        <h2
                                            className={`mt-2 text-lg font-black ${title}`}
                                        >
                                            Workspace Settings
                                        </h2>

                                        <div className="mt-5 space-y-3">

                                            <div className={`flex items-center justify-between rounded-2xl border p-4 ${panelSoft}`}>

                                                <div>

                                                    <p className={`text-xs font-bold ${title}`}>
                                                        Appearance
                                                    </p>

                                                    <p className={`mt-1 text-[10px] ${muted}`}>
                                                        Switch between dark and light workspace themes.
                                                    </p>

                                                </div>

                                                <button
                                                    onClick={() =>
                                                        setDarkMode(
                                                            !darkMode
                                                        )
                                                    }
                                                    className={`flex items-center gap-2 rounded-xl border px-4 py-2.5 text-[10px] font-bold transition ${panelSoft} ${muted} hover:text-emerald-400`}
                                                >

                                                    {darkMode ? (
                                                        <>
                                                            <FiMoon />
                                                            Dark
                                                        </>
                                                    ) : (
                                                        <>
                                                            <FiSun />
                                                            Light
                                                        </>
                                                    )}

                                                </button>

                                            </div>

                                            <div className={`flex items-center justify-between rounded-2xl border p-4 ${panelSoft}`}>

                                                <div>

                                                    <p className={`text-xs font-bold ${title}`}>
                                                        Email Alerts
                                                    </p>

                                                    <p className={`mt-1 text-[10px] ${muted}`}>
                                                        Get notified by email when a critical threat is detected.
                                                    </p>

                                                </div>

                                                <button
                                                    onClick={() =>
                                                        setEmailAlerts(
                                                            !emailAlerts
                                                        )
                                                    }
                                                    className={`relative h-6 w-11 shrink-0 rounded-full transition ${emailAlerts
                                                        ? 'bg-emerald-400'
                                                        : darkMode
                                                            ? 'bg-[#1d312d]'
                                                            : 'bg-[#dce7e3]'
                                                        }`}
                                                >

                                                    <span
                                                        className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${emailAlerts
                                                            ? 'left-[22px]'
                                                            : 'left-0.5'
                                                            }`}
                                                    />

                                                </button>

                                            </div>

                                            <div className={`flex items-center justify-between rounded-2xl border p-4 ${panelSoft}`}>

                                                <div>

                                                    <p className={`text-xs font-bold ${title}`}>
                                                        Push Notifications
                                                    </p>

                                                    <p className={`mt-1 text-[10px] ${muted}`}>
                                                        Show live browser alerts for high-risk scans.
                                                    </p>

                                                </div>

                                                <button
                                                    onClick={() =>
                                                        setPushAlerts(
                                                            !pushAlerts
                                                        )
                                                    }
                                                    className={`relative h-6 w-11 shrink-0 rounded-full transition ${pushAlerts
                                                        ? 'bg-emerald-400'
                                                        : darkMode
                                                            ? 'bg-[#1d312d]'
                                                            : 'bg-[#dce7e3]'
                                                        }`}
                                                >

                                                    <span
                                                        className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${pushAlerts
                                                            ? 'left-[22px]'
                                                            : 'left-0.5'
                                                            }`}
                                                    />

                                                </button>

                                            </div>

                                            <div className={`flex items-center justify-between rounded-2xl border p-4 ${panelSoft}`}>

                                                <div>

                                                    <p className={`text-xs font-bold ${title}`}>
                                                        Auto-report to I4C
                                                    </p>

                                                    <p className={`mt-1 text-[10px] ${muted}`}>
                                                        Automatically file an I4C report for CRITICAL risk scans.
                                                    </p>

                                                </div>

                                                <button
                                                    onClick={() =>
                                                        setAutoReport(
                                                            !autoReport
                                                        )
                                                    }
                                                    className={`relative h-6 w-11 shrink-0 rounded-full transition ${autoReport
                                                        ? 'bg-emerald-400'
                                                        : darkMode
                                                            ? 'bg-[#1d312d]'
                                                            : 'bg-[#dce7e3]'
                                                        }`}
                                                >

                                                    <span
                                                        className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${autoReport
                                                            ? 'left-[22px]'
                                                            : 'left-0.5'
                                                            }`}
                                                    />

                                                </button>

                                            </div>

                                        </div>

                                    </section>

                                </div>

                            </div>
                        )}

                </main>

            </div>

        </div>
    );
}