import { useState } from 'react';
import {
    FiAlertCircle,
    FiArrowLeft,
    FiCheck,
    FiLock,
    FiMail,
    FiPhone,
    FiShield,
} from 'react-icons/fi';

import { supabase } from '../supabase';

type AuthMode = 'login' | 'signup' | 'phone' | 'otp';

export default function Auth() {
    const [mode, setMode] = useState<AuthMode>('login');

    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');

    const [phone, setPhone] = useState('');
    const [otp, setOtp] = useState('');

    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');

    const resetStatus = () => {
        setError('');
        setMessage('');
    };

    // =========================
    // EMAIL SIGN UP
    // =========================

    const handleSignup = async () => {
        resetStatus();

        if (!name.trim()) {
            setError('Please enter your full name.');
            return;
        }

        if (!email.trim()) {
            setError('Please enter your email address.');
            return;
        }

        if (password.length < 6) {
            setError('Password must contain at least 6 characters.');
            return;
        }

        try {
            setLoading(true);

            const { error } = await supabase.auth.signUp({
                email: email.trim(),
                password,
                options: {
                    data: {
                        full_name: name.trim(),
                    },
                },
            });

            if (error) {
                setError(error.message);
                return;
            }

            setMessage(
                'Account created successfully. Please check your email to verify your account.'
            );
        } catch {
            setError('Unable to create account. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // =========================
    // REAL EMAIL LOGIN
    // =========================

    const handleLogin = async () => {
        resetStatus();

        if (!email.trim() || !password) {
            setError('Please enter your email and password.');
            return;
        }

        try {
            setLoading(true);

            const { error } =
                await supabase.auth.signInWithPassword({
                    email: email.trim(),
                    password,
                });

            if (error) {
                setError(
                    'Invalid email or password. Please check your credentials.'
                );
                return;
            }

            // No fake setLoggedIn(true)
            // Supabase creates the real session automatically.
        } catch {
            setError('Unable to login. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // =========================
    // REAL GOOGLE LOGIN
    // =========================

    const handleGoogleLogin = async () => {
        resetStatus();

        try {
            setLoading(true);

            const { error } =
                await supabase.auth.signInWithOAuth({
                    provider: 'google',
                    options: {
                        redirectTo: window.location.origin,
                    },
                });

            if (error) {
                setError(error.message);
            }

        } catch {
            setError('Google authentication failed.');
            setLoading(false);
        }
    };

    // =========================
    // SEND REAL PHONE OTP
    // =========================

    const handleSendOTP = async () => {
        resetStatus();

        if (!phone.trim()) {
            setError(
                'Please enter your phone number with country code. Example: +919876543210'
            );
            return;
        }

        if (!phone.startsWith('+')) {
            setError(
                'Use international format with country code. Example: +919876543210'
            );
            return;
        }

        try {
            setLoading(true);

            const { error } = await supabase.auth.signInWithOtp({
                phone: phone.trim(),
            });

            if (error) {
                setError(error.message);
                return;
            }

            setMessage(
                'OTP sent successfully. Enter the exact OTP received on your phone.'
            );

            setMode('otp');

        } catch {
            setError('Unable to send OTP.');
        } finally {
            setLoading(false);
        }
    };

    // =========================
    // VERIFY REAL OTP
    // =========================

    const handleVerifyOTP = async () => {
        resetStatus();

        if (otp.length < 6) {
            setError('Please enter the complete OTP.');
            return;
        }

        try {
            setLoading(true);

            const { error } =
                await supabase.auth.verifyOtp({
                    phone: phone.trim(),
                    token: otp.trim(),
                    type: 'sms',
                });

            if (error) {
                setError(
                    'Invalid or expired OTP. Please enter the exact OTP sent to your phone.'
                );
                return;
            }

            // Real authentication successful
            // Session is now created by Supabase.

        } catch {
            setError('OTP verification failed.');
        } finally {
            setLoading(false);
        }
    };

    const inputClass =
        'w-full rounded-xl border border-[#1d312d] bg-[#07100f] px-4 py-3 text-sm text-[#e8eeea] outline-none transition placeholder:text-[#53645e] focus:border-emerald-400/50';

    return (
        <div className="min-h-screen bg-[#07100f] text-[#e8eeea] flex items-center justify-center p-5">

            <div className="pointer-events-none fixed inset-0 overflow-hidden">
                <div className="absolute -top-32 -left-32 w-[500px] h-[500px] rounded-full bg-emerald-500/[0.04] blur-3xl" />
                <div className="absolute bottom-[-180px] right-[-180px] w-[500px] h-[500px] rounded-full bg-cyan-500/[0.035] blur-3xl" />
            </div>

            <div className="relative w-full max-w-[460px]">

                {/* LOGO */}

                <div className="text-center mb-8">

                    <div className="mx-auto w-16 h-16 rounded-2xl border border-emerald-400/30 bg-emerald-500/10 flex items-center justify-center">
                        <FiShield className="text-emerald-400 text-3xl" />
                    </div>

                    <h1 className="mt-5 font-black tracking-[0.18em] text-xl">
                        SCAM<span className="text-cyan-400">GUARD</span>
                    </h1>

                    <p className="mt-2 text-[10px] tracking-[0.25em] text-emerald-400">
                        CYBER THREAT INTELLIGENCE
                    </p>

                </div>

                <div className="rounded-3xl border border-[#1d312d] bg-[#0b1614] p-6 md:p-8 shadow-2xl shadow-black/20">

                    {mode === 'login' && (
                        <>
                            <div className="mb-6">
                                <p className="text-[10px] font-mono tracking-[0.16em] text-emerald-400">
                                    SECURE ACCESS
                                </p>

                                <h2 className="mt-2 text-2xl font-black">
                                    Welcome back
                                </h2>

                                <p className="mt-2 text-xs text-[#82938e]">
                                    Sign in to access the ScamGuard intelligence network.
                                </p>
                            </div>

                            <div className="space-y-4">

                                <div>
                                    <label className="mb-2 block text-xs text-[#b7c5c0]">
                                        Email address
                                    </label>

                                    <div className="relative">
                                        <FiMail className="absolute left-4 top-1/2 -translate-y-1/2 text-[#82938e]" />

                                        <input
                                            type="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            placeholder="you@example.com"
                                            className={`${inputClass} pl-11`}
                                        />
                                    </div>
                                </div>

                                <div>
                                    <label className="mb-2 block text-xs text-[#b7c5c0]">
                                        Password
                                    </label>

                                    <div className="relative">
                                        <FiLock className="absolute left-4 top-1/2 -translate-y-1/2 text-[#82938e]" />

                                        <input
                                            type="password"
                                            value={password}
                                            onChange={(e) => setPassword(e.target.value)}
                                            placeholder="Enter your password"
                                            className={`${inputClass} pl-11`}
                                        />
                                    </div>
                                </div>

                                <button
                                    onClick={handleLogin}
                                    disabled={loading}
                                    className="w-full py-3.5 rounded-xl bg-emerald-400 text-[#06100d] font-bold text-sm hover:bg-emerald-300 disabled:opacity-50"
                                >
                                    {loading ? 'Authenticating...' : 'Secure Sign In'}
                                </button>

                                <div className="flex items-center gap-3 py-1">
                                    <div className="flex-1 h-px bg-[#1d312d]" />
                                    <span className="text-[10px] text-[#53645e]">OR CONTINUE WITH</span>
                                    <div className="flex-1 h-px bg-[#1d312d]" />
                                </div>

                                <button
                                    onClick={handleGoogleLogin}
                                    disabled={loading}
                                    className="w-full py-3 rounded-xl border border-[#1d312d] text-sm hover:border-emerald-400/30 hover:bg-emerald-500/5 transition disabled:opacity-50"
                                >
                                    Continue with Google
                                </button>

                                <button
                                    onClick={() => {
                                        resetStatus();
                                        setMode('phone');
                                    }}
                                    className="w-full py-3 rounded-xl border border-[#1d312d] text-sm text-cyan-400 hover:border-cyan-400/30"
                                >
                                    Continue with Phone OTP
                                </button>

                                <p className="pt-2 text-center text-xs text-[#82938e]">
                                    Don't have an account?{' '}
                                    <button
                                        onClick={() => {
                                            resetStatus();
                                            setMode('signup');
                                        }}
                                        className="text-emerald-400 font-semibold"
                                    >
                                        Create account
                                    </button>
                                </p>

                            </div>
                        </>
                    )}

                    {mode === 'signup' && (
                        <>
                            <button
                                onClick={() => setMode('login')}
                                className="mb-5 flex items-center gap-2 text-xs text-[#82938e]"
                            >
                                <FiArrowLeft />
                                Back to login
                            </button>

                            <h2 className="text-2xl font-black">
                                Create account
                            </h2>

                            <p className="mt-2 mb-6 text-xs text-[#82938e]">
                                Create your secure ScamGuard account.
                            </p>

                            <div className="space-y-4">

                                <input
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    placeholder="Full name"
                                    className={inputClass}
                                />

                                <input
                                    type="email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="Email address"
                                    className={inputClass}
                                />

                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Password (minimum 6 characters)"
                                    className={inputClass}
                                />

                                <button
                                    onClick={handleSignup}
                                    disabled={loading}
                                    className="w-full py-3.5 rounded-xl bg-emerald-400 text-[#06100d] font-bold disabled:opacity-50"
                                >
                                    {loading ? 'Creating account...' : 'Create Secure Account'}
                                </button>

                            </div>
                        </>
                    )}

                    {mode === 'phone' && (
                        <>
                            <button
                                onClick={() => setMode('login')}
                                className="mb-5 flex items-center gap-2 text-xs text-[#82938e]"
                            >
                                <FiArrowLeft />
                                Back
                            </button>

                            <FiPhone className="text-cyan-400 text-2xl mb-4" />

                            <h2 className="text-2xl font-black">
                                Phone verification
                            </h2>

                            <p className="mt-2 mb-6 text-xs text-[#82938e]">
                                We will send a real verification code to your phone.
                            </p>

                            <input
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                                placeholder="+919876543210"
                                className={inputClass}
                            />

                            <button
                                onClick={handleSendOTP}
                                disabled={loading}
                                className="mt-4 w-full py-3.5 rounded-xl bg-emerald-400 text-[#06100d] font-bold disabled:opacity-50"
                            >
                                {loading ? 'Sending OTP...' : 'Send Real OTP'}
                            </button>
                        </>
                    )}

                    {mode === 'otp' && (
                        <>
                            <button
                                onClick={() => setMode('phone')}
                                className="mb-5 flex items-center gap-2 text-xs text-[#82938e]"
                            >
                                <FiArrowLeft />
                                Change phone number
                            </button>

                            <FiCheck className="text-emerald-400 text-3xl mb-4" />

                            <h2 className="text-2xl font-black">
                                Verify OTP
                            </h2>

                            <p className="mt-2 mb-6 text-xs text-[#82938e]">
                                Enter the exact OTP sent to {phone}
                            </p>

                            <input
                                value={otp}
                                onChange={(e) =>
                                    setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))
                                }
                                placeholder="000000"
                                inputMode="numeric"
                                className={`${inputClass} text-center tracking-[0.5em] text-lg font-mono`}
                            />

                            <button
                                onClick={handleVerifyOTP}
                                disabled={loading}
                                className="mt-4 w-full py-3.5 rounded-xl bg-emerald-400 text-[#06100d] font-bold disabled:opacity-50"
                            >
                                {loading ? 'Verifying...' : 'Verify Real OTP'}
                            </button>
                        </>
                    )}

                    {error && (
                        <div className="mt-5 flex gap-2 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-300">
                            <FiAlertCircle className="shrink-0" />
                            {error}
                        </div>
                    )}

                    {message && (
                        <div className="mt-5 flex gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-emerald-300">
                            <FiCheck className="shrink-0" />
                            {message}
                        </div>
                    )}

                </div>
            </div>
        </div>
    );
}
