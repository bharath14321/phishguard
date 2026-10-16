import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { auth } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { Shield, KeyRound, ArrowRight, Loader2, AlertCircle, CheckCircle2, RotateCw, ArrowLeft } from 'lucide-react';

const OTP_LENGTH = 6;
const DEFAULT_COOLDOWN = 30; // 30 seconds

// Safe email masking utility
const maskEmail = (emailStr) => {
  if (!emailStr || typeof emailStr !== 'string' || !emailStr.includes('@')) {
    return 'your registered email';
  }
  const [local, domain] = emailStr.split('@');
  if (local.length <= 2) {
    return `${local[0]}*@${domain}`;
  }
  const maskedLocal = `${local[0]}***${local.slice(-1)}`;
  return `${maskedLocal}@${domain}`;
};

const Verify = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  // Retrieve email from navigation state or fallback
  const [email, setEmail] = useState(location.state?.email || '');
  const [otp, setOtp] = useState(Array(OTP_LENGTH).fill(''));
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [resendTimer, setResendTimer] = useState(DEFAULT_COOLDOWN); // Starts at 30s upon arriving from signup
  const [isVerifiedSuccess, setIsVerifiedSuccess] = useState(false);

  const inputRefs = useRef([]);

  // Resend Countdown Timer (1s ticks down to 0)
  useEffect(() => {
    let interval = null;
    if (resendTimer > 0) {
      interval = setInterval(() => {
        setResendTimer((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [resendTimer]);

  // Focus first input on initial mount
  useEffect(() => {
    if (inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, []);

  // Handle individual digit typing
  const handleDigitChange = (e, index) => {
    const rawVal = e.target.value;
    const digit = rawVal.replace(/\D/g, '').slice(-1); // Only allow numeric digit

    const newOtp = [...otp];
    newOtp[index] = digit;
    setOtp(newOtp);
    if (errorMessage) setErrorMessage('');
    if (successMessage) setSuccessMessage('');

    // Advance focus to next input if digit entered
    if (digit && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  // Handle backspace navigation
  const handleKeyDown = (e, index) => {
    if (e.key === 'Backspace') {
      if (!otp[index] && index > 0) {
        inputRefs.current[index - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      inputRefs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < OTP_LENGTH - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  // Handle paste full 6-digit code
  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').trim().replace(/\D/g, '').slice(0, OTP_LENGTH);
    if (!pastedData) return;

    const newOtp = Array(OTP_LENGTH).fill('');
    for (let i = 0; i < pastedData.length; i++) {
      newOtp[i] = pastedData[i];
    }
    setOtp(newOtp);
    if (errorMessage) setErrorMessage('');
    if (successMessage) setSuccessMessage('');

    const targetFocus = Math.min(pastedData.length, OTP_LENGTH - 1);
    inputRefs.current[targetFocus]?.focus();
  };

  // Submit OTP Verification
  const handleVerify = async (e) => {
    if (e) e.preventDefault();

    if (!email) {
      setErrorMessage('Missing registration email. Please re-enter your email or sign up again.');
      return;
    }

    const fullCode = otp.join('');
    if (fullCode.length !== OTP_LENGTH) {
      setErrorMessage('Please enter the full 6-digit verification code.');
      return;
    }

    setLoading(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      const response = await auth.verifyOtp({
        email: email.trim(),
        otp: fullCode,
      });

      setIsVerifiedSuccess(true);
      setSuccessMessage('Email verified successfully! Redirecting to sign in…');

      // If response also contained an access token, log them in directly
      if (response?.access_token) {
        login(response.access_token);
        setTimeout(() => {
          navigate('/dashboard');
        }, 1200);
      } else {
        // Otherwise direct to login
        setTimeout(() => {
          navigate('/login', { state: { verified: true, email: email.trim() } });
        }, 1500);
      }
    } catch (err) {
      const errDetail = err?.data?.detail?.error || err?.data?.detail;
      const errorCode = errDetail?.code || (typeof errDetail === 'string' ? errDetail : null);
      const errMsg = errDetail?.message || (typeof errDetail === 'string' ? errDetail : err.message || 'Verification failed. Please check your code.');

      setErrorMessage(errMsg);
    } finally {
      setLoading(false);
    }
  };

  // In-place Resend OTP handler (NEVER navigates away)
  const handleResendOtp = async () => {
    if (resendTimer > 0 || resending) return;

    if (!email) {
      setErrorMessage('Email address is missing. Please return to sign up.');
      return;
    }

    setResending(true);
    setErrorMessage('');
    setSuccessMessage('');

    try {
      await auth.resendOtp({ email: email.trim() });
      setSuccessMessage('A new 6-digit verification code has been dispatched to your email.');
      setResendTimer(DEFAULT_COOLDOWN); // Reset 30s countdown
      setOtp(Array(OTP_LENGTH).fill('')); // Clear boxes
      inputRefs.current[0]?.focus();
    } catch (err) {
      const errDetail = err?.data?.detail?.error || err?.data?.detail;
      const errorCode = errDetail?.code || (typeof errDetail === 'string' ? errDetail : null);
      const errMsg = errDetail?.message || (typeof errDetail === 'string' ? errDetail : err.message || 'Failed to resend code.');

      if (errorCode === 'OTP_RESEND_TOO_SOON') {
        // Parse remaining seconds from message if present or default
        const match = errMsg.match(/wait (\d+) seconds/i);
        const serverSeconds = match ? parseInt(match[1], 10) : 30;
        setResendTimer(serverSeconds);
        setErrorMessage(errMsg);
      } else if (errorCode === 'EMAIL_DELIVERY_FAILED') {
        setErrorMessage("We couldn't deliver a new verification code. Please check your email configuration or try again.");
      } else {
        setErrorMessage(errMsg);
      }
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center bg-slate-50 dark:bg-slate-950 px-4 py-12 transition-colors">
      <div className="w-full max-w-md">
        {/* Card Header & Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-800/50 mb-3 shadow-xs">
            <KeyRound className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Verify your email
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Enter the 6-digit verification code sent to{' '}
            <span className="font-semibold text-slate-800 dark:text-slate-200">
              {maskEmail(email)}
            </span>
          </p>
        </div>

        {/* Verification Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-2xl p-8 shadow-sm dark:shadow-none">
          {/* Success Banner */}
          {successMessage && (
            <div className="mb-6 p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                <div className="text-sm font-medium">
                  <p>{successMessage}</p>
                </div>
              </div>
            </div>
          )}

          {/* Error Banner */}
          {errorMessage && (
            <div className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-900 dark:text-rose-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="text-sm font-medium">
                  <p>{errorMessage}</p>
                </div>
              </div>
            </div>
          )}

          {/* Missing Email Inline Fallback Input */}
          {!email && (
            <div className="mb-5">
              <label
                htmlFor="manualEmail"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Verification Email Address
              </label>
              <input
                id="manualEmail"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@company.com"
                className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all"
              />
            </div>
          )}

          <form onSubmit={handleVerify} className="space-y-6">
            {/* 6-Digit OTP Boxes */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-3 text-center">
                Security Code
              </label>
              <div
                className="flex items-center justify-between gap-2 sm:gap-3"
                onPaste={handlePaste}
              >
                {otp.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => (inputRefs.current[idx] = el)}
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={1}
                    value={digit}
                    disabled={isVerifiedSuccess || loading}
                    onChange={(e) => handleDigitChange(e, idx)}
                    onKeyDown={(e) => handleKeyDown(e, idx)}
                    aria-label={`Digit ${idx + 1}`}
                    className="w-11 sm:w-12 h-13 text-center text-xl font-bold font-mono bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all disabled:opacity-50"
                  />
                ))}
              </div>
            </div>

            {/* Verify Action Button */}
            <button
              type="submit"
              disabled={loading || isVerifiedSuccess}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-semibold rounded-xl shadow-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Verifying code…</span>
                </>
              ) : isVerifiedSuccess ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Verified</span>
                </>
              ) : (
                <>
                  <span>Verify Email</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Resend Cooldown Section (In-Place) */}
          <div className="mt-6 pt-5 border-t border-slate-100 dark:border-slate-800/80 text-center space-y-2">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Didn't receive the code?
            </p>
            <div>
              {resendTimer > 0 ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 dark:text-slate-500 cursor-not-allowed">
                  <RotateCw className="w-3.5 h-3.5" />
                  Resend code in {resendTimer}s
                </span>
              ) : (
                <button
                  type="button"
                  onClick={handleResendOtp}
                  disabled={resending || loading || isVerifiedSuccess}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 underline underline-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {resending ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Sending new code…</span>
                    </>
                  ) : (
                    <>
                      <RotateCw className="w-3.5 h-3.5" />
                      <span>Resend OTP</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>

          {/* Change Email Link */}
          <div className="mt-4 text-center">
            <Link
              to="/signup"
              className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300 transition-colors"
            >
              <ArrowLeft className="w-3 h-3" />
              Change email or sign up with another address
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Verify;

