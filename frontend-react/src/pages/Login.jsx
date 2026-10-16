import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { auth } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { Shield, Eye, EyeOff, ArrowRight, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [emailOrUsername, setEmailOrUsername] = useState(location.state?.email || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorState, setErrorState] = useState(null); // { code, message, field, unverifiedEmail }
  const [verifiedBanner, setVerifiedBanner] = useState(location.state?.verified || false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!emailOrUsername.trim() || !password) {
      setErrorState({
        code: 'VALIDATION_ERROR',
        message: 'Please provide both your username/email and password.',
      });
      return;
    }

    setLoading(true);
    setErrorState(null);

    try {
      const response = await auth.login({
        email_or_username: emailOrUsername.trim(),
        password: password,
      });

      if (response && response.access_token) {
        login(response.access_token);
        navigate('/dashboard');
      } else {
        setErrorState({
          code: 'AUTH_FAILED',
          message: 'Failed to receive access token. Please try again.',
        });
      }
    } catch (err) {
      // Backend returns { detail: { error: { code, message, field } } } or fallback message
      const errDetail = err?.data?.detail?.error || err?.data?.detail;
      const errorCode = errDetail?.code || (typeof errDetail === 'string' ? errDetail : null);
      const errorMessage = errDetail?.message || (typeof errDetail === 'string' ? errDetail : err.message || 'Incorrect email or password.');

      if (errorCode === 'EMAIL_NOT_VERIFIED') {
        setErrorState({
          code: 'EMAIL_NOT_VERIFIED',
          message: 'Please verify your email before signing in.',
          unverifiedEmail: emailOrUsername.includes('@') ? emailOrUsername.trim() : '',
        });
      } else {
        setErrorState({
          code: errorCode || 'INVALID_CREDENTIALS',
          message: errorMessage,
          field: errDetail?.field,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center bg-slate-50 dark:bg-slate-950 px-4 py-12 transition-colors">
      <div className="w-full max-w-md">
        {/* Card Header & Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-800/50 mb-3 shadow-xs">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Sign in to PHISHGUARD
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Enterprise multi-engine phishing & threat defense portal
          </p>
        </div>

        {/* Auth Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-2xl p-8 shadow-sm dark:shadow-none">
          {/* Email Verification Success Banner */}
          {verifiedBanner && !errorState && (
            <div className="mb-6 p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200">
              <div className="flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-semibold">Email verified successfully!</p>
                  <p className="mt-0.5 text-emerald-700 dark:text-emerald-300">
                    Please sign in with your password to continue.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Unverified Account Warning Banner */}
          {errorState?.code === 'EMAIL_NOT_VERIFIED' && (
            <div className="mb-6 p-4 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-semibold">Email Verification Required</p>
                  <p className="mt-0.5 text-amber-700 dark:text-amber-300">
                    {errorState.message}
                  </p>
                  <button
                    type="button"
                    onClick={() => navigate('/verify', { state: { email: errorState.unverifiedEmail } })}
                    className="mt-3 inline-flex items-center text-xs font-semibold text-blue-700 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline underline-offset-2"
                  >
                    Verify email now <ArrowRight className="w-3.5 h-3.5 ml-1" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* General Error Banner */}
          {errorState && errorState.code !== 'EMAIL_NOT_VERIFIED' && (
            <div className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-900 dark:text-rose-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium">{errorState.message}</p>
                  {errorState.code === 'USER_NOT_FOUND' && (
                    <div className="mt-2 pt-2 border-t border-rose-200/60 dark:border-rose-800/60 text-xs text-rose-700 dark:text-rose-300">
                      <span>Don't have an account yet? </span>
                      <Link
                        to="/signup"
                        className="font-semibold underline underline-offset-2 hover:text-rose-900 dark:hover:text-rose-100"
                      >
                        Create account
                      </Link>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-5">
            {/* Email or Username */}
            <div>
              <label
                htmlFor="emailOrUsername"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Email or Username
              </label>
              <input
                id="emailOrUsername"
                name="emailOrUsername"
                type="text"
                autoComplete="username"
                required
                value={emailOrUsername}
                onChange={(e) => {
                  setEmailOrUsername(e.target.value);
                  if (errorState) setErrorState(null);
                }}
                placeholder="name@company.com or analyst_handle"
                className="w-full px-3.5 py-2.5 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all"
              />
            </div>

            {/* Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="password"
                  className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300"
                >
                  Password
                </label>
              </div>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (errorState) setErrorState(null);
                  }}
                  placeholder="••••••••••••"
                  className="w-full px-3.5 py-2.5 pr-10 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors p-1"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-semibold rounded-xl shadow-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Signing in…</span>
                </>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer Link */}
          <div className="mt-8 pt-6 border-t border-slate-100 dark:border-slate-800/80 text-center">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              Don't have an account?{' '}
              <Link
                to="/signup"
                className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 underline underline-offset-2"
              >
                Sign up
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;

