import React, { useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { auth } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { Shield, Eye, EyeOff, Check, X, ArrowRight, Loader2, AlertCircle } from 'lucide-react';

const PASSWORD_RULES = [
  { id: 'length', label: 'At least 8 characters', validator: (p) => p.length >= 8 },
  { id: 'upper', label: 'Uppercase letter', validator: (p) => /[A-Z]/.test(p) },
  { id: 'lower', label: 'Lowercase letter', validator: (p) => /[a-z]/.test(p) },
  { id: 'number', label: 'Number', validator: (p) => /[0-9]/.test(p) },
  { id: 'special', label: 'Special character (!@#$%^&*)', validator: (p) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(p) },
];

const Signup = () => {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [form, setForm] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  });

  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [fieldErrors, setFieldErrors] = useState({}); // { username, email, password, confirmPassword }
  const [generalError, setGeneralError] = useState('');

  // Password rules validation states
  const ruleStates = useMemo(() => {
    return PASSWORD_RULES.map((rule) => ({
      ...rule,
      passed: rule.validator(form.password),
    }));
  }, [form.password]);

  // Compute password strength score (0 to 4)
  const strengthScore = useMemo(() => {
    if (!form.password) return 0;
    const passedCount = ruleStates.filter((r) => r.passed).length;
    if (passedCount <= 2) return 1; // Weak
    if (passedCount === 3) return 2; // Fair
    if (passedCount === 4) return 3; // Good
    return 4; // Strong
  }, [ruleStates, form.password]);

  const strengthConfig = useMemo(() => {
    switch (strengthScore) {
      case 1:
        return { label: 'Weak', color: 'bg-rose-500', textColor: 'text-rose-600 dark:text-rose-400', width: 'w-1/4' };
      case 2:
        return { label: 'Fair', color: 'bg-amber-500', textColor: 'text-amber-600 dark:text-amber-400', width: 'w-2/4' };
      case 3:
        return { label: 'Good', color: 'bg-blue-500', textColor: 'text-blue-600 dark:text-blue-400', width: 'w-3/4' };
      case 4:
        return { label: 'Strong', color: 'bg-emerald-500', textColor: 'text-emerald-600 dark:text-emerald-400', width: 'w-full' };
      default:
        return { label: '', color: 'bg-slate-200 dark:bg-slate-700', textColor: 'text-slate-400', width: 'w-0' };
    }
  }, [strengthScore]);

  const passwordsMatch = useMemo(() => {
    if (!form.confirmPassword) return null;
    return form.password === form.confirmPassword;
  }, [form.password, form.confirmPassword]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((prev) => ({ ...prev, [name]: value }));
    if (fieldErrors[name]) {
      setFieldErrors((prev) => ({ ...prev, [name]: '' }));
    }
    if (generalError) setGeneralError('');
  };

  const validateClient = () => {
    const errors = {};

    // Username validation
    if (!form.username.trim()) {
      errors.username = 'Username is required.';
    } else if (form.username.length < 3 || form.username.length > 50) {
      errors.username = 'Username must be between 3 and 50 characters.';
    } else if (!/^[a-zA-Z0-9_\-\.]+$/.test(form.username)) {
      errors.username = 'Only letters, numbers, _, -, and . are allowed.';
    }

    // Email validation
    if (!form.email.trim()) {
      errors.email = 'Email address is required.';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) {
      errors.email = 'Please enter a valid email address.';
    }

    // Password validation
    if (!form.password) {
      errors.password = 'Password is required.';
    } else {
      const failedRules = ruleStates.filter((r) => !r.passed);
      if (failedRules.length > 0) {
        errors.password = 'Please satisfy all password complexity requirements.';
      }
    }

    // Confirm password
    if (!form.confirmPassword) {
      errors.confirmPassword = 'Please confirm your password.';
    } else if (form.password !== form.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match.';
    }

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateClient()) return;

    setLoading(true);
    setGeneralError('');
    setFieldErrors({});

    try {
      const response = await auth.register({
        username: form.username.trim(),
        email: form.email.trim(),
        password: form.password,
      });

      // If backend returns token directly
      if (response && response.access_token) {
        login(response.access_token);
        navigate('/dashboard');
      } else {
        // Successful registration -> Navigate to /verify with email in router state
        navigate('/verify', {
          state: { email: form.email.trim() },
        });
      }
    } catch (err) {
      // Parse structured backend error
      const errDetail = err?.data?.detail?.error || err?.data?.detail;
      const errorCode = errDetail?.code || (typeof errDetail === 'string' ? errDetail : null);
      const errorMessage = errDetail?.message || (typeof errDetail === 'string' ? errDetail : err.message || 'Registration failed.');
      const errorField = errDetail?.field;

      if (errorCode === 'USERNAME_ALREADY_REGISTERED' || errorField === 'username') {
        setFieldErrors((prev) => ({
          ...prev,
          username: errorMessage || 'Username already registered.',
        }));
      } else if (errorCode === 'EMAIL_ALREADY_REGISTERED' || errorField === 'email') {
        setFieldErrors((prev) => ({
          ...prev,
          email: errorMessage || 'Email already registered.',
        }));
      } else if (errorCode === 'PASSWORD_TOO_WEAK' || errorField === 'password') {
        setFieldErrors((prev) => ({
          ...prev,
          password: errorMessage || 'Password does not meet complexity requirements.',
        }));
      } else {
        setGeneralError(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[calc(100vh-140px)] flex items-center justify-center bg-slate-50 dark:bg-slate-950 px-4 py-12 transition-colors">
      <div className="w-full max-w-lg">
        {/* Card Header & Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-800/50 mb-3 shadow-xs">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Create your PHISHGUARD account
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Access enterprise phishing detection and security intelligence
          </p>
        </div>

        {/* Auth Card */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 rounded-2xl p-8 shadow-sm dark:shadow-none">
          {/* General Error Banner */}
          {generalError && (
            <div className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-900 dark:text-rose-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-medium">{generalError}</p>
                </div>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            {/* Username */}
            <div>
              <label
                htmlFor="username"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                value={form.username}
                onChange={handleChange}
                placeholder="analyst_handle"
                className={`w-full px-3.5 py-2.5 bg-white dark:bg-slate-950 border rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all ${
                  fieldErrors.username
                    ? 'border-rose-300 dark:border-rose-700 focus:ring-rose-500'
                    : 'border-slate-300 dark:border-slate-700'
                }`}
              />
              {fieldErrors.username && (
                <p className="mt-1.5 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1 font-medium">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {fieldErrors.username}
                </p>
              )}
            </div>

            {/* Email Address */}
            <div>
              <label
                htmlFor="email"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Email Address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                required
                value={form.email}
                onChange={handleChange}
                placeholder="name@company.com"
                className={`w-full px-3.5 py-2.5 bg-white dark:bg-slate-950 border rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all ${
                  fieldErrors.email
                    ? 'border-rose-300 dark:border-rose-700 focus:ring-rose-500'
                    : 'border-slate-300 dark:border-slate-700'
                }`}
              />
              {fieldErrors.email && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs text-rose-600 dark:text-rose-400 font-medium">
                  <div className="flex items-center gap-1">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                    <span>{fieldErrors.email}</span>
                  </div>
                  {fieldErrors.email.toLowerCase().includes('already registered') && (
                    <Link
                      to="/login"
                      state={{ email: form.email.trim() }}
                      className="underline underline-offset-2 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-semibold"
                    >
                      Sign in instead
                    </Link>
                  )}
                </div>
              )}
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
                {form.password && strengthConfig.label && (
                  <span className={`text-xs font-semibold ${strengthConfig.textColor}`}>
                    {strengthConfig.label}
                  </span>
                )}
              </div>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={form.password}
                  onChange={handleChange}
                  placeholder="••••••••••••"
                  className={`w-full px-3.5 py-2.5 pr-10 bg-white dark:bg-slate-950 border rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all ${
                    fieldErrors.password
                      ? 'border-rose-300 dark:border-rose-700 focus:ring-rose-500'
                      : 'border-slate-300 dark:border-slate-700'
                  }`}
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

              {/* Live Password Strength Meter Bar */}
              {form.password && (
                <div className="mt-2 h-1.5 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${strengthConfig.color} transition-all duration-300 ${strengthConfig.width}`}
                  />
                </div>
              )}

              {/* Password Requirements Checklist */}
              <div className="mt-3 p-3 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-slate-200/60 dark:border-slate-800 space-y-1.5">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                  Password Requirements:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {ruleStates.map((rule) => (
                    <div key={rule.id} className="flex items-center gap-1.5 text-xs">
                      {rule.passed ? (
                        <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0 stroke-[2.5]" />
                      ) : (
                        <div className="w-3.5 h-3.5 rounded-full border border-slate-300 dark:border-slate-600 shrink-0" />
                      )}
                      <span
                        className={
                          rule.passed
                            ? 'text-slate-800 dark:text-slate-200 font-medium'
                            : 'text-slate-500 dark:text-slate-400'
                        }
                      >
                        {rule.label}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              {fieldErrors.password && (
                <p className="mt-1.5 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1 font-medium">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {fieldErrors.password}
                </p>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label
                  htmlFor="confirmPassword"
                  className="block text-xs font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300"
                >
                  Confirm Password
                </label>
                {passwordsMatch !== null && (
                  <span
                    className={`text-xs font-semibold flex items-center gap-1 ${
                      passwordsMatch
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-rose-600 dark:text-rose-400'
                    }`}
                  >
                    {passwordsMatch ? 'Passwords match' : 'Passwords do not match'}
                  </span>
                )}
              </div>
              <div className="relative">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={form.confirmPassword}
                  onChange={handleChange}
                  placeholder="••••••••••••"
                  className={`w-full px-3.5 py-2.5 pr-10 bg-white dark:bg-slate-950 border rounded-xl text-slate-900 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-transparent transition-all ${
                    fieldErrors.confirmPassword || (passwordsMatch === false && form.confirmPassword)
                      ? 'border-rose-300 dark:border-rose-700 focus:ring-rose-500'
                      : passwordsMatch
                      ? 'border-emerald-300 dark:border-emerald-700 focus:ring-emerald-500'
                      : 'border-slate-300 dark:border-slate-700'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors p-1"
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {fieldErrors.confirmPassword && (
                <p className="mt-1.5 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1 font-medium">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {fieldErrors.confirmPassword}
                </p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-4 inline-flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white text-sm font-semibold rounded-xl shadow-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 dark:focus:ring-offset-slate-900"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Creating account…</span>
                </>
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer Link */}
          <div className="mt-8 pt-6 border-t border-slate-100 dark:border-slate-800/80 text-center">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              Already have an account?{' '}
              <Link
                to="/login"
                state={{ email: form.email.trim() }}
                className="font-semibold text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 underline underline-offset-2"
              >
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Signup;

