import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Home from './pages/Home';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Reports from './pages/Reports';
import Analyze from './pages/Analyze';
import AnalysisResult from './pages/AnalysisResult';
import Analyst from './pages/Analyst';
import Verify from './pages/Verify';
import Settings from './pages/Settings';
import PrivacyPolicy from './pages/PrivacyPolicy';
import TermsOfService from './pages/TermsOfService';
import ErrorBoundary from './components/ErrorBoundary';
import { useAuth } from './context/AuthContext';
import PublicLayout from './layouts/PublicLayout';
import AppLayout from './layouts/AppLayout';

// Simple auth guard that checks authentication via AuthContext.
const AuthGuard = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400">
        <div className="flex items-center gap-3">
          <div className="w-5 h-5 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-sm font-medium">Authenticating session…</span>
        </div>
      </div>
    );
  }
  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

// Lightweight placeholder component for upcoming authenticated pages
const PlaceholderPage = ({ title, description }) => (
  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 shadow-sm">
    <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mb-2">{title}</h2>
    <p className="text-sm text-slate-500 dark:text-slate-400">{description}</p>
  </div>
);

const App = () => (
  <ErrorBoundary>
    <Router>
      <Routes>
        {/* Public routes wrapped with PublicLayout */}
        <Route path="/" element={<PublicLayout><Home /></PublicLayout>} />
        <Route path="/login" element={<PublicLayout><Login /></PublicLayout>} />
        <Route path="/signup" element={<PublicLayout><Signup /></PublicLayout>} />
        <Route path="/verify" element={<PublicLayout><Verify /></PublicLayout>} />
        <Route path="/privacy-policy" element={<PrivacyPolicy />} />
        <Route path="/terms-of-service" element={<TermsOfService />} />

        {/* Protected routes wrapped with AppLayout */}
        <Route
          path="/dashboard"
          element={
            <AuthGuard>
              <AppLayout>
                <Dashboard />
              </AppLayout>
            </AuthGuard>
          }
        />
      <Route
        path="/analyze"
        element={
          <AuthGuard>
            <AppLayout>
              <Analyze />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/history"
        element={
          <AuthGuard>
            <AppLayout>
              <History />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/threat-intelligence"
        element={
          <AuthGuard>
            <AppLayout>
              <ThreatIntelligence />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/reports"
        element={
          <AuthGuard>
            <AppLayout>
              <Reports />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/analyst"
        element={
          <AuthGuard>
            <AppLayout>
              <Analyst />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/settings"
        element={
          <AuthGuard>
            <AppLayout>
              <Settings />
            </AppLayout>
          </AuthGuard>
        }
      />
      <Route
        path="/analysis/:id"
        element={
          <AuthGuard>
            <AppLayout>
              <AnalysisResult />
            </AppLayout>
          </AuthGuard>
        }
      />

      {/* Fallback – redirect to home */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  </Router>
  </ErrorBoundary>
);

export default App;
