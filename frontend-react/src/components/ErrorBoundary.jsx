import React from 'react';
import { AlertTriangle, RefreshCw, Home, ShieldAlert } from 'lucide-react';
import Button from './Button';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('PHISHGUARD React ErrorBoundary caught an error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/dashboard';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6 text-center">
            <div className="w-16 h-16 rounded-2xl bg-red-950/60 border border-red-800 text-red-400 flex items-center justify-center mx-auto">
              <ShieldAlert size={32} />
            </div>

            <div className="space-y-2">
              <h1 className="text-xl font-bold text-slate-100">Display Rendering Anomaly</h1>
              <p className="text-sm text-slate-400">
                PHISHGUARD encountered an unexpected UI rendering error while processing this view. Your security telemetry and background services remain active.
              </p>
            </div>

            {this.state.error && (
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-xl text-left text-xs font-mono text-red-400 break-all max-h-32 overflow-y-auto">
                {this.state.error.toString()}
              </div>
            )}

            <div className="flex items-center justify-center gap-3 pt-2">
              <Button
                variant="secondary"
                onClick={this.handleReload}
                className="flex items-center gap-2 text-xs"
              >
                <RefreshCw size={14} />
                <span>Reload Page</span>
              </Button>
              <Button
                variant="primary"
                onClick={this.handleGoHome}
                className="flex items-center gap-2 text-xs"
              >
                <Home size={14} />
                <span>Return to Console</span>
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
