import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

/**
 * ErrorState – Displays when an API request fails with an optional retry button.
 * 
 * @param {Object} props
 * @param {string} [props.title='Failed to load data']
 * @param {string} [props.message]
 * @param {Function} [props.onRetry]
 * @param {string} [props.className='']
 */
const ErrorState = ({
  title = 'Failed to load data',
  message = 'An unexpected error occurred while communicating with the security server.',
  onRetry,
  className = '',
}) => (
  <div className={`p-6 rounded-xl bg-red-50/50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 flex flex-col sm:flex-row items-center justify-between gap-4 ${className}`}>
    <div className="flex items-start gap-3 text-center sm:text-left">
      <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400 shrink-0 mt-0.5" />
      <div>
        <h4 className="text-sm font-semibold text-red-800 dark:text-red-300">{title}</h4>
        <p className="text-xs text-red-600 dark:text-red-400/90 mt-0.5">{message}</p>
      </div>
    </div>
    {onRetry && (
      <button
        type="button"
        onClick={onRetry}
        className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-100 hover:bg-red-200 dark:bg-red-900/50 dark:hover:bg-red-900/80 text-red-800 dark:text-red-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
      >
        <RefreshCw size={13} />
        <span>Retry</span>
      </button>
    )}
  </div>
);

export default ErrorState;
