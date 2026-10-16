import React from 'react';
/**
 * Badge – small label with optional color variant.
 * Props:
 *   - children: label text
 *   - variant: 'neutral' | 'success' | 'warning' | 'danger' | 'info' (default 'neutral')
 */
const variantClasses = {
  neutral: 'bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700',
  success: 'bg-emerald-50 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60',
  warning: 'bg-amber-50 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60',
  danger: 'bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300 border border-rose-200 dark:border-rose-800/60',
  info: 'bg-blue-50 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60',
};

const Badge = ({ children, variant = 'neutral', className = '' }) => (
  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${variantClasses[variant] || variantClasses.neutral} ${className}`}>
    {children}
  </span>
);

export default Badge;
