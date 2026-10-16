import React from 'react';
/**
 * Card – a simple container with consistent padding, rounded corners, and shadow.
 * Accepts children and optional extra Tailwind classes via `className`.
 */
const Card = ({ children, className = '' }) => (
  <div className={`bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm p-6 text-slate-900 dark:text-slate-100 ${className}`}>
    {children}
  </div>
);

export default Card;
