import React from 'react';
import { Inbox } from 'lucide-react';

/**
 * EmptyState – Displays when lists or data tables are empty.
 * 
 * @param {Object} props
 * @param {string} props.title
 * @param {string} [props.description]
 * @param {React.ReactNode} [props.action]
 * @param {React.ComponentType} [props.icon=Inbox]
 * @param {string} [props.className='']
 */
const EmptyState = ({
  title = 'No records found',
  description,
  action,
  icon: Icon = Inbox,
  className = '',
}) => (
  <div className={`flex flex-col items-center justify-center p-8 text-center bg-slate-50/50 dark:bg-slate-900/30 rounded-xl border border-dashed border-slate-300 dark:border-slate-800 ${className}`}>
    <div className="w-12 h-12 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500 flex items-center justify-center mb-3">
      <Icon size={24} />
    </div>
    <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200 mb-1">{title}</h3>
    {description && (
      <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mb-4">{description}</p>
    )}
    {action && <div>{action}</div>}
  </div>
);

export default EmptyState;
