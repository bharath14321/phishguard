import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

/**
 * EvidenceCard – Collapsible container for distinct forensic evidence sections.
 * 
 * @param {Object} props
 * @param {string} props.title - Section title
 * @param {React.ComponentType} [props.icon] - Lucide icon component
 * @param {React.ReactNode} [props.badge] - Optional badge element
 * @param {string} [props.subtitle] - Optional subtitle or short status
 * @param {boolean} [props.defaultOpen=true] - Initial expanded state
 * @param {React.ReactNode} props.children - Evidence content
 * @param {string} [props.className=''] - Additional CSS classes
 */
const EvidenceCard = ({
  title,
  icon: Icon,
  badge,
  subtitle,
  defaultOpen = true,
  children,
  className = '',
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div
      className={`rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm transition-all overflow-hidden ${className}`}
    >
      {/* Header Button */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        aria-expanded={isOpen}
        className="w-full px-5 py-4 flex items-center justify-between gap-3 text-left hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        <div className="flex items-center gap-3 min-w-0">
          {Icon && (
            <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center justify-center shrink-0">
              <Icon size={18} />
            </div>
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                {title}
              </h3>
              {badge}
            </div>
            {subtitle && (
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div className="text-slate-400 dark:text-slate-500 shrink-0">
          {isOpen ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
        </div>
      </button>

      {/* Collapsible Content */}
      {isOpen && (
        <div className="px-5 pb-5 pt-1 border-t border-slate-100 dark:border-slate-800/80">
          {children}
        </div>
      )}
    </div>
  );
};

export default EvidenceCard;
