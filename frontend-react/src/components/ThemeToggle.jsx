import React from 'react';
import { Sun, Moon, Laptop } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

/**
 * ThemeToggle – accessible interactive toggle switching between theme states.
 * Supports displaying current active mode and cycling seamlessly.
 */
const ThemeToggle = ({ className = '' }) => {
  const { theme, resolvedTheme, toggle } = useTheme();
  const isDark = resolvedTheme === 'dark';

  return (
    <button
      type="button"
      onClick={toggle}
      title={`Current theme: ${theme} (${resolvedTheme}). Click to toggle.`}
      aria-label={`Toggle theme (currently ${theme})`}
      className={`p-2 rounded-lg text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${className}`}
    >
      {isDark ? (
        <Moon size={19} className="text-blue-400" />
      ) : (
        <Sun size={19} className="text-amber-500" />
      )}
    </button>
  );
};

export default ThemeToggle;
