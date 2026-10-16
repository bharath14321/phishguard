import React from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  ShieldAlert,
  History,
  Globe,
  FileText,
  Bot,
  Settings,
  LogOut,
  ShieldCheck,
  User,
  X,
} from 'lucide-react';

/**
 * Navigation items for the authenticated application.
 */
const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/analyze', label: 'Analyze', icon: ShieldAlert },
  { to: '/history', label: 'History', icon: History },
  { to: '/threat-intelligence', label: 'Threat Intelligence', icon: Globe },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/analyst', label: 'AI Analyst', icon: Bot },
  { to: '/settings', label: 'Settings', icon: Settings },
];

/**
 * Sidebar Component
 * Renders the main navigation, branding, and authenticated user profile with logout.
 * 
 * @param {Object} props
 * @param {Function} [props.onClose] - Optional callback triggered when a navigation item is clicked (for mobile drawer).
 * @param {string} [props.className] - Optional custom CSS classes.
 */
const Sidebar = ({ onClose, className = '' }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    if (onClose) onClose();
    navigate('/');
  };

  // Safe display for username / email
  const displayUsername = user?.username || (user?.email ? user.email.split('@')[0] : 'Security Analyst');
  const displayEmail = user?.email || '';
  const initial = (displayUsername.charAt(0) || 'A').toUpperCase();

  return (
    <aside
      className={`w-64 h-full flex flex-col bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 select-none ${className}`}
      aria-label="Main Navigation"
    >
      {/* Top Branding */}
      <div className="h-16 px-5 flex items-center justify-between border-b border-slate-200 dark:border-slate-800 shrink-0">
        <Link
          to="/dashboard"
          onClick={onClose}
          className="flex items-center gap-2.5 group focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg p-1"
        >
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-md shadow-blue-500/20 group-hover:scale-105 transition-transform">
            <ShieldCheck size={20} />
          </div>
          <div className="flex flex-col">
            <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
              PHISHGUARD
            </span>
            <span className="text-[10px] uppercase font-semibold tracking-wider text-slate-400 dark:text-slate-500 -mt-1">
              SOC Platform
            </span>
          </div>
        </Link>

        {/* Mobile close button if inside drawer */}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation sidebar"
            className="md:hidden p-1.5 rounded-lg text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X size={20} />
          </button>
        )}
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 group focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20 font-semibold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/70'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    size={18}
                    className={`shrink-0 transition-colors ${
                      isActive
                        ? 'text-white'
                        : 'text-slate-500 dark:text-slate-400 group-hover:text-slate-900 dark:group-hover:text-slate-100'
                    }`}
                  />
                  <span className="truncate">{item.label}</span>
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* User Info & Logout Section */}
      <div className="p-3 border-t border-slate-200 dark:border-slate-800 shrink-0 space-y-2">
        <div className="flex items-center gap-3 px-2 py-2 rounded-lg bg-slate-50 dark:bg-slate-800/50">
          <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/60 text-blue-700 dark:text-blue-300 flex items-center justify-center font-bold text-xs shrink-0 border border-blue-200 dark:border-blue-800">
            {initial}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">
              {displayUsername}
            </p>
            {displayEmail ? (
              <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                {displayEmail}
              </p>
            ) : (
              <p className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium truncate">
                Analyst Session
              </p>
            )}
          </div>
        </div>

        <button
          type="button"
          onClick={handleLogout}
          aria-label="Log out of application"
          className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
        >
          <LogOut size={15} />
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
