import React, { useState } from 'react';
import Sidebar from '../components/Sidebar';
import ThemeToggle from '../components/ThemeToggle';
import { Menu, ShieldCheck, Activity } from 'lucide-react';

/**
 * AppLayout – authenticated application shell with a responsive sidebar,
 * sticky top bar with theme toggle, and spacious main content area.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children
 */
const AppLayout = ({ children }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col md:flex-row">
      {/* Desktop Fixed Sidebar */}
      <div className="hidden md:block h-screen sticky top-0 shrink-0 z-20">
        <Sidebar />
      </div>

      {/* Mobile Drawer Backdrop & Sidebar */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm md:hidden flex"
          role="dialog"
          aria-modal="true"
          aria-label="Mobile Navigation Menu"
          onClick={() => setMobileMenuOpen(false)}
        >
          <div
            className="w-64 h-full bg-white dark:bg-slate-900 shadow-2xl relative animate-in slide-in-from-left duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            <Sidebar onClose={() => setMobileMenuOpen(false)} />
          </div>
        </div>
      )}

      {/* Main Content Area + Top Bar */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        {/* Authenticated Top Bar */}
        <header className="h-16 px-4 md:px-6 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 flex items-center justify-between sticky top-0 z-10 shrink-0">
          <div className="flex items-center gap-3">
            {/* Mobile menu toggle */}
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open sidebar menu"
              aria-expanded={mobileMenuOpen}
              className="md:hidden p-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              <Menu size={22} />
            </button>

            {/* Mobile Branding / Desktop Breadcrumb indicator */}
            <div className="flex items-center gap-2">
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                Threat Engine Active
              </span>
              <span className="text-xs text-slate-400 dark:text-slate-500 hidden lg:inline-block">
                | Multi-Layer AI Security Console
              </span>
            </div>
          </div>

          {/* Right side tools */}
          <div className="flex items-center gap-3">
            <ThemeToggle />
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

export default AppLayout;
