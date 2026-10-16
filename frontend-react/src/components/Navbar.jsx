import React from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ThemeToggle from './ThemeToggle';
import { Sun, Moon, LogIn, UserPlus, LayoutDashboard } from 'lucide-react';

const Navbar = () => {
  const { isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  const navLinks = [
    { to: '/', label: 'Platform' },
    { to: '#capabilities', label: 'Capabilities' },
    { to: '#threat-intel', label: 'Threat Intelligence' },
    { to: '#ai-analyst', label: 'AI Analyst' },
    { to: '#research', label: 'Research' },
  ];

  return (
    <nav className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 px-4 md:px-6 py-3 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-6">
        <Link to="/" className="text-xl font-extrabold tracking-tight text-slate-900 dark:text-white">PHISHGUARD</Link>
        {navLinks.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              isActive
                ? 'text-blue-600 dark:text-blue-400 font-semibold text-sm'
                : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-sm font-medium transition-colors'
            }
          >
            {link.label}
          </NavLink>
        ))}
      </div>
      <div className="flex items-center space-x-3">
        <ThemeToggle />
        {isAuthenticated ? (
          <button
            onClick={handleLogout}
            className="flex items-center text-red-600 hover:text-red-800"
          >
            <LogIn size={18} className="mr-1" />
            Logout
          </button>
        ) : (
          <>
            <NavLink
              to="/login"
              className="flex items-center text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-gray-100"
            >
              <LogIn size={18} className="mr-1" />
              Sign In
            </NavLink>
            <NavLink
              to="/signup"
              className="flex items-center text-blue-600 dark:text-blue-400 hover:underline"
            >
              <UserPlus size={18} className="mr-1" />
              Get Started
            </NavLink>
          </>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
