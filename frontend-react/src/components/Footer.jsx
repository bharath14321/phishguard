import React from 'react';
import { Link } from 'react-router-dom';
/**
 * Footer – simple site footer with branding and navigation links.
 * Uses Tailwind classes that match the existing styling approach.
 */
const Footer = () => (
  <footer className="bg-gray-100 dark:bg-gray-900 text-gray-600 dark:text-gray-300 py-6">
    <div className="container mx-auto px-4 flex flex-col md:flex-row justify-between items-center">
      <div className="text-sm">© {new Date().getFullYear()} PHISHGUARD</div>
      <nav className="flex space-x-4 mt-4 md:mt-0">
        <Link to="/" className="hover:underline">Platform</Link>
        <Link to="#threat-intel" className="hover:underline">Threat Intelligence</Link>
        <Link to="#ai-analyst" className="hover:underline">AI Analyst</Link>
        <Link to="#research" className="hover:underline">Research</Link>
        <Link to="/privacy" className="hover:underline">Privacy</Link>
      </nav>
    </div>
  </footer>
);

export default Footer;
