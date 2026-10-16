import React from 'react';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

/**
 * PublicLayout – wraps public pages with Navbar and Footer.
 */
const PublicLayout = ({ children }) => (
  <>
    <Navbar />
    <main className="min-h-screen bg-gray-50 dark:bg-gray-950">{children}</main>
    <Footer />
  </>
);

export default PublicLayout;
