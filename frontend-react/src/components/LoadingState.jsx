import React from 'react';

/**
 * LoadingState – Reusable loading indicator for async views and data tables.
 * 
 * @param {Object} props
 * @param {string} [props.message='Loading data...']
 * @param {string} [props.className='']
 */
const LoadingState = ({ message = 'Loading data...', className = '' }) => (
  <div className={`flex flex-col items-center justify-center p-8 text-center ${className}`}>
    <div className="w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full animate-spin mb-3"></div>
    <p className="text-sm font-medium text-slate-600 dark:text-slate-400">{message}</p>
  </div>
);

export default LoadingState;
