import React from 'react';
/**
 * SectionHeading – standard heading for sections with optional subtitle.
 * Props:
 *   - title: main heading text (required)
 *   - subtitle: secondary text (optional)
 */
const SectionHeading = ({ title, subtitle }) => (
  <div className="text-center mb-8">
    <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">{title}</h2>
    {subtitle && (
      <p className="mt-2 text-lg text-gray-600 dark:text-gray-400">{subtitle}</p>
    )}
  </div>
);

export default SectionHeading;
