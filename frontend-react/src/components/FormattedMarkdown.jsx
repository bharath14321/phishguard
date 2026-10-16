import React from 'react';

/**
 * Helper to format inline bold, code, links, and epistemic tags safely without innerHTML.
 */
export function renderFormattedInline(text) {
  if (!text) return null;

  // Regex matching tokens: markdown links [text](url), bold **text**, code `text`, and epistemic markers
  const tokenRegex = /(\[[^\]]+\]\([^)]+\)|\*\*.*?\*\*|`.*?`|\[CONFIRMED EVIDENCE\]|\[MODEL PREDICTION\]|\[RULE-BASED SIGNALS\]|\[CORRELATED EVIDENCE\]|\[UNKNOWN \/ UNAVAILABLE\])/g;
  const segments = text.split(tokenRegex);

  return segments.map((seg, i) => {
    if (!seg) return null;

    // Markdown link: [text](url)
    const linkMatch = seg.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (linkMatch) {
      const linkText = linkMatch[1];
      const linkHref = linkMatch[2];
      // Only allow http(s) or mailto URLs for security
      const isSafe = /^https?:\/\//i.test(linkHref) || /^mailto:/i.test(linkHref);
      return (
        <a
          key={i}
          href={isSafe ? linkHref : '#'}
          target={isSafe ? '_blank' : '_self'}
          rel="noopener noreferrer"
          className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
        >
          {linkText}
        </a>
      );
    }

    if (seg.startsWith('**') && seg.endsWith('**') && seg.length >= 4) {
      return (
        <strong key={i} className="font-bold text-slate-900 dark:text-slate-100">
          {seg.slice(2, -2)}
        </strong>
      );
    }

    if (seg.startsWith('`') && seg.endsWith('`') && seg.length >= 2) {
      return (
        <code
          key={i}
          className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 font-mono text-xs text-blue-600 dark:text-blue-400"
        >
          {seg.slice(1, -1)}
        </code>
      );
    }

    if (seg === '[CONFIRMED EVIDENCE]') {
      return (
        <span
          key={i}
          className="inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 mr-1"
        >
          CONFIRMED EVIDENCE
        </span>
      );
    }
    if (seg === '[MODEL PREDICTION]') {
      return (
        <span
          key={i}
          className="inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300 mr-1"
        >
          MODEL PREDICTION
        </span>
      );
    }
    if (seg === '[RULE-BASED SIGNALS]') {
      return (
        <span
          key={i}
          className="inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 mr-1"
        >
          RULE SIGNALS
        </span>
      );
    }
    if (seg === '[CORRELATED EVIDENCE]') {
      return (
        <span
          key={i}
          className="inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300 mr-1"
        >
          CORRELATED EVIDENCE
        </span>
      );
    }
    if (seg === '[UNKNOWN / UNAVAILABLE]') {
      return (
        <span
          key={i}
          className="inline-block px-1.5 py-0.5 text-[10px] font-bold rounded bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300 mr-1"
        >
          UNKNOWN / UNAVAILABLE
        </span>
      );
    }

    return seg;
  });
}

/**
 * Format markdown text safely without dangerouslySetInnerHTML.
 */
export default function FormattedMarkdown({ text, className = '' }) {
  if (!text) return null;

  const lines = text.split('\n');

  return (
    <div className={`space-y-1.5 text-xs md:text-sm leading-relaxed text-slate-800 dark:text-slate-200 ${className}`}>
      {lines.map((line, idx) => {
        const trimmed = line.trim();

        if (!trimmed) {
          return <div key={idx} className="h-1" />;
        }

        // Headers
        if (trimmed.startsWith('##### ')) {
          return (
            <h6 key={idx} className="font-semibold uppercase tracking-wider text-slate-700 dark:text-slate-300 text-xs pt-1">
              {renderFormattedInline(trimmed.substring(6))}
            </h6>
          );
        }
        if (trimmed.startsWith('#### ')) {
          return (
            <h5 key={idx} className="font-bold text-slate-800 dark:text-slate-200 text-xs md:text-sm pt-1">
              {renderFormattedInline(trimmed.substring(5))}
            </h5>
          );
        }
        if (trimmed.startsWith('### ')) {
          return (
            <h4 key={idx} className="font-bold text-slate-900 dark:text-slate-100 text-sm md:text-base pt-1">
              {renderFormattedInline(trimmed.substring(4))}
            </h4>
          );
        }
        if (trimmed.startsWith('## ')) {
          return (
            <h3 key={idx} className="font-bold text-slate-900 dark:text-slate-100 text-base md:text-lg pt-1.5 pb-0.5 border-b border-slate-200 dark:border-slate-800">
              {renderFormattedInline(trimmed.substring(3))}
            </h3>
          );
        }
        if (trimmed.startsWith('# ')) {
          return (
            <h2 key={idx} className="font-bold text-slate-900 dark:text-slate-100 text-lg md:text-xl pt-2">
              {renderFormattedInline(trimmed.substring(2))}
            </h2>
          );
        }

        // Blockquote
        if (trimmed.startsWith('> ')) {
          return (
            <blockquote key={idx} className="pl-3 border-l-2 border-slate-300 dark:border-slate-700 italic text-slate-600 dark:text-slate-400">
              {renderFormattedInline(trimmed.substring(2))}
            </blockquote>
          );
        }

        // Bullet point: - or * or •
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ') || trimmed.startsWith('• ')) {
          const bulletContent = trimmed.substring(2);
          return (
            <div key={idx} className="flex items-start gap-2 pl-2">
              <span className="text-blue-500 font-bold shrink-0">•</span>
              <span className="flex-1">
                {renderFormattedInline(bulletContent)}
              </span>
            </div>
          );
        }

        // Numbered list
        const numMatch = trimmed.match(/^(\d+)\.\s+(.*)/);
        if (numMatch) {
          return (
            <div key={idx} className="flex items-start gap-2 pl-2">
              <span className="font-mono font-semibold text-slate-500 shrink-0">{numMatch[1]}.</span>
              <span className="flex-1">
                {renderFormattedInline(numMatch[2])}
              </span>
            </div>
          );
        }

        return <p key={idx}>{renderFormattedInline(line)}</p>;
      })}
    </div>
  );
}
