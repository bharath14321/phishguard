import React, { createContext, useState, useEffect, useCallback, useContext } from 'react';

/**
 * Theme context to manage system / light / dark themes across PHISHGUARD.
 *
 * Values:
 * - theme: 'system' | 'light' | 'dark' (user preference stored in localStorage)
 * - resolvedTheme: 'light' | 'dark' (actual computed visual mode)
 * - mode: 'light' | 'dark' (alias for resolvedTheme for backward compatibility)
 * - setTheme: (theme: 'system' | 'light' | 'dark') => void
 * - toggle: () => void (toggles between light and dark)
 */
const ThemeContext = createContext({
  theme: 'system',
  resolvedTheme: 'light',
  mode: 'light',
  setTheme: () => {},
  toggle: () => {},
});

const THEME_STORAGE_KEY = 'phishguard_theme';

/**
 * Get OS preferred theme ('dark' or 'light').
 */
const getSystemTheme = () => {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark'
    : 'light';
};

export const ThemeProvider = ({ children }) => {
  // Stored preference: 'system' | 'light' | 'dark'
  const [theme, setThemeState] = useState(() => {
    if (typeof window === 'undefined') return 'system';
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark' || saved === 'system') {
      return saved;
    }
    return 'system';
  });

  // Active computed mode: 'light' | 'dark'
  const [resolvedTheme, setResolvedTheme] = useState(() => {
    const saved = typeof window !== 'undefined' ? localStorage.getItem(THEME_STORAGE_KEY) : 'system';
    if (saved === 'dark') return 'dark';
    if (saved === 'light') return 'light';
    return getSystemTheme();
  });

  // Apply theme to document root element
  const applyThemeToDOM = useCallback((activeMode) => {
    const root = document.documentElement;
    if (activeMode === 'dark') {
      root.classList.add('dark');
      root.style.colorScheme = 'dark';
    } else {
      root.classList.remove('dark');
      root.style.colorScheme = 'light';
    }
  }, []);

  // Update resolved theme whenever theme preference or system preference changes
  useEffect(() => {
    let activeMode = 'light';
    if (theme === 'dark') {
      activeMode = 'dark';
    } else if (theme === 'light') {
      activeMode = 'light';
    } else {
      activeMode = getSystemTheme();
    }

    setResolvedTheme(activeMode);
    applyThemeToDOM(activeMode);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme, applyThemeToDOM]);

  // Listen for OS theme changes in real time when 'system' is selected
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

    const handleSystemThemeChange = (e) => {
      if (theme === 'system') {
        const newSystemTheme = e.matches ? 'dark' : 'light';
        setResolvedTheme(newSystemTheme);
        applyThemeToDOM(newSystemTheme);
      }
    };

    mediaQuery.addEventListener('change', handleSystemThemeChange);
    return () => mediaQuery.removeEventListener('change', handleSystemThemeChange);
  }, [theme, applyThemeToDOM]);

  const setTheme = useCallback((newTheme) => {
    if (['system', 'light', 'dark'].includes(newTheme)) {
      setThemeState(newTheme);
    }
  }, []);

  const toggle = useCallback(() => {
    setThemeState((prev) => {
      if (prev === 'system') {
        const sys = getSystemTheme();
        return sys === 'dark' ? 'light' : 'dark';
      }
      return prev === 'dark' ? 'light' : 'dark';
    });
  }, []);

  return (
    <ThemeContext.Provider
      value={{
        theme,
        resolvedTheme,
        mode: resolvedTheme, // Backward compatibility
        setTheme,
        toggle,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
};

export const useTheme = () => useContext(ThemeContext);

export default ThemeContext;
