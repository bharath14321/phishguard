import React, { createContext, useContext, useState, useEffect } from "react";
import { auth } from "../services/api";

// Context providing authentication state and actions
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Load current user on mount if token exists
  useEffect(() => {
    const init = async () => {
      const token = localStorage.getItem("access_token");
      if (token) {
        try {
          const data = await auth.me();
          setUser(data);
        } catch (err) {
          // Token invalid or request failed – clear it
          console.warn("Auth init failed", err);
          localStorage.removeItem("access_token");
          setUser(null);
        }
      }
      setLoading(false);
    };
    init();
  }, []);

  const login = (token) => {
    localStorage.setItem("access_token", token);
    // After storing token, fetch user profile
    auth.me()
      .then((data) => setUser(data))
      .catch(() => setUser(null));
  };

  const logout = () => {
    localStorage.removeItem("access_token");
    setUser(null);
  };

  const value = {
    user,
    loading,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => useContext(AuthContext);
