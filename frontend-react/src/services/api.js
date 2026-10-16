// Central API client for FastAPI backend
// Uses fetch with relative URLs (Vite dev server proxies /api to backend).
// Handles JWT storage, request headers, JSON handling, and error mapping.

const API_BASE = "/api"; // Vite dev proxy forwards to backend

// Get token from localStorage (the backend stores token under 'access_token')
function getToken() {
  return localStorage.getItem("access_token");
}

// Generic request helper
export async function request({ method, path, data = null, params = null, headers = {} }) {
  const url = new URL(API_BASE + path, window.location.origin);
  // Append query parameters if provided
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) url.searchParams.append(key, String(value));
    });
  }

  const fetchOptions = {
    method,
    headers: {
      "Accept": "application/json",
      ...headers,
    },
    credentials: "same-origin",
  };

  const token = getToken();
  if (token) {
    fetchOptions.headers["Authorization"] = `Bearer ${token}`;
  }

  if (data) {
    // Assume JSON payload unless FormData is passed
    if (data instanceof FormData) {
      fetchOptions.body = data;
      // Do not set Content-Type so browser sets multipart/form-data with boundary
    } else {
      fetchOptions.headers["Content-Type"] = "application/json";
      fetchOptions.body = JSON.stringify(data);
    }
  }

  let response;
  try {
    response = await fetch(url.toString(), fetchOptions);
  } catch (err) {
    // Network error
    throw { status: 0, message: "Network error", details: err };
  }

  let responseData;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    responseData = await response.json();
  } else {
    responseData = await response.text();
  }

  if (!response.ok) {
    // Structured backend error format expected: {detail: ..., error_code: ...}
    const err = {
      status: response.status,
      message: responseData?.detail || response.statusText,
      data: responseData,
    };
    throw err;
  }

  return responseData;
}

// Auth endpoints
export const auth = {
  register: (payload) => request({ method: "POST", path: "/v1/auth/register", data: payload }),
  login: (payload) => request({ method: "POST", path: "/v1/auth/login", data: payload }),
  verifyOtp: (payload) => request({ method: "POST", path: "/v1/auth/verify-otp", data: payload }),
  resendOtp: (payload) => request({ method: "POST", path: "/v1/auth/resend-otp", data: payload }),
  status: (identifier) => request({ method: "GET", path: `/v1/auth/status/${encodeURIComponent(identifier)}` }),
  me: () => request({ method: "GET", path: "/v1/auth/me" }),
};

// Analysis endpoints
export const analysis = {
  submitUrl: (url) => request({ method: "POST", path: "/v1/analyze/url", data: { url } }),
  submitHash: (hash) => request({ method: "POST", path: "/v1/analyze/hash", data: { hash } }),
  submitEmail: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request({ method: "POST", path: "/v1/analyze/email", data: form });
  },
  submitQr: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request({ method: "POST", path: "/v1/analyze/qr", data: form });
  },
  submitFile: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request({ method: "POST", path: "/v1/analyze/file", data: form });
  },
  get: (id) => request({ method: "GET", path: `/v1/analyze/${id}` }),
  recent: (limit = 10) => request({ method: "GET", path: "/v1/analyze/recent", params: { limit } }),
  history: (limit = 50) => request({ method: "GET", path: "/v1/analyze/history", params: { limit } }),
  stats: () => request({ method: "GET", path: "/v1/analyze/stats" }),
};

// Mail Security endpoints
export const mailSecurity = {
  getAccounts: () => request({ method: "GET", path: "/v1/mail-security/accounts" }),
  getGmailConnectUrl: () => request({ method: "GET", path: "/v1/mail-security/gmail/connect" }),
  connectAccount: (payload) => request({ method: "POST", path: "/v1/mail-security/accounts/connect", data: payload }),
  disconnectAccount: (id) => request({ method: "DELETE", path: `/v1/mail-security/accounts/${id}` }),
  syncAccount: (id) => request({ method: "POST", path: `/v1/mail-security/accounts/${id}/sync` }),
  getMessages: (params) => request({ method: "GET", path: "/v1/mail-security/messages", params }),
  getMessage: (id) => request({ method: "GET", path: `/v1/mail-security/messages/${id}` }),
  getStats: () => request({ method: "GET", path: "/v1/mail-security/stats" }),
  getSettings: () => request({ method: "GET", path: "/v1/mail-security/settings" }),
  updateSettings: (payload) => request({ method: "PUT", path: "/v1/mail-security/settings", data: payload }),
  ingestEmail: (payload) => request({ method: "POST", path: "/v1/mail-security/ingest", data: payload }),
};

// Chat endpoint (AI Analyst)
export const chat = {
  send: (payload) => request({ method: "POST", path: "/v1/chat", data: payload }),
  suggestions: (analysisId) => request({ method: "GET", path: `/v1/chat/suggestions/${analysisId}` }),
};

export default {
  request,
  auth,
  analysis,
  mailSecurity,
  chat,
};
