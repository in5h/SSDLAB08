// Centralized API fetch wrapper
// - Automatically adds Authorization: Bearer <token>
// - Redirects to /login on 401 (expired/invalid token)

const BASE = '';  // Vite proxy strips the base; calls go to /api/* → backend:4000/api/*

function getToken() {
  return localStorage.getItem('token');
}

export function getUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || 'null');
  } catch {
    return null;
  }
}

export function clearSession() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}

async function apiFetch(url, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(BASE + url, { ...options, headers });

  if (res.status === 401) {
    clearSession();
    window.location.replace('/login');
    throw new Error('Session expired. Please log in again.');
  }

  return res;
}

export default apiFetch;
