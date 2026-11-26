let accessToken = '';
let currentUser = null;
const listeners = new Set();

// Ensure no legacy operator tokens remain in browser storage across upgrades.
try {
  sessionStorage.removeItem('larp_operator_session');
  sessionStorage.removeItem('larp_network_token');
} catch {
  // Ignore storage restrictions
}

function notify() {
  for (const listener of listeners) {
    listener();
  }
}

export function readSession() {
  return accessToken;
}

export function readUser() {
  return currentUser;
}

export function saveAuthSession(payload) {
  accessToken = payload?.access_token || '';
  currentUser = payload?.user || null;
  notify();
}

export function clearAuthSession() {
  accessToken = '';
  currentUser = null;
  notify();
}

export function saveSession(token) {
  accessToken = token || '';
  if (!accessToken) currentUser = null;
  notify();
}

export function subscribeSession(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function requestSignIn(reason) {
  window.dispatchEvent(new CustomEvent('larp-sign-in', { detail: reason }));
}
