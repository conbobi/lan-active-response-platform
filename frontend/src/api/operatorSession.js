const key = 'larp_operator_session';
const changed = 'larp-session-changed';

export function readSession() {
  try {
    return sessionStorage.getItem(key) || '';
  } catch (error) {
    if (error.name === 'SecurityError') return '';
    throw error;
  }
}

export function saveSession(token) {
  if (token) sessionStorage.setItem(key, token);
  else sessionStorage.removeItem(key);
  sessionStorage.removeItem('larp_network_token');
  window.dispatchEvent(new Event(changed));
}

export function subscribeSession(listener) {
  window.addEventListener(changed, listener);
  return () => window.removeEventListener(changed, listener);
}

export function requestSignIn(reason) {
  window.dispatchEvent(new CustomEvent('larp-sign-in', { detail: reason }));
}
