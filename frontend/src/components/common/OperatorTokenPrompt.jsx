// Operator token entry shared with Agents → Network & Firewall.
// The token stays in this tab's sessionStorage under the same key api.js reads.
import { useState } from 'react';
import Button from '../ui/Button';

export const OPERATOR_TOKEN_KEY = 'larp_network_token';

export default function OperatorTokenPrompt({ reason, onSaved }) {
  const [value, setValue] = useState('');
  const save = (event) => {
    event.preventDefault();
    const token = value.trim();
    if (!token) return;
    sessionStorage.setItem(OPERATOR_TOKEN_KEY, token);
    setValue('');
    if (onSaved) onSaved();
  };
  return (
    <form
      onSubmit={save}
      style={{
        padding: '0.75rem 1rem', borderRadius: '8px', display: 'flex', flexDirection: 'column', gap: '0.5rem',
        backgroundColor: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.3)',
      }}
    >
      <strong style={{ fontSize: '0.85rem' }}>Cần operator token</strong>
      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
        {reason || 'Manager yêu cầu token của operator được cấp quyền cho Agent này.'} Token chỉ lưu trong tab hiện tại.
      </span>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Bearer token"
          aria-label="Operator token"
          style={{ flex: 1, padding: '0.4rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
        />
        <Button size="sm" variant="primary" type="submit" disabled={!value.trim()}>Lưu token</Button>
      </div>
    </form>
  );
}
