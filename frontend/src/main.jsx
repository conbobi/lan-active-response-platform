import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import App from './App';
import './styles/soc-dark.css';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'var(--bg-elevated)',
            color: 'var(--text-primary)',
            border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-lg)',
            fontSize: '0.875rem',
            fontWeight: 500,
          },
          success: {
            iconTheme: {
              primary: 'var(--success)',
              secondary: 'var(--bg-elevated)',
            },
          },
          error: {
            iconTheme: {
              primary: 'var(--error)',
              secondary: 'var(--bg-elevated)',
            },
            style: {
              background: 'var(--bg-elevated)',
              color: 'var(--error)',
              border: '1px solid var(--error)',
            },
          },
        }}
      />
    </BrowserRouter>
  </React.StrictMode>
);
