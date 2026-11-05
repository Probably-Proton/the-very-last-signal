import React, { Component, ErrorInfo, ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class RootErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[RootErrorBoundary] Unhandled application error caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          backgroundColor: '#0c0c0b',
          color: '#ebe6dc',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px',
          fontFamily: 'monospace',
          textAlign: 'center'
        }}>
          <div style={{
            maxWidth: '600px',
            border: '1px solid #7f1d1d',
            backgroundColor: '#1c1917',
            padding: '32px',
            borderRadius: '4px',
            boxShadow: '0 0 30px rgba(127, 29, 29, 0.3)'
          }}>
            <div style={{
              width: '12px',
              height: '12px',
              backgroundColor: '#ef4444',
              borderRadius: '50%',
              margin: '0 auto 16px auto'
            }} />
            <h1 style={{ fontSize: '18px', letterSpacing: '0.2em', textTransform: 'uppercase', color: '#f87171', marginBottom: '12px' }}>
              TRANSMISSION DESK FAULT // SESSION INTERRUPTED
            </h1>
            <p style={{ fontSize: '13px', color: '#a8a29e', lineHeight: 1.6, marginBottom: '20px' }}>
              An unhandled runtime exception was intercepted by the case terminal. Your investigation dossier remains preserved in the central registry.
            </p>
            {this.state.error && (
              <pre style={{
                textAlign: 'left',
                backgroundColor: '#0c0a09',
                border: '1px solid #292524',
                padding: '12px',
                fontSize: '11px',
                color: '#fca5a5',
                overflowX: 'auto',
                marginBottom: '24px'
              }}>
                {this.state.error.message || String(this.state.error)}
              </pre>
            )}
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  window.location.reload();
                }}
                style={{
                  backgroundColor: '#9e1b1b',
                  color: '#ffffff',
                  border: 'none',
                  padding: '10px 20px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  fontWeight: 'bold',
                  letterSpacing: '0.15em',
                  cursor: 'pointer'
                }}
              >
                RELOAD TERMINAL
              </button>
              <button
                onClick={() => {
                  window.location.href = '/';
                }}
                style={{
                  backgroundColor: '#292524',
                  color: '#ebe6dc',
                  border: '1px solid #44403c',
                  padding: '10px 20px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  letterSpacing: '0.15em',
                  cursor: 'pointer'
                }}
              >
                BRIEFING HOME
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

createRoot(document.getElementById('root')!).render(
  <RootErrorBoundary>
    <App />
  </RootErrorBoundary>
);
