'use client'

import { useState, useEffect, useRef } from 'react'
import Link from 'next/link'
import ParticleBackground from '@/components/ParticleBackground'

export default function LoginPage() {
  const [activeTab, setActiveTab] = useState('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState({ type: '', text: '' })
  const supabaseRef = useRef(null)

  function getSupabase() {
    if (!supabaseRef.current) {
      let createBrowserClient
      try {
        createBrowserClient = require('@supabase/ssr').createBrowserClient
      } catch {
        return null
      }
      supabaseRef.current = createBrowserClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL,
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
      )
    }
    return supabaseRef.current
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setMessage({ type: '', text: '' })

    if (activeTab === 'signup') {
      if (password !== confirmPassword) {
        setMessage({ type: 'error', text: 'Passwords do not match.' })
        setLoading(false)
        return
      }
      const { error } = await getSupabase().auth.signUp({ email, password })
      if (error) {
        setMessage({ type: 'error', text: error.message })
      } else {
        setMessage({ type: 'success', text: 'Check your email to confirm your account.' })
        setEmail('')
        setPassword('')
        setConfirmPassword('')
      }
    } else {
      const { error } = await getSupabase().auth.signInWithPassword({ email, password })
      if (error) {
        setMessage({ type: 'error', text: error.message })
      } else {
        window.location.href = '/dashboard'
      }
    }
    setLoading(false)
  }

  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      background: '#060608',
    }}>
      <style jsx>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .form-card {
          animation: slideIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .tab-btn {
          background: none;
          border: none;
          font-family: 'JetBrains Mono', monospace;
          font-size: 10px;
          letter-spacing: 0.15em;
          text-transform: uppercase;
          color: rgba(240,237,232,0.35);
          padding: 0 0 10px;
          cursor: pointer;
          border-bottom: 1px solid transparent;
          transition: color 0.2s, border-color 0.2s;
          margin-right: 32px;
        }
        .tab-btn.active {
          color: var(--text);
          border-bottom-color: #00ff88;
        }
        .input-field {
          width: 100%;
          background: rgba(255,255,255,0.04);
          border: 1px solid rgba(255,255,255,0.08);
          padding: 14px 16px;
          font-family: 'JetBrains Mono', monospace;
          font-size: 12px;
          color: #f0ede8;
          outline: none;
          transition: border-color 0.2s, box-shadow 0.2s;
          margin-bottom: 12px;
        }
        .input-field::placeholder {
          color: rgba(240,237,232,0.25);
        }
        .input-field:focus {
          border-color: rgba(0,255,136,0.5);
          box-shadow: 0 0 0 3px rgba(0,255,136,0.06);
        }
        .submit-btn {
          width: 100%;
          font-family: 'JetBrains Mono', monospace;
          font-size: 11px;
          font-weight: 500;
          letter-spacing: 0.12em;
          text-transform: uppercase;
          color: #060608;
          background: #00ff88;
          border: none;
          padding: 14px 36px;
          cursor: none;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          transition: all 0.2s;
          clip-path: polygon(10px 0%, 100% 0%, calc(100% - 10px) 100%, 0% 100%);
          margin-top: 8px;
        }
        .submit-btn:hover:not(:disabled) {
          box-shadow: 0 0 32px rgba(0,255,136,0.45);
          transform: translateY(-2px);
        }
        .submit-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .divider {
          width: 1px;
          background: rgba(255,255,255,0.06);
          min-height: 100vh;
        }
        @media (max-width: 768px) {
          .left-half { display: none; }
          .divider { display: none; }
        }
      `}</style>

      {/* LEFT HALF */}
      <div className="left-half" style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        <ParticleBackground />
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2,
        }}>
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: '700px',
            height: '400px',
            background: 'radial-gradient(ellipse, rgba(0,255,136,0.06) 0%, transparent 70%)',
            pointerEvents: 'none',
          }} />
          <p style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 500,
            fontSize: '28px',
            lineHeight: 1.4,
            color: 'rgba(240,237,232,0.7)',
            maxWidth: '380px',
            textAlign: 'center',
            marginBottom: '24px',
            position: 'relative',
            zIndex: 1,
          }}>
            &ldquo;Know your attack surface before someone else does.&rdquo;
          </p>
          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            color: 'rgba(240,237,232,0.3)',
            letterSpacing: '0.15em',
            textTransform: 'uppercase',
            position: 'relative',
            zIndex: 1,
          }}>
            NetSec AI Platform
          </p>
        </div>
      </div>

      <div className="divider" />

      {/* RIGHT HALF */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px',
      }}>
        <div className="form-card" style={{ maxWidth: '400px', width: '100%' }}>
          {/* Logo */}
          <Link href="/" style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            fontFamily: "'Syne', sans-serif",
            fontWeight: 600,
            fontSize: '18px',
            color: '#f0ede8',
            textDecoration: 'none',
            marginBottom: '40px',
            letterSpacing: '0.08em',
          }}>
            <span style={{
              width: '7px',
              height: '7px',
              background: '#00ff88',
              borderRadius: '50%',
              boxShadow: '0 0 12px #00ff88',
              display: 'inline-block',
            }} />
            NETSEC AI
          </Link>

          <h1 style={{
            fontFamily: "'Syne', sans-serif",
            fontWeight: 500,
            fontSize: '32px',
            color: '#f0ede8',
            marginBottom: '8px',
          }}>
            Access your dashboard
          </h1>
          <p style={{
            fontFamily: "'Instrument Sans', sans-serif",
            fontWeight: 300,
            fontSize: '14px',
            color: 'rgba(240,237,232,0.5)',
            marginBottom: '0',
          }}>
            Sign in or create an account to continue.
          </p>

          {/* Tabs */}
          <div style={{ display: 'flex', marginTop: '40px', marginBottom: '32px' }}>
            <button
              className={`tab-btn ${activeTab === 'signin' ? 'active' : ''}`}
              onClick={() => { setActiveTab('signin'); setMessage({ type: '', text: '' }) }}
            >
              Sign In
            </button>
            <button
              className={`tab-btn ${activeTab === 'signup' ? 'active' : ''}`}
              onClick={() => { setActiveTab('signup'); setMessage({ type: '', text: '' }) }}
            >
              Sign Up
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit}>
            <input
              type="email"
              className="input-field"
              placeholder="Email address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <input
              type="password"
              className="input-field"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {activeTab === 'signup' && (
              <input
                type="password"
                className="input-field"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            )}

            {message.text && (
              <p style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '11px',
                color: message.type === 'success' ? '#00ff88' : '#ff4560',
                marginTop: '12px',
                marginBottom: '8px',
              }}>
                {message.text}
              </p>
            )}

            <button
              type="submit"
              className="submit-btn"
              disabled={loading}
            >
              {loading ? '...' : activeTab === 'signin' ? 'Sign In →' : 'Create Account →'}
            </button>
          </form>

          <p style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '10px',
            color: 'rgba(240,237,232,0.3)',
            marginTop: '20px',
            letterSpacing: '0.05em',
          }}>
            Protected by Supabase Auth
          </p>
        </div>
      </div>
    </div>
  )
}
