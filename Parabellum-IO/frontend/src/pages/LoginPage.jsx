import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

export default function LoginPage() {
  const navigate = useNavigate();
  const [tab, setTab] = useState('login'); // 'login' | 'signup'
  const [step, setStep] = useState('form'); // 'form' | 'otp' | 'forgot' | 'reset'
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [org, setOrg] = useState('');
  const [otp, setOtp] = useState('');
  const [devOtp, setDevOtp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [remember, setRemember] = useState(true);
  const [resendIn, setResendIn] = useState(0);

  // Countdown for the "Resend code" button
  useEffect(() => {
    if (resendIn <= 0) return undefined;
    const t = setTimeout(() => setResendIn(s => s - 1), 1000);
    return () => clearTimeout(t);
  }, [resendIn]);

  useEffect(() => {
    if (localStorage.getItem('token')) navigate('/dashboard', { replace: true });
  }, [navigate]);

  async function handleLogin(e) {
    e.preventDefault();
    setError(''); setSuccess('');
    if (!email || !password) { setError('Email and password are required.'); return; }
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Login failed');
      setDevOtp(data.devOtp || '');
      setSuccess(data.message);
      setResendIn(data.resendInSeconds || 60);
      setStep('otp');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e) {
    e.preventDefault();
    setError(''); setSuccess('');
    if (!otp) { setError('Please enter the OTP code.'); return; }
    setLoading(true);
    try {
      const res = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: otp, remember }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Verification failed');
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleResend() {
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not resend the code');
      if (data.devOtp) setDevOtp(data.devOtp);
      setSuccess(data.message);
      setResendIn(data.resendInSeconds || 60);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Forgot password: send a reset code (same delivery as the login code)
  async function handleForgot(e) {
    e?.preventDefault();
    setError(''); setSuccess('');
    if (!email) { setError('Enter your e-mail address.'); return; }
    setLoading(true);
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Could not send the reset code');
      setDevOtp(data.devOtp || '');
      setSuccess(data.message);
      setResendIn(data.resendInSeconds || 60);
      setStep('reset');
    } catch (err) { setError(err.message); } finally { setLoading(false); }
  }

  async function handleReset(e) {
    e.preventDefault();
    setError('');
    if (!otp || !newPassword) { setError('Enter the code and a new password.'); return; }
    if (newPassword !== confirmPassword) { setError('The two passwords do not match.'); return; }
    setLoading(true);
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: otp, newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Password reset failed');
      setStep('form'); setTab('login'); setOtp(''); setDevOtp(''); setPassword(''); setNewPassword(''); setConfirmPassword('');
      setSuccess(data.message);
    } catch (err) { setError(err.message); } finally { setLoading(false); }
  }

  async function handleSignup(e) {
    e.preventDefault();
    setError(''); setSuccess('');
    if (!name || !email || !password) { setError('Name, email, and password are required.'); return; }
    setLoading(true);
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, organization: org, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        // One account per e-mail: send the user to Sign In instead of creating a second account
        if (data.code === 'EMAIL_EXISTS') {
          setTab('login'); setPassword('');
          setSuccess('');
          setError(data.error);
          return;
        }
        throw new Error(data.error || 'Signup failed');
      }
      setSuccess('Account created! Please log in.');
      setTab('login');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-logo">
          <img src="/logo.png" alt="Parabellum IO" onError={e => e.target.style.display='none'} />
          <h1>Parabellum IO</h1>
          <p>DevSecOps Compliance Platform</p>
        </div>

        {step === 'form' ? (
          <>
            <div className="auth-tabs">
              <button className={`auth-tab ${tab === 'login' ? 'active' : ''}`} onClick={() => { setTab('login'); setError(''); setSuccess(''); }}>Sign In</button>
              <button className={`auth-tab ${tab === 'signup' ? 'active' : ''}`} onClick={() => { setTab('signup'); setError(''); setSuccess(''); }}>Create Account</button>
            </div>

            {error && <div className="auth-error">⚠ {error}</div>}
            {success && <div className="auth-success">✓ {success}</div>}

            {tab === 'login' ? (
              <form onSubmit={handleLogin}>
                <div className="field">
                  <label>Email Address</label>
                  <input className="input" type="email" placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} />
                </div>
                <div className="field">
                  <label>Password</label>
                  <input className="input" type="password" placeholder="Your password" value={password} onChange={e => setPassword(e.target.value)} />
                </div>
                <button className="btn btn-primary" type="submit" style={{width:'100%',justifyContent:'center',padding:'11px'}} disabled={loading}>
                  {loading ? <><span className="spinner"/> Checking…</> : 'Sign In →'}
                </button>
                <button type="button" className="btn btn-ghost" style={{width:'100%',justifyContent:'center',marginTop:'8px',fontSize:'13px'}}
                  onClick={() => { setStep('forgot'); setError(''); setSuccess(''); }}>
                  Forgot password?
                </button>
              </form>
            ) : (
              <form onSubmit={handleSignup}>
                <div className="field">
                  <label>Full Name</label>
                  <input className="input" type="text" placeholder="Your name" value={name} onChange={e => setName(e.target.value)} />
                </div>
                <div className="field">
                  <label>Email Address</label>
                  <input className="input" type="email" placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} />
                </div>
                <div className="field">
                  <label>Organization (optional)</label>
                  <input className="input" type="text" placeholder="Your company" value={org} onChange={e => setOrg(e.target.value)} />
                </div>
                <div className="field">
                  <label>Password</label>
                  <input className="input" type="password" placeholder="Min 8 chars, uppercase, number, symbol" value={password} onChange={e => setPassword(e.target.value)} />
                </div>
                <button className="btn btn-primary" type="submit" style={{width:'100%',justifyContent:'center',padding:'11px'}} disabled={loading}>
                  {loading ? <><span className="spinner"/> Creating…</> : 'Create Account →'}
                </button>
              </form>
            )}
          </>
        ) : step === 'forgot' ? (
          <form onSubmit={handleForgot}>
            <h3 style={{margin:'0 0 6px'}}>Reset your password</h3>
            <p style={{fontSize:'13px',color:'var(--muted)',marginTop:0}}>Enter your account e-mail. We will send a 6-digit reset code.</p>
            {error && <div className="auth-error">⚠ {error}</div>}
            <div className="field">
              <label>Email Address</label>
              <input className="input" type="email" placeholder="you@example.com" value={email} onChange={e => setEmail(e.target.value)} />
            </div>
            <button className="btn btn-primary" type="submit" style={{width:'100%',justifyContent:'center',padding:'11px'}} disabled={loading}>
              {loading ? <><span className="spinner"/> Sending…</> : 'Send reset code →'}
            </button>
            <button type="button" className="btn btn-ghost" style={{width:'100%',justifyContent:'center',marginTop:'8px'}} onClick={() => { setStep('form'); setError(''); }}>
              ← Back to Sign In
            </button>
          </form>
        ) : step === 'reset' ? (
          <form onSubmit={handleReset}>
            <h3 style={{margin:'0 0 6px'}}>Choose a new password</h3>
            <div style={{fontSize:'13px',color:'var(--muted)',marginBottom:'8px'}}>{success}</div>
            {devOtp && (
              <div className="otp-box" style={{marginBottom:'14px'}}>
                <div style={{fontSize:'11px',color:'var(--muted)',marginBottom:'6px',textTransform:'uppercase',letterSpacing:'.05em'}}>Your reset code</div>
                <div className="otp-code">{devOtp}</div>
                <div style={{fontSize:'11px',color:'var(--muted)',marginTop:'6px'}}>Expires in 5 minutes</div>
              </div>
            )}
            {error && <div className="auth-error">⚠ {error}</div>}
            <div className="field">
              <label>Reset code</label>
              <input className="input" type="text" inputMode="numeric" autoComplete="one-time-code" placeholder="6-digit code" value={otp} onChange={e => setOtp(e.target.value.replace(/\D/g, ''))} maxLength={6} style={{fontSize:'18px',letterSpacing:'5px',textAlign:'center'}} />
            </div>
            <div className="field">
              <label>New password</label>
              <input className="input" type="password" autoComplete="new-password" placeholder="Min 8 chars, uppercase, number, symbol" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
            </div>
            <div className="field">
              <label>Confirm new password</label>
              <input className="input" type="password" autoComplete="new-password" value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} />
            </div>
            <button className="btn btn-primary" type="submit" style={{width:'100%',justifyContent:'center',padding:'11px'}} disabled={loading}>
              {loading ? <><span className="spinner"/> Saving…</> : 'Set new password →'}
            </button>
            <button type="button" className="btn btn-secondary" style={{width:'100%',justifyContent:'center',marginTop:'8px'}} disabled={loading || resendIn > 0} onClick={() => handleForgot()}>
              {resendIn > 0 ? `Resend code in ${resendIn}s` : '↻ Resend code'}
            </button>
            <button type="button" className="btn btn-ghost" style={{width:'100%',justifyContent:'center',marginTop:'8px'}} onClick={() => { setStep('form'); setOtp(''); setDevOtp(''); setError(''); }}>
              ← Back to Sign In
            </button>
          </form>
        ) : (
          /* OTP step */
          <form onSubmit={handleVerify}>
            <div style={{textAlign:'center',marginBottom:'20px'}}>
              <div style={{fontSize:'13px',color:'var(--muted)',marginBottom:'8px'}}>{success}</div>
              {devOtp && (
                <div className="otp-box">
                  <div style={{fontSize:'11px',color:'var(--muted)',marginBottom:'6px',textTransform:'uppercase',letterSpacing:'.05em'}}>Your login code</div>
                  <div className="otp-code">{devOtp}</div>
                  <div style={{fontSize:'11px',color:'var(--muted)',marginTop:'6px'}}>Expires in 5 minutes</div>
                </div>
              )}
            </div>
            {error && <div className="auth-error">⚠ {error}</div>}
            <div className="field">
              <label>OTP Code</label>
              <input className="input" type="text" inputMode="numeric" autoComplete="one-time-code" placeholder="Enter 6-digit code" value={otp} onChange={e => setOtp(e.target.value.replace(/\D/g, ''))} maxLength={6} style={{fontSize:'20px',letterSpacing:'6px',textAlign:'center'}} />
            </div>
            <label style={{display:'flex',alignItems:'center',gap:8,fontSize:'13px',color:'var(--muted)',marginBottom:'14px'}}>
              <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
              Keep me signed in on this device for 30 days
            </label>
            <button className="btn btn-primary" type="submit" style={{width:'100%',justifyContent:'center',padding:'11px'}} disabled={loading}>
              {loading ? <><span className="spinner"/> Verifying…</> : 'Verify & Login →'}
            </button>
            <button type="button" className="btn btn-secondary" style={{width:'100%',justifyContent:'center',marginTop:'8px'}} disabled={loading || resendIn > 0} onClick={handleResend}>
              {resendIn > 0 ? `Resend code in ${resendIn}s` : '↻ Resend code'}
            </button>
            <button type="button" className="btn btn-ghost" style={{width:'100%',justifyContent:'center',marginTop:'8px'}} onClick={() => { setStep('form'); setOtp(''); setDevOtp(''); setError(''); }}>
              ← Back
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
