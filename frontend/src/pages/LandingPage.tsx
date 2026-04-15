import { useEffect, useRef, useState } from "react";
import Navbar from "../components/layout/Navbar";

const loadScript = (src: string) =>
  new Promise<void>((res) => {
    if (document.querySelector(`script[src="${src}"]`)) return res();
    const s = Object.assign(document.createElement("script"), { src, onload: res });
    document.head.appendChild(s);
  });

const STATS = [
  { value: 98, suffix: "%", label: "Threat Detection Rate" },
  { value: 5, suffix: "min", label: "Avg Review Time" },
  { value: 25, suffix: "+", label: "Security Checks" },
  { value: 12000, suffix: "+", label: "PRs Analyzed" },
];

const STEPS = [
  {
    num: "01", icon: "🔗", title: "Connect Your Repo",
    desc: "Integrate with GitHub, GitLab, or Bitbucket in under 2 minutes. No agent, no infra changes required.",
    tag: "Setup",
  },
  {
    num: "02", icon: "🔍", title: "Analyze Every Change",
    desc: "Every PR diff is scanned for secrets, injection vectors, insecure patterns, and policy violations.",
    tag: "Scan",
  },
  {
    num: "03", icon: "✅", title: "Ship with Confidence",
    desc: "Receive inline review comments, a risk score, and a clear merge verdict before code lands in main.",
    tag: "Review",
  },
];

const FEATURES = [
  { icon: "🔐", color: "#38bdf8", title: "Secret Detection", desc: "Catches API keys, tokens, and credentials in diff hunks before they reach your repo history." },
  { icon: "📊", color: "#a78bfa", title: "Risk Scoring Engine", desc: "Weighted scoring across severity, confidence, and tool trust reduces decision fatigue on large teams." },
  { icon: "🚦", color: "#34d399", title: "Merge Gate Decision", desc: "Configurable policy thresholds block, warn, or approve based on your team's risk tolerance." },
  { icon: "💬", color: "#f472b6", title: "Inline Review Comments", desc: "Auto-generated comments mapped to exact file lines with remediation steps and reference links." },
  { icon: "🛡️", color: "#fb923c", title: "SAST Integration", desc: "Aggregates findings from Semgrep, Bandit, Snyk, and more into a unified review surface." },
  { icon: "⚙️", color: "#38bdf8", title: "Policy-as-Code", desc: "Define custom rules in YAML and version them alongside your application code." },
];

const THREATS = [
  { type: "CRITICAL", msg: "Hardcoded AWS secret key detected in config.py", file: "config.py", line: 142 },
  { type: "HIGH", msg: "SQL injection via unsanitized input in api/routes.js", file: "routes.js", line: 89 },
  { type: "MEDIUM", msg: "Unvalidated redirect target in auth/callback.ts", file: "callback.ts", line: 34 },
  { type: "HIGH", msg: "Prototype pollution via Object.assign in utils/merge.js", file: "merge.js", line: 17 },
  { type: "LOW", msg: "Debug endpoint left enabled in server.ts", file: "server.ts", line: 201 },
  { type: "CRITICAL", msg: "Private RSA key committed to repository at certs/dev.pem", file: "dev.pem", line: 1 },
] as const;

const SEV_COLORS: Record<(typeof THREATS)[number]["type"], string> = {
  CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e",
};

const PLANS = [
  {
    name: "Starter", price: "Free", period: "forever",
    features: ["5 repositories", "100 PRs / month", "Basic security checks", "Community support"],
    cta: "Get Started", variant: "secondary",
  },
  {
    name: "Pro", price: "$49", period: "per seat / month",
    features: ["Unlimited repos", "Unlimited PRs", "All security checks", "Slack & Jira alerts", "Custom policies", "Priority support"],
    cta: "Start Free Trial", variant: "primary", popular: true,
  },
  {
    name: "Enterprise", price: "Custom", period: "tailored pricing",
    features: ["Everything in Pro", "SSO / SAML", "Full audit logs", "99.9% SLA", "Dedicated CSM", "On-premise option"],
    cta: "Contact Sales", variant: "secondary",
  },
];

const TESTIMONIALS = [
  {
    name: "Aisha Kamara", role: "Head of Security @ Luminary",
    text: "ShieldSentinel cut our mean-time-to-detect by 73%. It's the first tool that actually fits inside the PR workflow instead of bolting on to the side.",
  },
  {
    name: "Ben Nakamura", role: "Staff Engineer @ Volta",
    text: "The inline comment quality is insane. It doesn't just flag issues - it tells you exactly how to fix them and links the CVE. Huge time-saver.",
  },
  {
    name: "Petra Horackova", role: "CTO @ Krosschain",
    text: "We replaced two separate tools with ShieldSentinel and our false-positive rate dropped to almost zero thanks to the risk scoring engine.",
  },
];

// ─── PR Review Scroll Animation Data ───────────────────────────────────────
const PR_LINES = [
  { type: "comment", content: "// User authentication route", indent: 0 },
  { type: "code", content: "app.post('/login', async (req, res) => {", indent: 0 },
  { type: "removed", content: "  const query = `SELECT * FROM users WHERE email='${req.body.email}'`;", indent: 1 },
  { type: "removed", content: "  const apiKey = 'sk-prod-8f2k9d3m1n7p4q6r';", indent: 1 },
  { type: "added", content: "  const query = 'SELECT * FROM users WHERE email = $1';", indent: 1 },
  { type: "added", content: "  const params = [req.body.email];", indent: 1 },
  { type: "code", content: "  const result = await db.query(query, params);", indent: 1 },
  { type: "code", content: "  if (!result.rows.length) return res.status(401).json({err: 'Invalid'});", indent: 1 },
  { type: "finding", label: "CRITICAL", content: "Hardcoded secret key detected on line 4 — rotate immediately", indent: 0 },
  { type: "finding", label: "HIGH", content: "SQL injection via template literal on line 3 — fixed on line 5", indent: 0 },
  { type: "code", content: "  const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET);", indent: 1 },
  { type: "code", content: "  res.json({ token });", indent: 1 },
  { type: "code", content: "});", indent: 0 },
  { type: "verdict", content: "✅ 2 findings remediated · Risk score: 12/100 · APPROVED to merge", indent: 0 },
];

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }

.r {
  font-family: 'Outfit', sans-serif;
  background: #f3f6fb;
  color: #1e3a8a;
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── Nav ── */
.nav { position: fixed; top: 0; left: 0; right: 0; z-index: 200; padding: 0 2rem; transition: background 0.4s ease, border-color 0.4s ease; }
.nav.scrolled { background: rgba(4,8,26,0.88); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px); border-bottom: 1px solid rgba(56,189,248,0.1); }
.nav-inner { max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; height: 70px; }
.logo { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; letter-spacing: -0.02em; color: #f1f5f9; text-decoration: none; }
.logo-icon { width: 36px; height: 36px; background: linear-gradient(135deg, #38bdf8 0%, #6366f1 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.nav-links { display: flex; gap: 2rem; list-style: none; }
.nav-links a { color: #64748b; text-decoration: none; font-size: 0.88rem; font-weight: 500; transition: color 0.2s; }
.nav-links a:hover { color: #e2e8f0; }
.nav-btns { display: flex; gap: 0.6rem; }
.btn-ghost { background: transparent; border: 1px solid rgba(100,116,139,0.35); color: #94a3b8; padding: 0.42rem 1.1rem; border-radius: 9px; font-size: 0.84rem; cursor: pointer; font-family: inherit; transition: all 0.2s; }
.btn-ghost:hover { border-color: rgba(56,189,248,0.5); color: #38bdf8; }
.btn-pill { background: #38bdf8; color: #04081a; padding: 0.42rem 1.2rem; border-radius: 9px; font-size: 0.84rem; font-weight: 700; cursor: pointer; border: none; font-family: inherit; transition: all 0.2s; }
.btn-pill:hover { background: #7dd3fc; }

/* ── Hero ── */
.hero { min-height: 100vh; display: flex; align-items: center; position: relative; overflow: hidden; padding: 9rem 2rem 5rem; }
.hero-bg-grid {
  position: absolute; inset: 0; z-index: 0;
  background-image: linear-gradient(rgba(56,189,248,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.035) 1px, transparent 1px);
  background-size: 64px 64px;
  -webkit-mask-image: radial-gradient(ellipse 90% 80% at 50% 40%, black 30%, transparent 100%);
  mask-image: radial-gradient(ellipse 90% 80% at 50% 40%, black 30%, transparent 100%);
}
.hero-glow-a { position: absolute; top: -160px; left: 50%; transform: translateX(-50%); width: 900px; height: 600px; background: radial-gradient(ellipse, rgba(56,189,248,0.07) 0%, transparent 65%); z-index: 0; pointer-events: none; }
.hero-glow-b { position: absolute; bottom: -80px; right: -120px; width: 600px; height: 600px; background: radial-gradient(ellipse, rgba(99,102,241,0.06) 0%, transparent 65%); z-index: 0; pointer-events: none; }
.hero-inner { max-width: 1200px; margin: 0 auto; width: 100%; position: relative; z-index: 2; }
.hero-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(56,189,248,0.07); border: 1px solid rgba(56,189,248,0.18); padding: 5px 14px; border-radius: 99px; font-size: 0.75rem; font-weight: 600; color: #38bdf8; margin-bottom: 1.75rem; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.02em; }
.badge-pulse { width: 6px; height: 6px; background: #38bdf8; border-radius: 50%; animation: bp 2s ease-in-out infinite; }
@keyframes bp { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.7)} }
.hero-h1 { font-size: clamp(2.8rem, 6.5vw, 5.6rem); font-weight: 900; line-height: 1.03; letter-spacing: -0.045em; color: #1e3a8a; margin-bottom: 1.6rem; perspective: 1000px; }
.hero-line { display: block; overflow: visible; }
.hero-char { display: inline-block; }
.hero-accent { color: #38bdf8; }
.hero-sub { font-size: 1.1rem; color: #1e3a8a; max-width: 540px; line-height: 1.75; margin-bottom: 2.5rem; font-weight: 400; }
.hero-cta { display: flex; gap: 0.9rem; flex-wrap: wrap; margin-bottom: 3.5rem; align-items: center; }
.btn-cta-primary { background: #38bdf8; color: #04081a; padding: 0.82rem 1.9rem; border-radius: 13px; font-size: 0.95rem; font-weight: 700; cursor: pointer; border: none; font-family: inherit; transition: all 0.25s; display: inline-flex; align-items: center; gap: 8px; }
.btn-cta-primary:hover { background: #7dd3fc; transform: translateY(-2px); box-shadow: 0 8px 24px rgba(56,189,248,0.25); }
.btn-cta-ghost { background: transparent; border: 1px solid rgba(15,23,42,0.2); color: #1e3a8a; padding: 0.82rem 1.9rem; border-radius: 13px; font-size: 0.95rem; font-weight: 500; cursor: pointer; font-family: inherit; transition: all 0.25s; display: inline-flex; align-items: center; gap: 8px; }
.btn-cta-ghost:hover { border-color: rgba(30,58,138,0.45); color: #1e3a8a; transform: translateY(-2px); }
.hero-trust { display: flex; gap: 1.5rem; flex-wrap: wrap; }
.trust-item { display: flex; align-items: center; gap: 7px; color: #475569; font-size: 0.8rem; font-weight: 500; }
.trust-check { color: #34d399; font-size: 0.85rem; }

/* ── Stats ── */
.stats-band { padding: 0 2rem 5rem; }
.stats-inner { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(4,1fr); border: 1px solid #dbeafe; border-radius: 22px; overflow: hidden; }
@media(max-width:760px){ .stats-inner { grid-template-columns: repeat(2,1fr); } }
.stat-cell { padding: 2.4rem 1.5rem; text-align: center; background: #f8fbff; border-right: 1px solid #e2e8f0; transition: background 0.3s; }
.stat-cell:last-child { border-right: none; }
.stat-cell:hover { background: #eff6ff; }
.stat-num { display: flex; align-items: baseline; justify-content: center; gap: 1px; font-size: 2.8rem; font-weight: 800; color: #1e3a8a; letter-spacing: -0.045em; line-height: 1; }
.stat-sfx { font-size: 1.6rem; }
.stat-lbl { color: #1e3a8a; font-size: 0.82rem; margin-top: 0.5rem; }

/* ── Section base ── */
.sec { padding: 7rem 2rem; }
.sec-inner { max-width: 1200px; margin: 0 auto; }
.sec-tag { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #38bdf8; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.65rem; }
.sec-h2 { font-size: clamp(1.9rem, 4vw, 3rem); font-weight: 800; letter-spacing: -0.035em; color: #1e3a8a; margin-bottom: 0.8rem; line-height: 1.12; }
.sec-sub { color: #1e3a8a; font-size: 0.95rem; max-width: 500px; line-height: 1.75; }
.sec-head { margin-bottom: 3.5rem; }

/* ── Steps ── */
.steps-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px,1fr)); gap: 1.5rem; }
.step-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 22px; padding: 2.2rem; position: relative; overflow: hidden; transition: border-color 0.35s, transform 0.35s; cursor: default; }
.step-card:hover { border-color: rgba(56,189,248,0.35); transform: translateY(-5px); }
.step-card::after { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, rgba(56,189,248,0.05) 0%, transparent 60%); opacity: 0; transition: opacity 0.35s; }
.step-card:hover::after { opacity: 1; }
.step-label { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #38bdf8; background: rgba(56,189,248,0.08); border: 1px solid rgba(56,189,248,0.18); display: inline-block; padding: 3px 10px; border-radius: 5px; margin-bottom: 1.4rem; letter-spacing: 0.05em; }
.step-icon-box { width: 52px; height: 52px; background: rgba(56,189,248,0.07); border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; margin-bottom: 1.3rem; border: 1px solid rgba(56,189,248,0.12); }
.step-title { font-size: 1.08rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.55rem; }
.step-desc { color: #1e3a8a; font-size: 0.875rem; line-height: 1.7; }

/* ── Features ── */
.feat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(310px,1fr)); gap: 1.25rem; }
.feat-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 18px; padding: 1.8rem; transition: border-color 0.3s, background 0.3s, transform 0.3s; cursor: default; }
.feat-card:hover { border-color: rgba(56,189,248,0.28); background: #f8fbff; transform: translateY(-3px); }
.feat-icon-box { width: 42px; height: 42px; border-radius: 13px; display: flex; align-items: center; justify-content: center; font-size: 1.25rem; margin-bottom: 1rem; }
.feat-title { font-size: 0.95rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.45rem; }
.feat-desc { color: #1e3a8a; font-size: 0.84rem; line-height: 1.7; }

/* ── PR Review Scroll Animation ── */
.pr-review-section { padding: 7rem 2rem 3.5rem; background: #f8fbff; min-height: 120vh; }
.pr-review-inner { max-width: 1200px; margin: 0 auto; }
.pr-sticky-wrapper { display: grid; grid-template-columns: 1fr 1fr; gap: 4rem; align-items: start; }
@media(max-width:900px) {
  .pr-review-section { min-height: auto; }
  .pr-sticky-wrapper { grid-template-columns: 1fr; }
}
.pr-sticky-left { position: sticky; top: 120px; }
.pr-code-sticky { position: sticky; top: 120px; align-self: start; }
.pr-sticky-title { font-size: clamp(1.7rem, 3.5vw, 2.6rem); font-weight: 800; color: #1e3a8a; letter-spacing: -0.03em; line-height: 1.15; margin-bottom: 1rem; }
.pr-sticky-sub { color: #475569; font-size: 0.95rem; line-height: 1.75; max-width: 400px; margin-bottom: 2rem; }
.pr-progress-bar { width: 100%; height: 4px; background: #e2e8f0; border-radius: 2px; overflow: hidden; margin-bottom: 1.5rem; }
.pr-progress-fill { height: 100%; background: linear-gradient(90deg, #38bdf8, #6366f1); border-radius: 2px; transition: width 0.1s linear; width: 0%; }
.pr-step-indicators { display: flex; flex-direction: column; gap: 0.75rem; }
.pr-step-ind { display: flex; align-items: center; gap: 12px; padding: 0.6rem 1rem; border-radius: 10px; transition: all 0.3s; opacity: 0.4; }
.pr-step-ind.active { opacity: 1; background: rgba(56,189,248,0.06); border: 1px solid rgba(56,189,248,0.15); }
.pr-step-dot { width: 8px; height: 8px; border-radius: 50%; background: #cbd5e1; flex-shrink: 0; transition: background 0.3s; }
.pr-step-ind.active .pr-step-dot { background: #38bdf8; }
.pr-step-label { font-size: 0.82rem; font-weight: 600; color: #475569; font-family: 'JetBrains Mono', monospace; }
.pr-step-ind.active .pr-step-label { color: #1e3a8a; }

.pr-code-window { background: #0f172a; border-radius: 18px; overflow: hidden; border: 1px solid rgba(56,189,248,0.15); }
.pr-code-bar { display: flex; align-items: center; gap: 8px; padding: 0.85rem 1.2rem; background: #1e293b; border-bottom: 1px solid rgba(255,255,255,0.05); }
.pr-code-dot { width: 12px; height: 12px; border-radius: 50%; }
.pr-code-filename { font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #64748b; margin-left: 6px; }
.pr-code-body { padding: 1rem 0; min-height: 420px; }
@media(max-width:900px) { .pr-code-sticky, .pr-sticky-left { position: static; top: auto; } }
.pr-line { display: flex; align-items: flex-start; gap: 12px; padding: 0.22rem 1.2rem; font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; line-height: 1.65; opacity: 0; transform: translateX(-12px); transition: opacity 0.4s ease, transform 0.4s ease; }
.pr-line.visible { opacity: 1; transform: translateX(0); }
.pr-line.removed { background: rgba(239,68,68,0.08); border-left: 2px solid #ef4444; }
.pr-line.added { background: rgba(52,211,153,0.08); border-left: 2px solid #34d399; }
.pr-line.finding { background: rgba(251,146,60,0.08); border-left: 2px solid #fb923c; margin: 0.2rem 0; }
.pr-line.verdict { background: rgba(56,189,248,0.08); border-left: 2px solid #38bdf8; margin-top: 0.5rem; }
.pr-line-prefix { color: #475569; user-select: none; min-width: 14px; font-size: 0.7rem; margin-top: 2px; }
.pr-line.removed .pr-line-prefix { color: #ef4444; }
.pr-line.added .pr-line-prefix { color: #34d399; }
.pr-line-content { color: #e2e8f0; flex: 1; }
.pr-line.removed .pr-line-content { color: #fca5a5; }
.pr-line.added .pr-line-content { color: #86efac; }
.pr-finding-badge { font-size: 0.65rem; font-weight: 700; padding: 2px 7px; border-radius: 4px; white-space: nowrap; flex-shrink: 0; margin-top: 2px; }
.pr-line.verdict .pr-line-content { color: #38bdf8; font-weight: 600; }

/* ── Carousel for Testimonials ── */
.carousel-wrapper { position: relative; overflow: hidden; }
.carousel-track { display: flex; gap: 0; transition: transform 0.55s cubic-bezier(0.25, 0.46, 0.45, 0.94); will-change: transform; }
.carousel-track .testi-card { min-width: 33.333%; flex-shrink: 0; }
@media(max-width:900px) { .carousel-track .testi-card { min-width: 50%; } }
@media(max-width:600px) { .carousel-track .testi-card { min-width: 100%; } }
.carousel-controls { display: flex; align-items: center; gap: 1rem; margin-top: 2rem; justify-content: center; }
.carousel-btn { width: 42px; height: 42px; border-radius: 50%; border: 1px solid #dbeafe; background: #fff; color: #1e3a8a; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-size: 1rem; }
.carousel-btn:hover { background: #1e3a8a; color: #fff; border-color: #1e3a8a; }
.carousel-btn:disabled { opacity: 0.35; cursor: not-allowed; }
.carousel-dots { display: flex; gap: 6px; }
.carousel-dot { width: 8px; height: 8px; border-radius: 50%; background: #dbeafe; cursor: pointer; transition: all 0.25s; border: none; padding: 0; }
.carousel-dot.active { background: #1e3a8a; width: 22px; border-radius: 4px; }

/* ── Testimonials card ── */
.testi-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 20px; padding: 2rem; transition: border-color 0.3s, transform 0.3s; }
.testi-card:hover { border-color: rgba(56,189,248,0.25); transform: translateY(-3px); }
.testi-quote { font-size: 0.92rem; color: #1e3a8a; line-height: 1.75; margin-bottom: 1.5rem; font-style: italic; }
.testi-author { display: flex; align-items: center; gap: 12px; }
.testi-avatar { width: 40px; height: 40px; border-radius: 50%; background: rgba(56,189,248,0.12); border: 1px solid rgba(56,189,248,0.2); display: flex; align-items: center; justify-content: center; font-size: 0.9rem; font-weight: 700; color: #38bdf8; flex-shrink: 0; }
.testi-name { font-size: 0.88rem; font-weight: 700; color: #1e3a8a; }
.testi-role { font-size: 0.78rem; color: #1e3a8a; margin-top: 2px; }
.stars { color: #38bdf8; font-size: 0.75rem; letter-spacing: 2px; margin-bottom: 0.8rem; }

/* ── Console ── */
.console-wrap { background: #ffffff; border: 1px solid #dbeafe; border-radius: 20px; overflow: hidden; }
.console-bar { padding: 0.9rem 1.4rem; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display: flex; align-items: center; gap: 9px; }
.cdot { width: 13px; height: 13px; border-radius: 50%; }
.cbar-title { font-family: 'JetBrains Mono', monospace; font-size: 0.77rem; color: #1e3a8a; margin-left: 6px; }
.cbar-status { margin-left: auto; display: flex; align-items: center; gap: 6px; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #34d399; }
.cbar-dot { width: 6px; height: 6px; background: #34d399; border-radius: 50%; animation: bp 1.4s ease-in-out infinite; }
.console-body { padding: 1.4rem 1.4rem 1.6rem; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.85; min-height: 310px; position: relative; overflow: hidden; }
.scan-bar { position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent 0%, #38bdf8 50%, transparent 100%); animation: scan-slide 2.4s linear infinite; opacity: 0.5; }
@keyframes scan-slide { 0%{transform:translateY(0)} 100%{transform:translateY(310px)} }
.c-row { display: flex; align-items: flex-start; gap: 12px; padding: 0.28rem 0; border-bottom: 1px solid rgba(56,189,248,0.04); }
.sev-badge { padding: 2px 9px; border-radius: 5px; font-size: 0.67rem; font-weight: 700; white-space: nowrap; letter-spacing: 0.04em; flex-shrink: 0; margin-top: 2px; }
.c-msg { color: #1e3a8a; font-size: 0.77rem; transition: color 0.4s; }
.c-row.lit .c-msg { color: #1e3a8a; }
.c-file { color: #38bdf8; font-size: 0.7rem; margin-top: 1px; opacity: 0.7; }
.c-verdict { color: #38bdf8; margin-top: 1rem; font-size: 0.78rem; }
.c-blocked { color: #ef4444; font-weight: 700; }

/* ── Plans ── */
.plans-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(270px,1fr)); gap: 1.5rem; }
.plan-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 24px; padding: 2.2rem; position: relative; transition: transform 0.3s, border-color 0.3s; }
.plan-card:hover { transform: translateY(-5px); }
.plan-card.pop { border-color: rgba(56,189,248,0.5); background: rgba(56,189,248,0.035); }
.pop-badge { position: absolute; top: -1px; left: 50%; transform: translateX(-50%); background: #38bdf8; color: #04081a; font-size: 0.68rem; font-weight: 800; padding: 4px 18px; border-radius: 0 0 10px 10px; letter-spacing: 0.06em; }
.plan-name { font-size: 0.82rem; font-weight: 600; color: #1e3a8a; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.8rem; padding-top: 0.6rem; }
.plan-price { font-size: 3rem; font-weight: 900; letter-spacing: -0.05em; color: #1e3a8a; line-height: 1; }
.plan-price-sub { font-size: 0.85rem; color: #1e3a8a; margin-top: 0.3rem; margin-bottom: 1.5rem; font-weight: 400; }
.plan-sep { height: 1px; background: rgba(56,189,248,0.08); margin-bottom: 1.5rem; }
.plan-feat-list { list-style: none; display: flex; flex-direction: column; gap: 0.65rem; margin-bottom: 2rem; }
.plan-feat-list li { display: flex; align-items: center; gap: 9px; font-size: 0.86rem; color: #1e3a8a; }
.feat-check { color: #34d399; font-size: 0.8rem; flex-shrink: 0; }
.plan-cta { width: 100%; padding: 0.8rem; border-radius: 13px; font-size: 0.9rem; font-weight: 700; cursor: pointer; font-family: inherit; transition: all 0.22s; letter-spacing: -0.01em; }
.plan-cta.p { background: #38bdf8; color: #04081a; border: none; }
.plan-cta.p:hover { background: #7dd3fc; }
.plan-cta.s { background: transparent; border: 1px solid rgba(30,58,138,0.28); color: #1e3a8a; }
.plan-cta.s:hover { border-color: rgba(30,58,138,0.5); color: #1e3a8a; }

/* ── CTA ── */
.cta-sec { padding: 6rem 2rem; position: relative; overflow: hidden; }
.cta-glow { position: absolute; inset: 0; background: radial-gradient(ellipse 65% 75% at 50% 50%, rgba(56,189,248,0.055), transparent); pointer-events: none; }
.cta-inner { max-width: 1200px; margin: 0 auto; position: relative; z-index: 1; }
.cta-box { background: #f8fbff; border: 1px solid #dbeafe; border-radius: 30px; padding: 5rem 3rem; text-align: center; backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); }
.cta-h2 { font-size: clamp(2rem, 4.5vw, 3.4rem); font-weight: 900; letter-spacing: -0.045em; color: #1e3a8a; margin-bottom: 1rem; line-height: 1.1; }
.cta-sub { color: #1e3a8a; font-size: 1rem; max-width: 460px; margin: 0 auto 2.5rem; line-height: 1.75; }
.cta-btns { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; }

/* ── Footer ── */
.footer { padding: 2.5rem 2rem; border-top: 1px solid rgba(56,189,248,0.07); }
.footer-inner { max-width: 1200px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; }
.footer-logo { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 0.95rem; color: #1e3a8a; }
.footer-copy { color: #1e3a8a; font-size: 0.78rem; }
.footer-links { display: flex; gap: 1.5rem; }
.footer-links a { color: #1e3a8a; text-decoration: none; font-size: 0.78rem; transition: color 0.2s; }
.footer-links a:hover { color: #1d4ed8; }

/* ── GSAP Reveal Utility (will be toggled by JS) ── */
.reveal-from-left { opacity: 0; transform: translateX(-60px); }
.reveal-from-right { opacity: 0; transform: translateX(60px); }
.reveal-from-bottom { opacity: 0; transform: translateY(60px); }
.reveal-from-top { opacity: 0; transform: translateY(-40px); }
.reveal-scale { opacity: 0; transform: scale(0.88); }

/* ── Cursor glow blob ── */
.cursor-glow {
  position: fixed; pointer-events: none; z-index: 9;
  width: 520px; height: 520px; border-radius: 50%;
  background: radial-gradient(ellipse, rgba(56,189,248,0.09) 0%, rgba(99,102,241,0.05) 40%, transparent 70%);
  transform: translate(-50%,-50%);
  transition: opacity 0.4s;
  will-change: left, top;
}

/* ── Floating orbs ── */
.orb { position: absolute; border-radius: 50%; pointer-events: none; filter: blur(72px); }
.orb-1 { width: 360px; height: 360px; background: rgba(56,189,248,0.09); top: 8%; left: 2%; animation: orb-float 9s ease-in-out infinite; }
.orb-2 { width: 260px; height: 260px; background: rgba(99,102,241,0.07); top: 45%; right: 5%; animation: orb-float 11s ease-in-out infinite reverse; }
.orb-3 { width: 200px; height: 200px; background: rgba(52,211,153,0.06); bottom: 18%; left: 38%; animation: orb-float 7.5s ease-in-out infinite 1.8s; }
@keyframes orb-float {
  0%,100% { transform: translateY(0) translateX(0) scale(1); }
  33%  { transform: translateY(-28px) translateX(14px) scale(1.06); }
  66%  { transform: translateY(14px) translateX(-10px) scale(0.96); }
}

/* ── Hero badge pulse glow ── */
@keyframes badge-glow-pulse {
  0%,100% { box-shadow: 0 0 0 0 rgba(56,189,248,0); border-color: rgba(56,189,248,0.18); }
  50%     { box-shadow: 0 0 22px 3px rgba(56,189,248,0.14); border-color: rgba(56,189,248,0.48); }
}
.hero-badge { animation: badge-glow-pulse 3.2s ease-in-out infinite; }

/* ── 3D tilt cards ── */
.step-card, .feat-card {
  transform-style: preserve-3d; will-change: transform;
  background-image: radial-gradient(ellipse at var(--mx,50%) var(--my,50%), rgba(56,189,248,0.05) 0%, transparent 65%);
  transition: border-color 0.35s, transform 0.12s ease, box-shadow 0.35s;
}
.step-card:hover, .feat-card:hover {
  box-shadow: 0 28px 70px rgba(30,58,138,0.1), 0 0 0 1px rgba(56,189,248,0.18);
}

/* ── Ripple click ── */
.ripple-btn { position: relative; overflow: hidden; }
.ripple-circle {
  position: absolute; border-radius: 50%;
  background: rgba(255,255,255,0.3);
  transform: scale(0); animation: ripple-out 0.65s ease forwards;
  pointer-events: none;
}
@keyframes ripple-out { to { transform: scale(4); opacity: 0; } }

/* ── Magnetic button glow ── */
.btn-mag { position: relative; }
.btn-mag::before {
  content: ''; position: absolute; inset: -4px; border-radius: 17px;
  background: linear-gradient(135deg, rgba(56,189,248,0.4), rgba(99,102,241,0.3));
  filter: blur(10px); opacity: 0; z-index: -1; transition: opacity 0.3s;
}
.btn-mag:hover::before { opacity: 1; }

/* ── Shimmer sweep on stat cells ── */
.stat-cell { position: relative; overflow: hidden; }
.stat-cell::after {
  content: ''; position: absolute; top: 0; left: -100%; width: 60%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(56,189,248,0.06), transparent);
  animation: shimmer-sweep 4s ease-in-out infinite;
}
@keyframes shimmer-sweep { 0%{left:-60%} 50%,100%{left:140%} }

/* ── Icon bounce on card hover ── */
.feat-card:hover .feat-icon-box {
  animation: icon-pop 0.45s cubic-bezier(0.36,0.07,0.19,0.97);
}
@keyframes icon-pop {
  0%,100%{transform:translateY(0) scale(1)}
  35%{transform:translateY(-7px) scale(1.12)}
  65%{transform:translateY(2px) scale(0.95)}
}

/* ── Blinking cursor on sec-tag ── */
@keyframes cursor-blink { 0%,100%{opacity:1} 50%{opacity:0} }
.sec-tag::after { content:'_'; animation: cursor-blink 1.1s step-end infinite; margin-left:1px; }

/* ── Trust items subtle float ── */
@keyframes trust-bob { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-5px)} }
.trust-item:nth-child(1){animation:trust-bob 4s ease-in-out infinite}
.trust-item:nth-child(2){animation:trust-bob 4s ease-in-out infinite 0.6s}
.trust-item:nth-child(3){animation:trust-bob 4s ease-in-out infinite 1.2s}
.trust-item:nth-child(4){animation:trust-bob 4s ease-in-out infinite 1.8s}

/* ── Popular plan card pulse glow ── */
@keyframes pop-glow {
  0%,100%{box-shadow:0 0 0 0 rgba(56,189,248,0)}
  50%{box-shadow:0 0 36px 6px rgba(56,189,248,0.13)}
}
.plan-card.pop { animation: pop-glow 3s ease-in-out infinite; }

/* ── Stat numbers subtle glow ── */
@keyframes num-glow { 0%,100%{text-shadow:none} 50%{text-shadow:0 0 18px rgba(30,58,138,0.18)} }
.stat-num { animation: num-glow 3.5s ease-in-out infinite; }

/* ── CTA box gradient shimmer ── */
@keyframes cta-shift {
  0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%}
}
.cta-box {
  background: linear-gradient(135deg,#f0f7ff 0%,#e8f3ff 35%,#eef6ff 65%,#f0f7ff 100%);
  background-size: 300% 300%;
  animation: cta-shift 7s ease infinite;
}

/* ── Hero grid fade in ── */
@keyframes grid-reveal { from{opacity:0} to{opacity:1} }
.hero-bg-grid { animation: grid-reveal 2.2s ease forwards; }

/* ── Steps connector line ── */
.steps-grid { position: relative; }
`;

const PR_STEPS = [
  { label: "fetch diff", line: 0 },
  { label: "detect removed", line: 2 },
  { label: "flag secrets", line: 3 },
  { label: "verify fixes", line: 4 },
  { label: "run sast", line: 8 },
  { label: "issue verdict", line: 13 },
];

export default function ShieldSentinel() {
  const [gsapReady, setGsapReady] = useState(false);
  const [activeThreat, setActiveThreat] = useState(0);
  const [visiblePrLines, setVisiblePrLines] = useState(0);
  const [prProgress, setPrProgress] = useState(0);
  const [activePrStep, setActivePrStep] = useState(0);
  const [carouselIdx, setCarouselIdx] = useState(0);
  const [itemsPerView, setItemsPerView] = useState(() => {
    if (typeof window === "undefined") return 3;
    if (window.innerWidth < 600) return 1;
    if (window.innerWidth < 900) return 2;
    return 3;
  });

  const heroRef = useRef<HTMLDivElement | null>(null);
  const statsRef = useRef<HTMLDivElement | null>(null);
  const stepsRef = useRef<HTMLDivElement | null>(null);
  const featRef = useRef<HTMLDivElement | null>(null);
  const consoleRef = useRef<HTMLDivElement | null>(null);
  const testiRef = useRef<HTMLDivElement | null>(null);
  const plansRef = useRef<HTMLDivElement | null>(null);
  const ctaRef = useRef<HTMLElement | null>(null);
  const prSectionRef = useRef<HTMLElement | null>(null);
  const prProgressFillRef = useRef<HTMLDivElement | null>(null);

  // Carousel items per view
  const maxIdx = Math.max(0, TESTIMONIALS.length - itemsPerView);

  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth < 600) setItemsPerView(1);
      else if (window.innerWidth < 900) setItemsPerView(2);
      else setItemsPerView(3);
    };
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    setCarouselIdx((prev) => Math.min(prev, maxIdx));
  }, [maxIdx]);

  useEffect(() => {
    (async () => {
      await loadScript("https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js");
      await loadScript("https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/ScrollTrigger.min.js");
      const w = window as any;
      if (w.gsap && w.ScrollTrigger) {
        w.gsap.registerPlugin(w.ScrollTrigger);
        setGsapReady(true);
      }
    })();
  }, []);

  // Cycling threat highlight
  useEffect(() => {
    const id = setInterval(() => setActiveThreat((n) => (n + 1) % THREATS.length), 2200);
    return () => clearInterval(id);
  }, []);

  // ── Cursor glow blob follows mouse ──
  useEffect(() => {
    const glow = document.querySelector<HTMLElement>(".cursor-glow");
    if (!glow) return;
    let raf = 0;
    const onMove = (e: MouseEvent) => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        glow.style.left = `${e.clientX}px`;
        glow.style.top = `${e.clientY}px`;
      });
    };
    window.addEventListener("mousemove", onMove);
    return () => { window.removeEventListener("mousemove", onMove); cancelAnimationFrame(raf); };
  }, []);

  // ── Hero glow parallax follows mouse ──
  useEffect(() => {
    const glowA = document.querySelector<HTMLElement>(".hero-glow-a");
    const glowB = document.querySelector<HTMLElement>(".hero-glow-b");
    if (!glowA || !glowB) return;
    let raf = 0;
    const onMove = (e: MouseEvent) => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const xp = (e.clientX / window.innerWidth - 0.5) * 2;
        const yp = (e.clientY / window.innerHeight - 0.5) * 2;
        glowA.style.transform = `translateX(calc(-50% + ${xp * 35}px)) translateY(${yp * 22}px)`;
        glowB.style.transform = `translateX(${-xp * 22}px) translateY(${-yp * 18}px)`;
      });
    };
    window.addEventListener("mousemove", onMove);
    return () => { window.removeEventListener("mousemove", onMove); cancelAnimationFrame(raf); };
  }, []);

  // ── 3D perspective tilt on cards ──
  useEffect(() => {
    const cards = document.querySelectorAll<HTMLElement>(".feat-card, .step-card");
    const cleanup: Array<() => void> = [];
    cards.forEach((card) => {
      const onMove = (e: MouseEvent) => {
        const r = card.getBoundingClientRect();
        const cx = r.left + r.width / 2;
        const cy = r.top + r.height / 2;
        const dx = (e.clientX - cx) / (r.width / 2);
        const dy = (e.clientY - cy) / (r.height / 2);
        card.style.transform = `perspective(820px) rotateY(${dx * 7}deg) rotateX(${-dy * 7}deg) translateY(-5px)`;
        card.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
        card.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
      };
      const onLeave = () => { card.style.transform = ""; };
      card.addEventListener("mousemove", onMove);
      card.addEventListener("mouseleave", onLeave);
      cleanup.push(() => { card.removeEventListener("mousemove", onMove); card.removeEventListener("mouseleave", onLeave); });
    });
    return () => cleanup.forEach((fn) => fn());
  }, [gsapReady]);

  // ── Magnetic pull on CTA buttons ──
  useEffect(() => {
    const btns = document.querySelectorAll<HTMLElement>(".btn-mag");
    const cleanup: Array<() => void> = [];
    btns.forEach((btn) => {
      const onMove = (e: MouseEvent) => {
        const r = btn.getBoundingClientRect();
        const dx = (e.clientX - r.left - r.width / 2) * 0.2;
        const dy = (e.clientY - r.top - r.height / 2) * 0.2;
        btn.style.transform = `translate(${dx}px, ${dy}px)`;
      };
      const onLeave = () => { btn.style.transform = ""; };
      btn.addEventListener("mousemove", onMove);
      btn.addEventListener("mouseleave", onLeave);
      cleanup.push(() => { btn.removeEventListener("mousemove", onMove); btn.removeEventListener("mouseleave", onLeave); });
    });
    return () => cleanup.forEach((fn) => fn());
  }, [gsapReady]);

  // PR scroll progress
  useEffect(() => {
    const handleScroll = () => {
      if (!prSectionRef.current) return;
      const rect = prSectionRef.current.getBoundingClientRect();
      const winH = window.innerHeight;
      const sectionH = prSectionRef.current.offsetHeight;

      // Use a viewport anchor so progress starts when the section is actually in view.
      const viewportAnchor = winH * 0.65;
      const scrolledInSection = viewportAnchor - rect.top;
      const effectiveScrollable = Math.max(1, sectionH - viewportAnchor + winH * 0.2);
      const progress = Math.max(0, Math.min(1, scrolledInSection / effectiveScrollable));
      const inView = rect.top < winH * 0.88 && rect.bottom > winH * 0.2;

      setPrProgress(progress);
      const lines = inView ? Math.max(2, Math.ceil(progress * PR_LINES.length)) : 0;
      setVisiblePrLines(Math.min(PR_LINES.length, lines));
      const stepIdx = inView ? Math.min(PR_STEPS.length - 1, Math.floor(progress * PR_STEPS.length)) : 0;
      setActivePrStep(stepIdx);
      if (prProgressFillRef.current) prProgressFillRef.current.style.width = `${progress * 100}%`;
    };

    // Run once immediately so the section is never blank on first paint.
    handleScroll();
    window.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", handleScroll);
    return () => {
      window.removeEventListener("scroll", handleScroll);
      window.removeEventListener("resize", handleScroll);
    };
  }, []);

  // GSAP animations
  useEffect(() => {
    if (!gsapReady) return;
    const w = window as any;
    const gsap = w.gsap;
    const ST = w.ScrollTrigger;
    if (!gsap || !ST) return;

    const ctx = gsap.context(() => {
      // ── Hero character animation ──
      const chars = heroRef.current?.querySelectorAll(".hero-char");
      if (chars?.length) {
        gsap.from(chars, {
          opacity: 0, y: 50, rotationX: -70,
          transformOrigin: "0% 50% -40px",
          stagger: { each: 0.022, from: "start" },
          duration: 0.65, ease: "back.out(1.4)",
        });
      }
      gsap.from(heroRef.current?.querySelectorAll(".hero-sub, .hero-cta, .hero-trust"), {
        opacity: 0, y: 28, stagger: 0.12, duration: 0.8, delay: 0.6, ease: "power3.out",
      });

      // ── Stats counter ──
      const statEls = statsRef.current?.querySelectorAll(".stat-num-val");
      statEls?.forEach((el, i) => {
        const statEl = el as HTMLElement;
        const target = STATS[i].value;
        gsap.fromTo(statEl, { innerText: 0 }, {
          innerText: target, duration: 1.8, ease: "power2.out", snap: { innerText: 1 },
          onUpdate() { statEl.innerText = Math.round(+statEl.innerText).toLocaleString(); },
          scrollTrigger: { trigger: statEl, start: "top 88%", once: true },
        });
      });

      // ── Steps: slide from left / right alternating ──
      const stepCards = stepsRef.current?.querySelectorAll(".step-card");
      stepCards?.forEach((card, i) => {
        gsap.from(card, {
          opacity: 0, x: i % 2 === 0 ? -70 : 70, y: 20,
          duration: 0.9, ease: "power3.out",
          scrollTrigger: { trigger: card, start: "top 82%", once: true },
        });
      });

      // ── Features: staggered from bottom with scale ──
      const featCards = featRef.current?.querySelectorAll(".feat-card");
      featCards?.forEach((card, i) => {
        gsap.from(card, {
          opacity: 0, y: 50 + (i % 3) * 15, scale: 0.94, rotationY: i % 2 === 0 ? -5 : 5,
          duration: 0.75, ease: "power3.out",
          scrollTrigger: { trigger: card, start: "top 85%", once: true },
        });
      });

      // ── Console: slide in from right ──
      gsap.from(consoleRef.current, {
        opacity: 0, x: 80, duration: 1, ease: "power3.out",
        scrollTrigger: { trigger: consoleRef.current, start: "top 82%", once: true },
      });

      // ── PR section heading from top ──
      if (prSectionRef.current) {
        gsap.from(prSectionRef.current.querySelector(".pr-sticky-left"), {
          opacity: 0, x: -60, duration: 1, ease: "power3.out",
          scrollTrigger: { trigger: prSectionRef.current, start: "top 75%", once: true },
        });
        gsap.from(prSectionRef.current.querySelector(".pr-code-window"), {
          opacity: 0, x: 60, duration: 1, ease: "power3.out",
          scrollTrigger: { trigger: prSectionRef.current, start: "top 75%", once: true },
        });
      }

      // ── Plans: cascade from bottom ──
      const planCards = plansRef.current?.querySelectorAll(".plan-card");
      planCards?.forEach((card, i) => {
        gsap.from(card, {
          opacity: 0, y: 80, duration: 0.85, delay: i * 0.12, ease: "power3.out",
          scrollTrigger: { trigger: plansRef.current, start: "top 78%", once: true },
        });
      });

      // ── CTA parallax ──
      const ctaGlow = ctaRef.current?.querySelector(".cta-glow");
      if (ctaGlow) gsap.to(ctaGlow, { y: -60, scrollTrigger: { trigger: ctaRef.current, scrub: 1.8 } });

      // ── Section headings ──
      document.querySelectorAll(".sec-head").forEach((el) => {
        const kids = Array.from(el.children);
        kids.forEach((child, i) => {
          gsap.from(child, {
            opacity: 0, y: 28 + i * 8, duration: 0.7, ease: "power3.out",
            scrollTrigger: { trigger: child, start: "top 85%", once: true },
          });
        });
      });
    });

    return () => {
      ctx.revert();
      ST.getAll().forEach((t: any) => t.kill());
    };
  }, [gsapReady]);

  // ── Button ripple on click ──
  const createRipple = (e: React.MouseEvent<HTMLButtonElement>) => {
    const btn = e.currentTarget;
    const existing = btn.querySelector(".ripple-circle");
    if (existing) existing.remove();
    const circle = document.createElement("span");
    const diameter = Math.max(btn.clientWidth, btn.clientHeight);
    const radius = diameter / 2;
    const rect = btn.getBoundingClientRect();
    circle.className = "ripple-circle";
    circle.style.cssText = `width:${diameter}px;height:${diameter}px;left:${e.clientX - rect.left - radius}px;top:${e.clientY - rect.top - radius}px`;
    btn.appendChild(circle);
    setTimeout(() => circle.remove(), 700);
  };

  const splitChars = (text: string) =>
    text.split("").map((c, i) => (
      <span key={i} className="hero-char" style={{ display: "inline-block", whiteSpace: c === " " ? "pre" : "normal" }}>{c}</span>
    ));

  const getPrLinePrefix = (type: string) => {
    if (type === "removed") return "-";
    if (type === "added") return "+";
    if (type === "finding") return "⚠";
    if (type === "verdict") return "▶";
    return " ";
  };

  const getFindinBadgeStyle = (label: string) => {
    const colors: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308" };
    const c = colors[label] || "#38bdf8";
    return { background: `${c}18`, color: c, border: `1px solid ${c}30` };
  };

  const carouselOffset = -(carouselIdx * (100 / itemsPerView));

  return (
    <div className="r">
      <style>{CSS}</style>
      {/* ── Global cursor glow blob ── */}
      <div className="cursor-glow" aria-hidden="true" />
      <Navbar />

      {/* ── Hero ── */}
      <section className="hero">
        <div className="hero-bg-grid" />
        <div className="hero-glow-a" />
        <div className="hero-glow-b" />
        {/* ── Floating ambient orbs ── */}
        <div className="orb orb-1" aria-hidden="true" />
        <div className="orb orb-2" aria-hidden="true" />
        <div className="orb orb-3" aria-hidden="true" />
        <div className="hero-inner" ref={heroRef}>
          <div className="hero-badge">
            <span className="badge-pulse" />
            v2.4 - Now with SAST integration
          </div>
          <h1 className="hero-h1">
            <span className="hero-line">{splitChars("Security reviews")}</span>
            <span className="hero-line">{splitChars("that ship faster")}</span>
            <span className="hero-line hero-accent">{splitChars("than attackers.")}</span>
          </h1>
          <p className="hero-sub">
            ShieldSentinel scans every pull request for secrets, injection vectors, and policy violations — and posts inline comments before a human ever opens the PR.
          </p>
          <div className="hero-cta">
            <button className="btn-cta-primary btn-mag ripple-btn" onClick={createRipple}>
              Run Live Demo
              <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
                <path d="M2.5 7.5h10M8.5 3.5l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            <button className="btn-cta-ghost btn-mag" onClick={createRipple}>View Documentation</button>
          </div>
          <div className="hero-trust">
            {["SOC 2 Type II", "GDPR Compliant", "Zero data retention", "Open-source rules"].map((b) => (
              <span key={b} className="trust-item"><span className="trust-check">✓</span> {b}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Stats ── */}
      <div className="stats-band">
        <div className="stats-inner" ref={statsRef}>
          {STATS.map((s) => (
            <div key={s.label} className="stat-cell">
              <div className="stat-num">
                <span className="stat-num-val">{s.value.toLocaleString()}</span>
                <span className="stat-sfx">{s.suffix}</span>
              </div>
              <p className="stat-lbl">{s.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── How It Works ── */}
      <section className="sec">
        <div className="sec-inner">
          <div className="sec-head">
            <div className="sec-tag">// workflow</div>
            <h2 className="sec-h2">How It Works</h2>
            <p className="sec-sub">Three focused steps from raw PR diff to a signed-off, merge-ready decision.</p>
          </div>
          <div className="steps-grid" ref={stepsRef}>
            {STEPS.map((s) => (
              <div key={s.num} className="step-card">
                <div className="step-label">Step {s.num}</div>
                <div className="step-icon-box">{s.icon}</div>
                <div className="step-title">{s.title}</div>
                <p className="step-desc">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Features ── */}
      <section className="sec" style={{ paddingTop: 0 }}>
        <div className="sec-inner">
          <div className="sec-head">
            <div className="sec-tag">// capabilities</div>
            <h2 className="sec-h2">Platform Capabilities</h2>
            <p className="sec-sub">Everything your security team needs to enforce standards across every PR, automatically.</p>
          </div>
          <div className="feat-grid" ref={featRef}>
            {FEATURES.map((f) => (
              <div key={f.title} className="feat-card">
                <div className="feat-icon-box" style={{ background: `${f.color}14`, color: f.color }}>{f.icon}</div>
                <div className="feat-title">{f.title}</div>
                <p className="feat-desc">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── PR Review Scroll Animation ── */}
      <section
        className="pr-review-section"
        ref={prSectionRef}
      >
        <div className="pr-review-inner">
          <div className="sec-head">
            <div className="sec-tag">// live review</div>
            <h2 className="sec-h2">Watch a PR Get Reviewed</h2>
            <p className="sec-sub">Scroll down to see ShieldSentinel analyze a real diff — line by line, in real time.</p>
          </div>
          <div className="pr-sticky-wrapper">
            {/* Left: Sticky progress */}
            <div className="pr-sticky-left">
              <div className="pr-sticky-title">AI-powered review, every single merge.</div>
              <p className="pr-sticky-sub">
                ShieldSentinel processes each changed line, correlates findings across the full diff, and issues a merge verdict in under 5 minutes.
              </p>
              <div className="pr-progress-bar">
                <div className="pr-progress-fill" ref={prProgressFillRef} />
              </div>
              <div className="pr-step-indicators">
                {PR_STEPS.map((step, i) => (
                  <div key={step.label} className={`pr-step-ind ${i <= activePrStep ? "active" : ""}`}>
                    <div className="pr-step-dot" />
                    <span className="pr-step-label">{step.label}</span>
                  </div>
                ))}
              </div>
            </div>
            {/* Right: Code window */}
            <div className="pr-code-sticky">
              <div className="pr-code-window">
                <div className="pr-code-bar">
                  <span className="pr-code-dot" style={{ background: "#ef4444" }} />
                  <span className="pr-code-dot" style={{ background: "#eab308" }} />
                  <span className="pr-code-dot" style={{ background: "#22c55e" }} />
                  <span className="pr-code-filename">routes/auth.js — PR #2841 feat/user-auth-refactor</span>
                </div>
                <div className="pr-code-body">
                  {PR_LINES.map((line, i) => (
                    <div
                      key={i}
                      className={`pr-line ${line.type} ${i < visiblePrLines ? "visible" : ""}`}
                      style={{ transitionDelay: `${(i % 3) * 0.05}s` }}
                    >
                      <span className="pr-line-prefix">{getPrLinePrefix(line.type)}</span>
                      {line.type === "finding" && (
                        <span className="pr-finding-badge" style={getFindinBadgeStyle((line as any).label)}>
                          {(line as any).label}
                        </span>
                      )}
                      <span className="pr-line-content" style={{ paddingLeft: `${line.indent * 12}px` }}>
                        {line.content}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Threat Detection Console ── */}
      <section className="sec" style={{ paddingTop: "5rem" }}>
        <div className="sec-inner">
          <div className="sec-head">
            <div className="sec-tag">// live intelligence</div>
            <h2 className="sec-h2">Real-time Threat Detection</h2>
            <p className="sec-sub">Watch ShieldSentinel flag risks the moment code changes — before review even starts.</p>
          </div>
          <div className="console-wrap" ref={consoleRef}>
            <div className="console-bar">
              <span className="cdot" style={{ background: "#ef4444" }} />
              <span className="cdot" style={{ background: "#eab308" }} />
              <span className="cdot" style={{ background: "#22c55e" }} />
              <span className="cbar-title">shieldsentinel — scanning PR #2841 — feat/user-auth-refactor</span>
              <span className="cbar-status"><span className="cbar-dot" />SCANNING</span>
            </div>
            <div className="console-body">
              <div className="scan-bar" />
              {THREATS.map((t, i) => (
                <div key={i} className={`c-row ${i === activeThreat ? "lit" : ""}`}>
                  <span className="sev-badge" style={{ background: `${SEV_COLORS[t.type]}18`, color: SEV_COLORS[t.type], border: `1px solid ${SEV_COLORS[t.type]}30` }}>
                    {t.type}
                  </span>
                  <div>
                    <div className="c-msg">{t.msg}</div>
                    <div className="c-file">{t.file}:{t.line}</div>
                  </div>
                </div>
              ))}
              <div className="c-verdict">
                ▶ scan complete · 6 findings · risk score: 87/100 · verdict: <span className="c-blocked">BLOCKED</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Testimonials Carousel ── */}
      <section className="sec" style={{ paddingTop: 0 }}>
        <div className="sec-inner">
          <div className="sec-head" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: "1rem" }}>
            <div>
              <div className="sec-tag">// social proof</div>
              <h2 className="sec-h2">Loved by Security Teams</h2>
              <p className="sec-sub">Engineering and security leads using ShieldSentinel share what changed for them.</p>
            </div>
          </div>
          <div className="carousel-wrapper" ref={testiRef}>
            <div
              className="carousel-track"
              style={{ transform: `translateX(${carouselOffset}%)` }}
            >
              {TESTIMONIALS.map((t) => (
                <div key={t.name} className="testi-card">
                  <div className="stars">★★★★★</div>
                  <p className="testi-quote">"{t.text}"</p>
                  <div className="testi-author">
                    <div className="testi-avatar">{t.name.split(" ").map((n) => n[0]).join("")}</div>
                    <div>
                      <div className="testi-name">{t.name}</div>
                      <div className="testi-role">{t.role}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="carousel-controls">
            <button className="carousel-btn" onClick={() => setCarouselIdx(Math.max(0, carouselIdx - 1))} disabled={carouselIdx === 0}>‹</button>
            <div className="carousel-dots">
              {Array.from({ length: maxIdx + 1 }).map((_, i) => (
                <button key={i} className={`carousel-dot ${i === carouselIdx ? "active" : ""}`} onClick={() => setCarouselIdx(i)} />
              ))}
            </div>
            <button className="carousel-btn" onClick={() => setCarouselIdx(Math.min(maxIdx, carouselIdx + 1))} disabled={carouselIdx === maxIdx}>›</button>
          </div>
        </div>
      </section>

      {/* ── Pricing ── */}
      <section className="sec" style={{ paddingTop: 0 }}>
        <div className="sec-inner">
          <div className="sec-head">
            <div className="sec-tag">// pricing</div>
            <h2 className="sec-h2">Simple, Transparent Pricing</h2>
            <p className="sec-sub">Start free. Scale when you're ready. No hidden fees or per-seat surprises.</p>
          </div>
          <div className="plans-grid" ref={plansRef}>
            {PLANS.map((p) => (
              <div key={p.name} className={`plan-card ${(p as any).popular ? "pop" : ""}`}>
                {(p as any).popular && <div className="pop-badge">MOST POPULAR</div>}
                <div className="plan-name">{p.name}</div>
                <div className="plan-price">{p.price}</div>
                <p className="plan-price-sub">{p.period}</p>
                <div className="plan-sep" />
                <ul className="plan-feat-list">
                  {p.features.map((f) => (
                    <li key={f}><span className="feat-check">✓</span>{f}</li>
                  ))}
                </ul>
                <button className={`plan-cta ripple-btn ${p.variant === "primary" ? "p" : "s"}`} onClick={createRipple}>{p.cta}</button>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="cta-sec" ref={ctaRef}>
        <div className="cta-glow" />
        <div className="cta-inner">
          <div className="cta-box">
            <h2 className="cta-h2">Ready to secure every PR before merge?</h2>
            <p className="cta-sub">Join thousands of teams shipping faster with stronger security confidence built in from the start.</p>
            <div className="cta-btns">
              <button className="btn-cta-primary btn-mag ripple-btn" onClick={createRipple}>
                Start Free Today
                <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
                  <path d="M2.5 7.5h10M8.5 3.5l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
              <button className="btn-cta-ghost btn-mag" onClick={createRipple}>Talk to Sales</button>
            </div>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-logo">
            <span className="logo-icon">
              <svg width="16" height="16" viewBox="0 0 18 18" fill="none">
                <path d="M9 1.8L15.2 4.7V9c0 3.4-2.7 6.4-6.2 7.2C5.5 15.4 2.8 12.4 2.8 9V4.7L9 1.8z" fill="white" fillOpacity="0.92" />
              </svg>
            </span>
            ShieldSentinel
          </div>
          <p className="footer-copy">© 2025 ShieldSentinel. AI-native PR security review platform.</p>
          <nav className="footer-links">
            {["Privacy", "Terms", "Security", "Docs", "Status"].map((l) => (
              <a key={l} href="#">{l}</a>
            ))}
          </nav>
        </div>
      </footer>
    </div>
  );
}