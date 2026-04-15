import { useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, Code2, Users, Zap, GitMerge, Eye, Lock, Globe, Award } from 'lucide-react'
import Navbar from '../components/layout/Navbar'
import { useGsapReveal } from '../hooks/useGsapReveal'

const detections = [
  'Hardcoded Secrets', 'SQL Injection', 'Insecure HTTP', 'API Key Exposure',
  'Command Injection', 'Shell Injection', 'Weak Cryptography', 'Auth Bypass',
  'XSS Vectors', 'SSRF Patterns', 'Path Traversal', 'Insecure Deserialization',
]

const stack = ['FastAPI', 'PostgreSQL', 'Redis', 'Celery', 'React 18', 'TypeScript', 'Tailwind CSS']

const TIMELINE = [
  { year: '2023', title: 'Project Started', desc: 'ShieldSentinel began as a college project to solve slow, inconsistent PR security reviews in growing engineering teams.' },
  { year: 'Q1 2024', title: 'First Integration', desc: 'Launched GitHub integration with basic secret detection and SQL injection analysis. First 50 PRs scanned.' },
  { year: 'Q2 2024', title: 'SAST Pipeline', desc: 'Aggregated Semgrep, Bandit, and Snyk into a unified risk scoring engine. False-positive rate dropped to under 5%.' },
  { year: 'Q3 2024', title: 'Policy-as-Code', desc: 'Released YAML-based custom rules, letting teams version their security policy alongside application code.' },
  { year: 'Q4 2024', title: 'Enterprise Beta', desc: 'SSO, audit logs, and on-premise deployments went live for enterprise customers. 12,000+ PRs analyzed.' },
]

const PRINCIPLES = [
  { icon: <Zap size={18} />, title: 'Speed first', desc: 'Every review must complete in under 5 minutes. Security that slows teams down gets ignored.', color: '#1d4ed8' },
  { icon: <Eye size={18} />, title: 'Full transparency', desc: 'Every finding links its source rule, line number, and remediation path. No black boxes.', color: '#1e3a8a' },
  { icon: <Lock size={18} />, title: 'Zero data retention', desc: 'Diffs are analyzed in-memory and never stored. Your code stays your code.', color: '#2563eb' },
  { icon: <GitMerge size={18} />, title: 'Workflow-native', desc: 'Inline PR comments, not external dashboards. Security embedded in the workflow developers already use.', color: '#1d4ed8' },
]

const TEAM_MEMBERS = [
  { initials: 'AK', name: 'CHINMAY', role: 'Backend & Security', skills: ['FastAPI', 'SAST', 'Redis'] },
  { initials: 'PR', name: 'SUYASH', role: 'Frontend & Design', skills: ['React 18', 'TypeScript', 'Tailwind'] },
  { initials: 'SK', name: 'HRISHIKESH', role: 'ML & Risk Scoring', skills: ['Python', 'Celery', 'PostgreSQL'] },
]

const STATS = [
  { value: '12K+', label: 'PRs Analyzed' },
  { value: '98%', label: 'Detection Rate' },
  { value: '<5m', label: 'Avg Review Time' },
  { value: '25+', label: 'Security Checks' },
]

const fadeUp = { hidden: { opacity: 0, y: 32 }, show: { opacity: 1, y: 0, transition: { duration: 0.55 } } }
const fadeLeft = { hidden: { opacity: 0, x: -40 }, show: { opacity: 1, x: 0, transition: { duration: 0.55 } } }
const fadeRight = { hidden: { opacity: 0, x: 40 }, show: { opacity: 1, x: 0, transition: { duration: 0.55 } } }
const staggerContainer = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } }

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

.about-page {
  font-family: 'Outfit', sans-serif;
  background: #ffffff;
  color: #1e3a8a;
  min-height: 100vh;
}

.about-hero {
  padding: 9rem 1.5rem 5rem;
  position: relative;
  overflow: hidden;
  border-bottom: 1px solid #dbeafe;
}
.about-hero-grid {
  position: absolute; inset: 0;
  background-image: linear-gradient(rgba(30,58,138,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(30,58,138,0.04) 1px, transparent 1px);
  background-size: 48px 48px;
  -webkit-mask-image: radial-gradient(ellipse 80% 70% at 50% 0%, black 30%, transparent 100%);
  mask-image: radial-gradient(ellipse 80% 70% at 50% 0%, black 30%, transparent 100%);
}
.about-hero-inner { max-width: 900px; margin: 0 auto; position: relative; z-index: 2; }
.about-badge { display: inline-flex; align-items: center; gap: 8px; background: rgba(30,58,138,0.07); border: 1px solid rgba(30,58,138,0.18); padding: 5px 14px; border-radius: 99px; font-size: 0.72rem; font-weight: 600; color: #1d4ed8; margin-bottom: 1.5rem; font-family: 'JetBrains Mono', monospace; }
.about-h1 { font-size: clamp(2.2rem, 5vw, 3.8rem); font-weight: 900; letter-spacing: -0.04em; color: #1e3a8a; line-height: 1.1; margin-bottom: 1.2rem; }
.about-h1 span { color: #1d4ed8; }
.about-hero-sub { font-size: 1.05rem; color: #334155; max-width: 580px; line-height: 1.75; }

.about-stats { display: grid; grid-template-columns: repeat(4, 1fr); border-top: 1px solid #dbeafe; border-bottom: 1px solid #dbeafe; }
@media(max-width:640px) { .about-stats { grid-template-columns: repeat(2,1fr); } }
.about-stat { padding: 2rem 1.5rem; text-align: center; border-right: 1px solid #dbeafe; background: #f8fbff; }
.about-stat:last-child { border-right: none; }
.about-stat-val { font-size: 2.2rem; font-weight: 900; color: #1e3a8a; letter-spacing: -0.04em; line-height: 1; }
.about-stat-lbl { font-size: 0.78rem; color: #334155; margin-top: 0.35rem; }

.about-sec { padding: 5rem 1.5rem; border-bottom: 1px solid #eff6ff; }
.about-sec-inner { max-width: 900px; margin: 0 auto; }
.about-sec-tag { font-family: 'JetBrains Mono', monospace; font-size: 0.7rem; color: #1d4ed8; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.5rem; }
.about-sec-h2 { font-size: clamp(1.5rem, 3vw, 2.2rem); font-weight: 800; color: #1e3a8a; letter-spacing: -0.03em; margin-bottom: 0.75rem; }
.about-sec-sub { color: #334155; font-size: 0.92rem; line-height: 1.75; max-width: 520px; margin-bottom: 2.5rem; }

.card-dark { background: #ffffff; border: 1px solid #dbeafe; border-radius: 18px; padding: 1.6rem; transition: border-color 0.3s, transform 0.3s; }
.card-dark:hover { border-color: rgba(30,58,138,0.28); transform: translateY(-3px); }

.problem-body { color: #334155; line-height: 1.8; font-size: 0.93rem; }
.problem-highlight { color: #1e3a8a; font-weight: 600; }

.detect-grid { display: flex; flex-wrap: wrap; gap: 0.6rem; }
.detect-pill { padding: 5px 14px; border-radius: 99px; background: rgba(30,58,138,0.07); border: 1px solid rgba(30,58,138,0.18); color: #1d4ed8; font-size: 0.78rem; font-weight: 500; transition: all 0.2s; cursor: default; }
.detect-pill:hover { background: rgba(30,58,138,0.14); border-color: rgba(30,58,138,0.35); color: #1e40af; }

.principles-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 1.2rem; }
.principle-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 16px; padding: 1.5rem; transition: all 0.3s; }
.principle-card:hover { transform: translateY(-4px); }
.principle-icon { width: 38px; height: 38px; border-radius: 12px; display: flex; align-items: center; justify-content: center; margin-bottom: 1rem; }
.principle-title { font-size: 0.9rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.4rem; }
.principle-desc { font-size: 0.8rem; color: #334155; line-height: 1.65; }

.timeline { position: relative; padding-left: 2rem; }
.timeline::before { content: ''; position: absolute; left: 7px; top: 6px; bottom: 6px; width: 2px; background: linear-gradient(to bottom, #1d4ed8, rgba(30,58,138,0.15)); border-radius: 1px; }
.timeline-item { position: relative; padding-bottom: 2.2rem; }
.timeline-item:last-child { padding-bottom: 0; }
.timeline-dot { position: absolute; left: -1.75rem; top: 5px; width: 12px; height: 12px; border-radius: 50%; background: #1d4ed8; border: 2px solid #ffffff; box-shadow: 0 0 0 3px rgba(30,58,138,0.2); }
.timeline-year { font-family: 'JetBrains Mono', monospace; font-size: 0.68rem; color: #1d4ed8; letter-spacing: 0.08em; margin-bottom: 0.25rem; }
.timeline-title { font-size: 0.95rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.35rem; }
.timeline-desc { font-size: 0.83rem; color: #334155; line-height: 1.7; }

.stack-pills { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.stack-pill { padding: 5px 12px; border-radius: 8px; background: #f8fbff; border: 1px solid #dbeafe; color: #1e3a8a; font-size: 0.78rem; font-family: 'JetBrains Mono', monospace; }

.team-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px,1fr)); gap: 1.2rem; }
.team-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 18px; padding: 1.6rem; transition: all 0.3s; }
.team-card:hover { border-color: rgba(30,58,138,0.2); transform: translateY(-4px); }
.team-avatar { width: 52px; height: 52px; border-radius: 50%; background: rgba(30,58,138,0.1); border: 1px solid rgba(30,58,138,0.2); display: flex; align-items: center; justify-content: center; font-size: 1rem; font-weight: 700; color: #1d4ed8; margin-bottom: 1rem; }
.team-name { font-size: 0.95rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.2rem; }
.team-role { font-size: 0.8rem; color: #334155; margin-bottom: 0.9rem; }
.team-skills { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.team-skill { padding: 3px 9px; border-radius: 6px; background: rgba(30,58,138,0.06); border: 1px solid rgba(30,58,138,0.14); color: #1d4ed8; font-size: 0.72rem; }

.recog-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 1rem; }
.recog-card { background: #ffffff; border: 1px solid #dbeafe; border-radius: 14px; padding: 1.4rem; display: flex; align-items: center; gap: 1rem; }
.recog-icon { color: #f59e0b; flex-shrink: 0; }
.recog-title { font-size: 0.85rem; font-weight: 700; color: #1e3a8a; margin-bottom: 0.2rem; }
.recog-sub { font-size: 0.75rem; color: #334155; }

.about-cta { padding: 5rem 1.5rem; text-align: center; }
.about-cta-inner { max-width: 600px; margin: 0 auto; }
.about-cta h2 { font-size: clamp(1.7rem, 3.5vw, 2.4rem); font-weight: 900; color: #1e3a8a; letter-spacing: -0.035em; margin-bottom: 1rem; line-height: 1.15; }
.about-cta p { color: #334155; font-size: 0.93rem; line-height: 1.75; margin-bottom: 2rem; }
.about-cta-btns { display: flex; gap: 0.75rem; justify-content: center; flex-wrap: wrap; }
.btn-primary { background: #1d4ed8; color: #ffffff; padding: 0.75rem 1.8rem; border-radius: 12px; font-size: 0.9rem; font-weight: 700; cursor: pointer; border: none; font-family: inherit; transition: all 0.22s; }
.btn-primary:hover { background: #1e40af; transform: translateY(-2px); }
.btn-outline { background: transparent; border: 1px solid rgba(30,58,138,0.25); color: #1e3a8a; padding: 0.75rem 1.8rem; border-radius: 12px; font-size: 0.9rem; font-weight: 500; cursor: pointer; font-family: inherit; transition: all 0.22s; }
.btn-outline:hover { border-color: rgba(30,58,138,0.5); transform: translateY(-2px); }
`

export default function AboutPage() {
  useEffect(() => { document.title = 'About | ShieldSentinel' }, [])
  const revealRef = useGsapReveal()

  return (
    <motion.div
      ref={revealRef}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="about-page"
    >
      <style>{CSS}</style>
      <Navbar />

      <motion.section className="about-hero" initial="hidden" animate="show" variants={staggerContainer}>
        <div className="about-hero-grid" />
        <div className="about-hero-inner">
          <motion.div className="about-badge" variants={fadeUp}>
            <Shield size={12} />
            AI-Native PR Security
          </motion.div>
          <motion.h1 className="about-h1" variants={fadeUp}>
            Built to stop <span>vulnerabilities</span><br />before they ship.
          </motion.h1>
          <motion.p className="about-hero-sub" variants={fadeUp}>
            ShieldSentinel is an AI-native PR review system built by a 3rd year team under Corporate Tech Domain - handling the full security review pipeline automatically, in seconds.
          </motion.p>
        </div>
      </motion.section>

      <motion.div className="about-stats" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.3 }} variants={staggerContainer}>
        {STATS.map((s) => (
          <motion.div key={s.label} className="about-stat" variants={fadeUp}>
            <div className="about-stat-val">{s.value}</div>
            <div className="about-stat-lbl">{s.label}</div>
          </motion.div>
        ))}
      </motion.div>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            <motion.div className="about-sec-tag" variants={fadeLeft}>// origin</motion.div>
            <motion.h2 className="about-sec-h2" variants={fadeLeft}>The Problem We&apos;re Solving</motion.h2>
          </motion.div>
          <motion.div className="card-dark" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={fadeUp}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '1rem' }}>
              <AlertTriangle size={18} color="#f59e0b" />
              <span style={{ fontWeight: 700, color: '#1e3a8a', fontSize: '0.95rem' }}>Why code reviews keep failing</span>
            </div>
            <p className="problem-body">
              Code reviews are <span className="problem-highlight">slow, inconsistent,</span> and depend entirely on who&apos;s available. Junior reviewers miss security issues. Senior reviewers don&apos;t have time. Security teams are bottlenecks, not accelerators.
            </p>
            <p className="problem-body" style={{ marginTop: '0.9rem' }}>
              ShieldSentinel replaces the guesswork with a <span className="problem-highlight">deterministic, policy-driven pipeline</span> that fetches diffs, detects vulnerabilities, scores findings, and generates a merge decision - in seconds, every time, with no human in the loop unless a finding demands it.
            </p>
          </motion.div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            <motion.div className="about-sec-tag" variants={fadeUp}>// design principles</motion.div>
            <motion.h2 className="about-sec-h2" variants={fadeUp}>What We Believe</motion.h2>
            <motion.p className="about-sec-sub" variants={fadeUp}>These four principles guided every architecture decision and trade-off.</motion.p>
          </motion.div>
          <motion.div className="principles-grid" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.15 }} variants={staggerContainer}>
            {PRINCIPLES.map((p) => (
              <motion.div key={p.title} className="principle-card" variants={fadeUp} whileHover={{ scale: 1.02 }}>
                <div className="principle-icon" style={{ background: `${p.color}14`, color: p.color }}>{p.icon}</div>
                <div className="principle-title">{p.title}</div>
                <p className="principle-desc">{p.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            <motion.div className="about-sec-tag" variants={fadeRight}>// detection coverage</motion.div>
            <motion.h2 className="about-sec-h2" variants={fadeRight}>What We Detect</motion.h2>
            <motion.p className="about-sec-sub" variants={fadeRight}>25+ pattern-matched checks across OWASP Top 10, CWE, and custom policy rules.</motion.p>
          </motion.div>
          <motion.div className="detect-grid" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            {detections.map((d, i) => (
              <motion.span key={d} className="detect-pill" variants={fadeUp} custom={i} whileHover={{ scale: 1.05 }}>
                {d}
              </motion.span>
            ))}
          </motion.div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            <motion.div className="about-sec-tag" variants={fadeLeft}>// journey</motion.div>
            <motion.h2 className="about-sec-h2" variants={fadeLeft}>How We Got Here</motion.h2>
            <motion.p className="about-sec-sub" variants={fadeLeft}>From a college project to a production-grade security platform.</motion.p>
          </motion.div>
          <motion.div className="timeline" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.1 }} variants={staggerContainer}>
            {TIMELINE.map((item) => (
              <motion.div key={item.year} className="timeline-item" variants={fadeLeft}>
                <div className="timeline-dot" />
                <div className="timeline-year">{item.year}</div>
                <div className="timeline-title">{item.title}</div>
                <p className="timeline-desc">{item.desc}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px,1fr))', gap: '2rem' }}>
            <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={fadeLeft}>
              <div className="about-sec-tag">// stack</div>
              <h2 className="about-sec-h2" style={{ marginBottom: '1.2rem' }}>Tech Stack</h2>
              <div className="card-dark">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem' }}>
                  <Code2 size={16} color="#1e3a8a" />
                  <span style={{ color: '#1e3a8a', fontWeight: 600, fontSize: '0.88rem' }}>Production dependencies</span>
                </div>
                <div className="stack-pills">
                  {stack.map((s) => <span key={s} className="stack-pill">{s}</span>)}
                </div>
              </div>
            </motion.div>

            <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={fadeRight}>
              <div className="about-sec-tag">// team</div>
              <h2 className="about-sec-h2" style={{ marginBottom: '1.2rem' }}>The Team</h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '1rem', color: '#334155', fontSize: '0.82rem' }}>
                <Users size={14} />
                <span>3rd Year - Corporate Tech Domain</span>
              </div>
              <div className="team-grid" style={{ gridTemplateColumns: '1fr' }}>
                {TEAM_MEMBERS.map((m) => (
                  <motion.div key={m.name} className="team-card" whileHover={{ scale: 1.02 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      <div className="team-avatar">{m.initials}</div>
                      <div>
                        <div className="team-name">{m.name}</div>
                        <div className="team-role">{m.role}</div>
                        <div className="team-skills">
                          {m.skills.map((s) => <span key={s} className="team-skill">{s}</span>)}
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={staggerContainer}>
            <motion.div className="about-sec-tag" variants={fadeUp}>// recognition</motion.div>
            <motion.h2 className="about-sec-h2" variants={fadeUp}>Awards & Recognition</motion.h2>
            <motion.div className="recog-grid" style={{ marginTop: '1.5rem' }} variants={staggerContainer}>
              {[
                { title: 'Best Security Tool', sub: 'College Tech Fest 2024' },
                { title: 'Top Project Award', sub: 'Corporate Tech Domain' },
                { title: 'Open Source Pick', sub: 'Dev Community Spotlight' },
                { title: 'SOC 2 Ready', sub: 'Compliance Benchmark' },
              ].map((r) => (
                <motion.div key={r.title} className="recog-card" variants={fadeUp}>
                  <Award size={22} className="recog-icon" />
                  <div>
                    <div className="recog-title">{r.title}</div>
                    <div className="recog-sub">{r.sub}</div>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          </motion.div>
        </div>
      </section>

      <section className="about-sec">
        <div className="about-sec-inner">
          <motion.div className="card-dark" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px,1fr))', gap: '1.5rem', alignItems: 'center' }} initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }} variants={fadeUp}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: '0.75rem' }}>
                <Globe size={18} color="#2563eb" />
                <span style={{ fontWeight: 700, color: '#1e3a8a', fontSize: '0.95rem' }}>Open-source rules engine</span>
              </div>
              <p style={{ color: '#334155', fontSize: '0.85rem', lineHeight: 1.75 }}>
                Our detection rule library is open source and community-maintained. Contribute rules, report false positives, or fork the engine for your own tooling.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <button className="btn-primary">View on GitHub</button>
              <button className="btn-outline">Read the Docs</button>
            </div>
          </motion.div>
        </div>
      </section>

      <motion.section className="about-cta" initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.3 }} variants={staggerContainer}>
        <div className="about-cta-inner">
          <motion.h2 variants={fadeUp}>Ready to see ShieldSentinel in action?</motion.h2>
          <motion.p variants={fadeUp}>Connect your first repo in under 2 minutes. No agent, no infra changes, no credit card required.</motion.p>
          <motion.div className="about-cta-btns" variants={fadeUp}>
            <button className="btn-primary">Start for Free</button>
            <button className="btn-outline">Talk to Us</button>
          </motion.div>
        </div>
      </motion.section>
    </motion.div>
  )
}
