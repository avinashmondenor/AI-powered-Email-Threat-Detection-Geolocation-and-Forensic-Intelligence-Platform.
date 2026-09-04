import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert, ShieldCheck, Mail, Server, Globe, FileText, Activity,
  AlertTriangle, Link as LinkIcon, Download, RefreshCw, Terminal, CheckCircle,
  XCircle, FileCode, Layers, Info, Copy, Check, UploadCloud, Network, Database, Lock, Eye
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const STAGES = [
  { id: 1, name: '1. RAW .EML', key: 'evidence' },
  { id: 2, name: '2. PRESERVATION', key: 'evidence' },
  { id: 3, name: '3. FORENSICS', key: 'header_forensics' },
  { id: 4, name: '4. ORIGIN RECON', key: 'origin_reconstruction' },
  { id: 5, name: '5. INFRA INTEL', key: 'infrastructure' },
  { id: 6, name: '6. CAMPAIGN GRAPH', key: 'campaign' },
  { id: 7, name: '7. CONFIDENCE', key: 'confidence' },
  { id: 8, name: '8. FINDINGS', key: 'findings' }
];

export default function App() {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState('');
  const [activeStageIdx, setActiveStageIdx] = useState(0);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('workflow'); // workflow, overview, campaign, report
  const [copiedHash, setCopiedHash] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [isDragging, setIsDragging] = useState(false);

  const fileInputRef = useRef(null);

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/health`)
      .then(res => res.text())
      .then(text => {
        try {
          setHealthStatus(JSON.parse(text));
        } catch (e) {
          setHealthStatus({ mock_mode: true });
        }
      })
      .catch(() => setHealthStatus({ mock_mode: true }));
  }, []);

  const validateAndAnalyzeFile = (file) => {
    if (!file) return;
    const name = file.name ? file.name.toLowerCase() : '';
    const isEmlExt = name.endsWith('.eml') || name.endsWith('.msg') || name.endsWith('.txt');
    const isEmlMime = file.type === 'message/rfc822' || file.type === 'application/octet-stream' || file.type === 'text/plain';

    if (!isEmlExt && !isEmlMime) {
      setError('Invalid file type. Please select an .EML email file.');
      return;
    }
    handleFileUpload(file);
  };

  const handleFileUpload = async (file) => {
    setLoading(true);
    setError(null);
    setActiveStageIdx(0);
    setLoadingStage('Stage 1: RAW .EML Ingestion & Verification...');

    const formData = new FormData();
    formData.append('file', file);

    const stageMessages = [
      'Stage 1: RAW .EML File Ingestion...',
      'Stage 2: Calculating SHA-256 & Evidence Preservation...',
      'Stage 3: Header Forensics & Authentication Analysis...',
      'Stage 4: Trust-Aware Origin Route Reconstruction...',
      'Stage 5: Infrastructure & Network Intelligence...',
      'Stage 6: Campaign Graph Indicator Correlation...',
      'Stage 7: Confidence-Based Evidence Evaluation...',
      'Stage 8: Compiling Forensic Findings...'
    ];

    let idx = 0;
    const interval = setInterval(() => {
      idx = (idx + 1) % stageMessages.length;
      setActiveStageIdx(idx);
      setLoadingStage(stageMessages[idx]);
    }, 350);

    try {
      let res;
      try {
        res = await fetch(`${API_BASE_URL}/api/analyze`, {
          method: 'POST',
          body: formData, // Browser automatically generates multipart/form-data boundary
        });
      } catch (netErr) {
        clearInterval(interval);
        throw new Error('Unable to connect to analysis server. Please ensure backend is running at http://127.0.0.1:8000.');
      }

      clearInterval(interval);

      if (res.status === 502 || res.status === 504 || res.status === 503) {
        throw new Error(`Unable to connect to analysis server (HTTP ${res.status}). Please verify the backend is running at http://127.0.0.1:8000.`);
      }

      const contentType = res.headers.get('content-type') || '';
      const rawText = await res.text();

      if (!rawText || rawText.trim() === '') {
        throw new Error(`Analysis server returned an empty response (Status ${res.status}). Please check backend logs.`);
      }

      let data;
      if (contentType.includes('application/json')) {
        try {
          data = JSON.parse(rawText);
        } catch (jsonErr) {
          throw new Error(`Server returned malformed JSON response (${res.status}).`);
        }
      } else {
        throw new Error(`Server error (${res.status}): ${rawText.substring(0, 150)}`);
      }

      if (!res.ok || data.success === false) {
        const errMsg = data.error || data.detail || data.details || `Analysis error (Status ${res.status})`;
        throw new Error(errMsg);
      }

      setAnalysis(data.analysis || data);
      setActiveStageIdx(7);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setLoadingStage('');
    }
  };

  const handleSampleClick = async (sampleName) => {
    setLoading(true);
    setError(null);
    setLoadingStage('Executing Forensic Pipeline on Sample EML...');
    try {
      let res;
      try {
        res = await fetch(`${API_BASE_URL}/api/samples/${sampleName}`);
      } catch (netErr) {
        throw new Error('Unable to connect to analysis server.');
      }

      const contentType = res.headers.get('content-type') || '';
      const rawText = await res.text();

      if (!rawText || rawText.trim() === '') {
        throw new Error('Received empty response for sample.');
      }

      let data;
      if (contentType.includes('application/json')) {
        data = JSON.parse(rawText);
      } else {
        throw new Error(`Server status ${res.status}`);
      }

      if (!res.ok || data.success === false) {
        throw new Error(data.error || data.detail || 'Failed to analyze sample.');
      }

      setAnalysis(data.analysis || data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setLoadingStage('');
    }
  };

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(key);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const downloadReport = () => {
    if (!analysis) return;
    fetch(`${API_BASE_URL}/api/analysis/${analysis.analysis_id}/report`)
      .then(res => res.text())
      .then(text => {
        const blob = new Blob([text], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Forensic_Report_${analysis.evidence?.id || analysis.analysis_id}.md`;
        a.click();
      });
  };

  return (
    <div className="app-container">
      {/* HEADER */}
      <header className="app-header">
        <div className="brand">
          <div className="brand-icon">
            <ShieldAlert size={26} />
          </div>
          <div>
            <h1 className="brand-title">EMAIL THREAT DETECTION & FORENSIC INVESTIGATION PLATFORM</h1>
            <div className="brand-subtitle">8-Stage Forensic Preservation, Origin Reconstruction & Threat Analysis Engine</div>
          </div>
        </div>

        <div className="header-badges">
          <span className={`badge ${healthStatus?.mock_mode ? 'badge-mock' : 'badge-live'}`}>
            <Activity size={14} />
            {healthStatus?.mock_mode ? 'MOCK INTELLIGENCE ACTIVE' : 'LIVE API ACTIVE'}
          </span>
          {analysis && (
            <button className="btn-secondary" onClick={() => { setAnalysis(null); setError(null); }}>
              <RefreshCw size={14} /> New Evidence Upload
            </button>
          )}
        </div>
      </header>

      {/* ERROR ALERT */}
      {error && (
        <div className="glass-card" style={{ borderColor: 'var(--accent-red)', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--accent-red)' }}>
            <AlertTriangle size={20} />
            <div>
              <strong>Forensic Analysis Failure:</strong> {error}
            </div>
          </div>
        </div>
      )}

      {/* UPLOAD SCREEN */}
      {!analysis && !loading && (
        <div className="glass-card upload-hero">
          <div
            className={`dropzone ${isDragging ? 'active' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragEnter={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                validateAndAnalyzeFile(e.dataTransfer.files[0]);
              }
            }}
            onClick={() => fileInputRef.current && fileInputRef.current.click()}
          >
            <UploadCloud size={50} style={{ color: 'var(--accent-cyan)', marginBottom: 16 }} />
            <h2 style={{ fontSize: '1.4rem', marginBottom: 8 }}>Drop .EML File Here for Forensic Analysis</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: 20 }}>
              Calculates SHA-256 hash, preserves evidence integrity, reconstructs Received hops, enriches network intel, and builds campaign correlation graph.
            </p>

            <input
              ref={fileInputRef}
              type="file"
              accept=".eml,message/rfc822,.msg,.txt"
              style={{ display: 'none' }}
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  validateAndAnalyzeFile(e.target.files[0]);
                }
              }}
            />

            <button
              className="btn-primary"
              onClick={(e) => {
                e.stopPropagation();
                if (fileInputRef.current) fileInputRef.current.click();
              }}
            >
              Select EML File
            </button>
          </div>

          <div style={{ marginTop: 24 }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 1 }}>
              Or Quick Test Synthetic Sample Forensic Cases:
            </div>
            <div className="sample-selector">
              <button className="sample-btn" onClick={() => handleSampleClick('phishing')}>
                <AlertTriangle size={14} style={{ color: 'var(--accent-red)' }} /> Phishing & PayPal Lookalike
              </button>
              <button className="sample-btn" onClick={() => handleSampleClick('spoofed_sender')}>
                <ShieldAlert size={14} style={{ color: 'var(--accent-orange)' }} /> Executive CEO Spoofing
              </button>
              <button className="sample-btn" onClick={() => handleSampleClick('suspicious_url')}>
                <LinkIcon size={14} style={{ color: 'var(--accent-yellow)' }} /> IP Link & Shorteners
              </button>
              <button className="sample-btn" onClick={() => handleSampleClick('suspicious_attachment')}>
                <FileCode size={14} style={{ color: 'var(--accent-purple)' }} /> Executable Attachment (.pdf.exe)
              </button>
              <button className="sample-btn" onClick={() => handleSampleClick('legitimate')}>
                <CheckCircle size={14} style={{ color: 'var(--accent-green)' }} /> Legitimate Newsletter
              </button>
            </div>
          </div>
        </div>
      )}

      {/* LOADING STATE */}
      {loading && (
        <div className="glass-card" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <RefreshCw size={40} className="spin-icon" style={{ color: 'var(--accent-cyan)', marginBottom: 16 }} />
          <h2 style={{ fontSize: '1.3rem' }}>{loadingStage || 'Executing Forensic Investigation Pipeline...'}</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: 8 }}>
            Preserving EML evidence • Calculating SHA-256 • Reconstructing trust route • Correlating campaign graph
          </p>
        </div>
      )}

      {/* DASHBOARD WITH 8 WORKFLOW STAGES */}
      {analysis && !loading && (
        <div>
          {/* 8-STAGE WORKFLOW STEPPER BADGE HEADER */}
          <div className="glass-card" style={{ marginBottom: 20, padding: 16 }}>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>
              8-Stage Forensic Pipeline Status:
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))', gap: 8 }}>
              {STAGES.map((stg, i) => (
                <div
                  key={stg.id}
                  style={{
                    background: 'rgba(0, 242, 254, 0.08)',
                    border: '1px solid rgba(0, 242, 254, 0.3)',
                    borderRadius: 6,
                    padding: '8px 10px',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    color: 'var(--accent-cyan)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6
                  }}
                >
                  <CheckCircle size={12} style={{ color: 'var(--accent-green)', flexShrink: 0 }} />
                  <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{stg.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* TAB BAR */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 20 }}>
            <button
              className={`btn-secondary ${activeTab === 'workflow' ? 'active-tab' : ''}`}
              onClick={() => setActiveTab('workflow')}
              style={{ borderColor: activeTab === 'workflow' ? 'var(--accent-cyan)' : 'var(--border-color)', color: activeTab === 'workflow' ? 'var(--accent-cyan)' : 'inherit' }}
            >
              <Layers size={16} /> 8-Stage Forensic Analysis
            </button>

            <button
              className={`btn-secondary ${activeTab === 'campaign' ? 'active-tab' : ''}`}
              onClick={() => setActiveTab('campaign')}
              style={{ borderColor: activeTab === 'campaign' ? 'var(--accent-cyan)' : 'var(--border-color)', color: activeTab === 'campaign' ? 'var(--accent-cyan)' : 'inherit' }}
            >
              <Network size={16} /> Campaign Correlation Graph
            </button>

            <button
              className={`btn-secondary ${activeTab === 'report' ? 'active-tab' : ''}`}
              onClick={() => setActiveTab('report')}
              style={{ borderColor: activeTab === 'report' ? 'var(--accent-cyan)' : 'var(--border-color)', color: activeTab === 'report' ? 'var(--accent-cyan)' : 'inherit' }}
            >
              <FileText size={16} /> Forensic Report
            </button>

            <div style={{ marginLeft: 'auto' }}>
              <button className="btn-primary" onClick={downloadReport}>
                <Download size={14} /> Export Forensic Report (.MD)
              </button>
            </div>
          </div>

          {activeTab === 'workflow' && (
            <div>
              {/* STAGE 1 & 2: RAW EML & EVIDENCE PRESERVATION */}
              <div className="grid-2">
                <div className="glass-card">
                  <div className="card-title">
                    <Lock size={18} /> Stage 1 & 2: Evidence Preservation & Hash Integrity
                  </div>
                  <table className="data-table">
                    <tbody>
                      <tr>
                        <td>Evidence ID</td>
                        <td><code style={{ color: 'var(--accent-cyan)', fontWeight: 'bold' }}>{analysis.evidence?.evidence_id}</code></td>
                      </tr>
                      <tr>
                        <td>Filename</td>
                        <td><strong>{analysis.evidence?.filename}</strong></td>
                      </tr>
                      <tr>
                        <td>SHA-256 Hash</td>
                        <td>
                          <button
                            className="btn-secondary"
                            style={{ padding: '2px 6px', fontSize: '0.75rem' }}
                            onClick={() => handleCopy(analysis.evidence?.sha256, 'sha256')}
                          >
                            {copiedHash === 'sha256' ? <Check size={12} /> : <Copy size={12} />}
                            {analysis.evidence?.sha256?.substring(0, 16)}...
                          </button>
                        </td>
                      </tr>
                      <tr>
                        <td>File Size</td>
                        <td>{analysis.evidence?.size_bytes} bytes</td>
                      </tr>
                      <tr>
                        <td>MIME Type</td>
                        <td><code>{analysis.evidence?.mime_type}</code></td>
                      </tr>
                      <tr>
                        <td>Integrity Status</td>
                        <td>
                          <span className="badge badge-live">
                            ✓ {analysis.evidence?.integrity_status}
                          </span>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* STAGE 8 / TOP VERDICT CARD */}
                <div className="glass-card score-card">
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1 }}>
                    Stage 8: Overall Verdict & Risk Rating
                  </div>

                  <div className="score-circle" style={{ borderColor: `var(--accent-${analysis.risk_level === 'CRITICAL' ? 'red' : analysis.risk_level === 'HIGH' ? 'orange' : analysis.risk_level === 'MEDIUM' ? 'yellow' : 'green'})` }}>
                    <div className={`score-value class-${analysis.risk_level}`}>
                      {analysis.risk_score}
                    </div>
                    <div className="score-max">/ 100</div>
                  </div>

                  <div className={`pill-classification pill-${analysis.risk_level}`}>
                    {analysis.verdict ? `${analysis.verdict.toUpperCase()} (${analysis.risk_level})` : analysis.risk_level}
                  </div>

                  <div style={{ fontSize: '0.8rem', marginTop: 12, color: 'var(--text-muted)' }}>
                    Threat Confidence: <strong style={{ color: 'var(--accent-cyan)' }}>{analysis.confidence?.threat_confidence}</strong>
                  </div>
                </div>
              </div>

              {/* STAGE 3: THREAT & HEADER FORENSICS */}
              <div className="grid-2">
                <div className="glass-card">
                  <div className="card-title">
                    <Mail size={18} /> Stage 3: Header Forensics & Identity Spoofing Analysis
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.88rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>From:</span>{' '}
                      <code style={{ color: 'var(--accent-cyan)' }}>{analysis.email?.from}</code>
                    </div>

                    {analysis.header_forensics?.identity_anomalies?.display_name_spoofing && (
                      <div style={{ background: 'rgba(255,23,68,0.12)', border: '1px solid var(--accent-red)', padding: '8px 12px', borderRadius: 6, fontSize: '0.8rem', color: 'var(--accent-red)' }}>
                        🚨 <strong>Display Name Spoofing Detected!</strong> Name contains '{analysis.header_forensics.identity_anomalies.spoofed_brand}' but domain is '{analysis.email?.sender_domain}'.
                      </div>
                    )}

                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Reply-To:</span>{' '}
                      <code style={{ color: analysis.email?.reply_to_mismatch ? 'var(--accent-red)' : 'inherit' }}>
                        {analysis.email?.reply_to}
                      </code>
                    </div>

                    {analysis.email?.reply_to_mismatch && (
                      <div style={{ background: 'rgba(255,23,68,0.12)', border: '1px solid var(--accent-red)', padding: '8px 12px', borderRadius: 6, fontSize: '0.8rem', color: 'var(--accent-red)' }}>
                        ⚠️ <strong>Reply-To Mismatch!</strong> From domain ({analysis.email?.sender_domain}) differs from Reply-To domain ({analysis.email?.reply_to_domain}).
                      </div>
                    )}

                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Return-Path:</span> <code>{analysis.email?.return_path || 'N/A'}</code>
                    </div>

                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Subject:</span> <strong>{analysis.email?.subject}</strong>
                    </div>

                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Message-ID:</span> <code>{analysis.email?.message_id}</code>
                    </div>
                  </div>
                </div>

                <div className="glass-card">
                  <div className="card-title">
                    <CheckCircle size={18} /> Stage 3: Authentication Protocol Verification
                  </div>

                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Protocol</th>
                        <th>Result</th>
                        <th>Source</th>
                        <th>Alignment Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><strong>SPF</strong></td>
                        <td>
                          <span style={{ color: analysis.authentication?.spf?.result === 'PASS' ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 'bold' }}>
                            {analysis.authentication?.spf?.result}
                          </span>
                        </td>
                        <td><code>{analysis.authentication?.spf?.source}</code></td>
                        <td>{analysis.authentication?.spf?.domain || 'N/A'}</td>
                      </tr>
                      <tr>
                        <td><strong>DKIM</strong></td>
                        <td>
                          <span style={{ color: analysis.authentication?.dkim?.result === 'PASS' ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 'bold' }}>
                            {analysis.authentication?.dkim?.result}
                          </span>
                        </td>
                        <td><code>{analysis.authentication?.dkim?.source}</code></td>
                        <td>Selector: <code>{analysis.authentication?.dkim?.selector || 'none'}</code></td>
                      </tr>
                      <tr>
                        <td><strong>DMARC</strong></td>
                        <td>
                          <span style={{ color: analysis.authentication?.dmarc?.result === 'PASS' ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 'bold' }}>
                            {analysis.authentication?.dmarc?.result}
                          </span>
                        </td>
                        <td><code>{analysis.authentication?.dmarc?.source}</code></td>
                        <td>
                          Policy: <code>{analysis.authentication?.dmarc?.policy}</code> | SPF Align: {analysis.authentication?.dmarc?.spf_alignment ? 'YES' : 'NO'}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* STAGE 4: TRUST-AWARE ORIGIN RECONSTRUCTION */}
              <div className="glass-card" style={{ marginBottom: 24 }}>
                <div className="card-title" style={{ justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Server size={18} /> Stage 4: Trust-Aware Origin Route Reconstruction
                  </div>
                  <span className="badge badge-mock" style={{ color: 'var(--accent-cyan)', borderColor: 'var(--accent-cyan)' }}>
                    ORIGIN CONFIDENCE: {analysis.origin_reconstruction?.origin_confidence}
                  </span>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, marginBottom: 16, borderLeft: '4px solid var(--accent-cyan)' }}>
                  <div style={{ fontSize: '0.88rem', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>
                    Probable Origin Host: <code>{analysis.origin_reconstruction?.probable_origin?.ip}</code> ({analysis.origin_reconstruction?.probable_origin?.host})
                  </div>
                  <div style={{ fontSize: '0.82rem', marginTop: 4, color: 'var(--text-muted)' }}>
                    {analysis.origin_reconstruction?.confidence_reason}
                  </div>
                  <div style={{ fontSize: '0.78rem', marginTop: 6, color: 'var(--text-dim)', fontStyle: 'italic' }}>
                    ℹ️ <strong>Attribution Caveat:</strong> {analysis.origin_reconstruction?.attribution_caveat}
                  </div>
                </div>

                <div className="timeline">
                  {analysis.origin_reconstruction?.reconstructed_chain?.map((hop, idx) => (
                    <div key={idx} className="timeline-step">
                      <div className="timeline-title">
                        Hop #{hop.hop_number}: <code>{hop.ip}</code> — <span style={{ color: hop.classification.includes('ANONYM') ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>{hop.classification}</span>
                      </div>
                      <div className="timeline-desc">
                        From: <code>{hop.from_host}</code> $\to$ By: <code>{hop.by_host}</code> | Org: {hop.organization} ({hop.country})
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 2 }}>{hop.notes}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* STAGE 5: INFRASTRUCTURE & DOMAIN INTELLIGENCE */}
              <div className="grid-2">
                <div className="glass-card">
                  <div className="card-title">
                    <Globe size={18} /> Stage 5: Infrastructure & Domain Intelligence
                  </div>

                  {analysis.lookalike_analysis?.lookalike ? (
                    <div style={{ background: 'rgba(255,23,68,0.12)', border: '1px solid var(--accent-red)', padding: 12, borderRadius: 6, marginBottom: 12 }}>
                      <strong style={{ color: 'var(--accent-red)' }}>🚨 Look-alike Brand Typosquatting!</strong>
                      <div style={{ fontSize: '0.85rem', marginTop: 4 }}>
                        Sender domain <code>{analysis.email?.sender_domain}</code> mimics brand <strong>{analysis.lookalike_analysis.reference}</strong> ({((analysis.lookalike_analysis.similarity_score || 0) * 100).toFixed(0)}% similarity).
                      </div>
                    </div>
                  ) : (
                    <div style={{ background: 'rgba(0,230,118,0.1)', border: '1px solid var(--accent-green)', padding: 8, borderRadius: 6, color: 'var(--accent-green)', fontSize: '0.85rem', marginBottom: 12 }}>
                      ✓ Domain <code>{analysis.email?.sender_domain}</code> passed brand typosquatting checks.
                    </div>
                  )}

                  <table className="data-table">
                    <tbody>
                      <tr>
                        <td>Registrable Domain</td>
                        <td><code>{analysis.email?.sender_domain}</code></td>
                      </tr>
                      <tr>
                        <td>Domain Age</td>
                        <td>{analysis.domain_intelligence?.age_days ? `${analysis.domain_intelligence.age_days} days` : 'Unknown'}</td>
                      </tr>
                      <tr>
                        <td>Domain Reputation</td>
                        <td><span style={{ color: analysis.domain_intelligence?.reputation === 'CLEAN' ? 'var(--accent-green)' : 'var(--accent-red)' }}>{analysis.domain_intelligence?.reputation || 'UNKNOWN'}</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* STAGE 7: CONFIDENCE ENGINE SUMMARY */}
                <div className="glass-card">
                  <div className="card-title">
                    <Eye size={18} /> Stage 7: Confidence-Based Forensic Metrics
                  </div>

                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Investigation Axis</th>
                        <th>Confidence</th>
                        <th>Reasoning / Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><strong>Threat Score</strong></td>
                        <td><span className="badge badge-live">{analysis.confidence?.threat_confidence}</span></td>
                        <td style={{ fontSize: '0.78rem' }}>{analysis.confidence?.threat_confidence_reason}</td>
                      </tr>
                      <tr>
                        <td><strong>Origin Attribution</strong></td>
                        <td><span className="badge badge-mock" style={{ color: 'var(--accent-cyan)', borderColor: 'var(--accent-cyan)' }}>{analysis.confidence?.origin_confidence}</span></td>
                        <td style={{ fontSize: '0.78rem' }}>{analysis.confidence?.origin_confidence_reason}</td>
                      </tr>
                      <tr>
                        <td><strong>Infrastructure Intel</strong></td>
                        <td><span className="badge badge-live">{analysis.confidence?.infrastructure_confidence}</span></td>
                        <td style={{ fontSize: '0.78rem' }}>{analysis.confidence?.infrastructure_confidence_reason}</td>
                      </tr>
                      <tr>
                        <td><strong>Campaign Correlation</strong></td>
                        <td><span className="badge badge-mock" style={{ color: 'var(--accent-yellow)' }}>{analysis.confidence?.campaign_confidence}</span></td>
                        <td style={{ fontSize: '0.78rem' }}>{analysis.confidence?.campaign_confidence_reason}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* STAGE 8: STRUCTURED FORENSIC FINDINGS TABLE */}
              <div className="glass-card" style={{ marginTop: 24 }}>
                <div className="card-title">
                  <ShieldAlert size={18} /> Stage 8: Structured Forensic Findings ({analysis.findings?.findings_count || 0})
                </div>

                {analysis.findings?.findings && analysis.findings.findings.length > 0 ? (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Category</th>
                        <th>Finding Title & Description</th>
                        <th>Supporting Forensic Evidence</th>
                        <th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.findings.findings.map((f) => (
                        <tr key={f.finding_number}>
                          <td><strong>{f.finding_number}</strong></td>
                          <td><code>{f.category}</code></td>
                          <td>
                            <strong>{f.title}</strong>
                            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{f.description}</div>
                          </td>
                          <td style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>{f.evidence}</td>
                          <td><span className="badge badge-live">{f.confidence}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div style={{ padding: 16, color: 'var(--accent-green)' }}>No threat findings detected. Email is classified as clean.</div>
                )}
              </div>
            </div>
          )}

          {/* CAMPAIGN GRAPH TAB */}
          {activeTab === 'campaign' && (
            <div className="glass-card">
              <div className="card-title">
                <Network size={18} /> Stage 6: Campaign Correlation Graph Engine
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, marginBottom: 20 }}>
                <div style={{ fontSize: '1rem', fontWeight: 'bold', color: 'var(--accent-cyan)' }}>
                  Campaign Cluster Status: {analysis.campaign?.campaign_name}
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: 4 }}>
                  Correlated across <strong>{analysis.campaign?.correlated_events_count || 0}</strong> historical database incidents.
                </div>
              </div>

              <div className="grid-2">
                <div>
                  <h3 style={{ fontSize: '0.95rem', marginBottom: 10, color: 'var(--accent-cyan)' }}>Graph Nodes ({analysis.campaign?.graph?.total_nodes || 0}):</h3>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Label / Value</th>
                        <th>Threat</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.campaign?.graph?.nodes?.map((n) => (
                        <tr key={n.id}>
                          <td><code>{n.type}</code></td>
                          <td>{n.label}</td>
                          <td>
                            <span style={{ color: n.threat_level === 'HIGH' || n.threat_level === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                              {n.threat_level}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div>
                  <h3 style={{ fontSize: '0.95rem', marginBottom: 10, color: 'var(--accent-cyan)' }}>Relationships ({analysis.campaign?.graph?.total_edges || 0}):</h3>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Source Node</th>
                        <th>Relationship</th>
                        <th>Target Node</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analysis.campaign?.graph?.edges?.map((e, idx) => (
                        <tr key={idx}>
                          <td><code>{e.source.substring(0, 20)}</code></td>
                          <td><span className="badge badge-mock" style={{ color: 'var(--accent-cyan)' }}>{e.relationship}</span></td>
                          <td><code>{e.target.substring(0, 20)}</code></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* REPORT TAB */}
          {activeTab === 'report' && (
            <div className="glass-card">
              <div className="card-title" style={{ justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <FileText size={18} /> Generated SOC Forensic Investigation Summary Report
                </div>
                <button className="btn-primary" onClick={downloadReport}>
                  <Download size={14} /> Save Markdown Report
                </button>
              </div>

              <iframe
                srcDoc={`<html><body style="background:#0e1525;color:#e0e6ed;font-family:sans-serif;padding:20px;white-space:pre-wrap;">${generateForensicReportText(analysis)}</body></html>`}
                style={{ width: '100%', height: '520px', border: '1px solid var(--border-color)', borderRadius: 8 }}
                title="Forensic Report"
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function generateForensicReportText(data) {
  return `
================================================================================
EMAIL THREAT DETECTION & FORENSIC INVESTIGATION REPORT
================================================================================
Evidence ID     : ${data.evidence?.evidence_id || data.analysis_id}
SHA-256 Hash    : ${data.evidence?.sha256 || 'N/A'}
Integrity Status: ${data.evidence?.integrity_status || 'VERIFIED'}
Timestamp       : ${data.timestamp || 'N/A'}
Verdict         : ${data.verdict || data.risk_level} (Score: ${data.risk_score}/100)
Threat Confidence: ${data.confidence?.threat_confidence}
Origin Confidence: ${data.confidence?.origin_confidence}

--------------------------------------------------------------------------------
1. FORENSIC FINDINGS (${data.findings?.findings_count || 0})
--------------------------------------------------------------------------------
${data.findings?.findings ? data.findings.findings.map(f => `[Finding #${f.finding_number}] ${f.title}\nCategory   : ${f.category}\nEvidence   : ${f.evidence}\nConfidence : ${f.confidence}\n`).join('\n') : 'No findings.'}

--------------------------------------------------------------------------------
2. ORIGIN ATTRIBUTION & RECONSTRUCTION
--------------------------------------------------------------------------------
Probable Origin IP : ${data.origin_reconstruction?.probable_origin?.ip} (${data.origin_reconstruction?.probable_origin?.host})
Confidence         : ${data.origin_reconstruction?.origin_confidence}
Reason             : ${data.origin_reconstruction?.confidence_reason}
Attribution Caveat : ${data.origin_reconstruction?.attribution_caveat}

--------------------------------------------------------------------------------
3. CAMPAIGN CORRELATION
--------------------------------------------------------------------------------
Campaign Status    : ${data.campaign?.campaign_name}
Correlated Incidents: ${data.campaign?.correlated_events_count || 0}
`;
}
