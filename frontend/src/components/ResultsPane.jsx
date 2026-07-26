import React from 'react';

export default function ResultsPane({ result, error, isProcessing }) {
  if (isProcessing) {
    return (
      <div className="pane results-pane">
        <div className="pane-header">// INSPECTION READOUT: TELEMETRY</div>
        <div className="log-output" style={{ color: 'var(--accent)', padding: '20px 0' }}>
          <p>&gt; ACCEPTING INGRESS PACKET...</p>
          <p>&gt; INTERROGATING QDRANT VECTOR STORE...</p>
          <p>&gt; MISTRAL-7B QUANTIZED GROUNDING ENGINE RUNNING...</p>
          <p style={{ marginTop: '12px', fontWeight: '600' }}>[INSPECTION IN PROGRESS]</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="pane results-pane" style={{ borderColor: 'var(--danger)' }}>
        <div className="pane-header" style={{ color: 'var(--danger)' }}>// INSPECTION EXCEPTION</div>
        <div className="log-output" style={{ color: 'var(--danger)' }}>
          <p>Inspection failed. The offline engine or RAG pipeline returned an exception.</p>
          <p style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text)' }}>Details: {error}</p>
          <p style={{ marginTop: '16px', color: 'var(--text-dim)' }}>Ensure Qdrant is active and try resubmitting the payload.</p>
        </div>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="pane results-pane">
        <div className="pane-header">// INSPECTION READOUT: TELEMETRY</div>
        <div className="log-output" style={{ color: 'var(--text-dim)', padding: '20px 0' }}>
          <p>No scans yet. Paste a log or CVE query to begin.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="pane results-pane">
      <div className="pane-header">// INSPECTION READOUT: COMPLETE</div>
      <div className="log-output" style={{ overflowY: 'auto', flex: 1 }}>
        <div style={{ marginBottom: '16px', paddingBottom: '12px', borderBottom: '1px solid rgba(74, 102, 112, 0.3)' }}>
          <span style={{ color: 'var(--accent)', display: 'block', marginBottom: '8px', fontWeight: 'bold' }}>
            [SYNTHESIZED INTELLIGENCE]
          </span>
          <div style={{ color: 'var(--text)', whiteSpace: 'pre-wrap', lineHeight: '1.5', fontSize: '13px' }}>
            {result.answer || JSON.stringify(result, null, 2)}
          </div>
        </div>

        {result.sources && result.sources.length > 0 && (
          <div style={{ marginBottom: '16px' }}>
            <span style={{ color: 'var(--accent-secondary)', display: 'block', marginBottom: '6px', fontSize: '12px' }}>
              [ATTRIBUTED REFERENCES]
            </span>
            <ul style={{ listStyle: 'none', paddingLeft: 0 }}>
              {result.sources.map((src, idx) => (
                <li key={idx} style={{ background: '#131822', padding: '8px 12px', marginBottom: '6px', borderLeft: '2px solid var(--accent-secondary)' }}>
                  <strong>{src.cve_id}</strong> {src.severity && <span style={{ color: src.severity === 'CRITICAL' || src.severity === 'HIGH' ? 'var(--danger)' : 'var(--accent)' }}>[{src.severity}]</span>} 
                  {src.base_score > 0 && ` — CVSS: ${src.base_score}`}
                  <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginTop: '2px' }}>Relevance Match: {(src.relevance_score * 100).toFixed(1)}%</div>
                </li>
              ))}
            </ul>
          </div>
        )}

        {result.llm_metrics && (
          <div style={{ background: '#12161f', padding: '12px', border: '1px dashed var(--accent-secondary)', fontSize: '11px', color: 'var(--text-dim)' }}>
            <span style={{ color: 'var(--accent-secondary)', display: 'block', marginBottom: '6px', fontWeight: '600' }}>[OFFLINE RUNTIME METRICS]</span>
            <div>Tokens Generated: {result.llm_metrics.tokens_generated} | Latency: {result.llm_metrics.latency_ms}ms</div>
            <div>Speed: {result.llm_metrics.tokens_per_sec} tok/s | Memory Footprint: {result.llm_metrics.memory_mb} MB ({result.llm_metrics.quant_level || 'Q4_K_M'})</div>
          </div>
        )}
      </div>
    </div>
  );
}
