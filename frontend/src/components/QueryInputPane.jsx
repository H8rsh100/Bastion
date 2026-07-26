import React, { useState } from 'react';

export default function QueryInputPane({ onSubmit, isProcessing }) {
  const [toolType, setToolType] = useState('search_cve');
  const [inputText, setInputText] = useState('');

  const toolConfig = {
    search_cve: {
      label: 'CVE Natural Language Search',
      placeholder: 'e.g., buffer overflow in OpenSSL parsing module...',
      buttonText: 'Search CVE',
      rows: 4
    },
    explain_vulnerability: {
      label: 'CVE Vulnerability Explanation',
      placeholder: 'e.g., CVE-2024-1234',
      buttonText: 'Explain CVE',
      rows: 2
    },
    scan_log_for_iocs: {
      label: 'Log IOC Inspector',
      placeholder: 'Paste raw firewall or authentication logs here to begin...',
      buttonText: 'Run scan',
      rows: 8
    },
    check_dependency_risk: {
      label: 'Supply Chain Dependency Risk Check',
      placeholder: 'e.g., lodash 4.17.20 or openssl 1.1.1k',
      buttonText: 'Check risk',
      rows: 2
    }
  };

  const currentConfig = toolConfig[toolType];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputText.trim() || isProcessing) return;
    onSubmit(toolType, inputText.trim());
  };

  return (
    <div className="pane query-pane">
      <div className="pane-header">// INGRESS PORT: SELECT TOOL</div>

      <div style={{ marginBottom: '16px' }}>
        <label className="mono" style={{ display: 'block', fontSize: '11px', color: 'var(--text-dim)', marginBottom: '6px' }}>
          INSPECTION GATEWARE:
        </label>
        <select 
          value={toolType} 
          onChange={(e) => setToolType(e.target.value)}
          disabled={isProcessing}
        >
          <option value="search_cve">[01] search_cve — RAG Semantic Search</option>
          <option value="explain_vulnerability">[02] explain_vulnerability — Plain Text Summary</option>
          <option value="scan_log_for_iocs">[03] scan_log_for_iocs — Hybrid Threat Flagging</option>
          <option value="check_dependency_risk">[04] check_dependency_risk — Package Vuln Cross-Ref</option>
        </select>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
        <label className="mono" style={{ display: 'block', fontSize: '11px', color: 'var(--text-dim)', marginBottom: '6px' }}>
          PAYLOAD / TARGET:
        </label>
        <textarea
          rows={currentConfig.rows}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder={currentConfig.placeholder}
          disabled={isProcessing}
          style={{ resize: 'vertical', marginBottom: '16px', flex: 1, minHeight: '120px' }}
        />

        <button 
          type="submit" 
          disabled={isProcessing || !inputText.trim()}
          style={{ alignSelf: 'flex-start', width: '100%' }}
        >
          {isProcessing ? 'INSPECTION IN PROGRESS...' : currentConfig.buttonText}
        </button>
      </form>
    </div>
  );
}
