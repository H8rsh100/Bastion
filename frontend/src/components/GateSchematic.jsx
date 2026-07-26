import React, { useState, useEffect } from 'react';
import './GateSchematic.css';

export default function GateSchematic({ activeGate = null, isDemo = true, collapsed = false }) {
  const [demoStep, setDemoStep] = useState(0);

  useEffect(() => {
    if (!isDemo) return;
    const interval = setInterval(() => {
      setDemoStep((prev) => (prev + 1) % 4);
    }, 1500);
    return () => clearInterval(interval);
  }, [isDemo]);

  // Determine which gate is illuminated
  const currentGate = isDemo 
    ? (demoStep === 0 ? 'RETRIEVE' : demoStep === 1 ? 'GROUND' : demoStep === 2 ? 'INSPECT' : null)
    : activeGate;

  return (
    <div className={`schematic-container ${collapsed ? 'collapsed' : ''}`}>
      <div className="schematic-header">
        <span>// PIPELINE SCHEMATIC: CHECKPOINT SECTOR 4</span>
        <div className="schematic-status">
          <div className={`status-indicator ${currentGate ? 'active' : ''}`} />
          <span>{currentGate ? `GATE [${currentGate}] INSPECTION IN PROGRESS` : 'STANDBY — WAITING FOR INGRESS'}</span>
        </div>
      </div>

      <div className={`pipeline-track ${isDemo ? 'animating' : ''}`}>
        <div className="packet-beam" />

        <div className={`gate-booth ${currentGate === 'RETRIEVE' ? 'active' : ''}`}>
          <div className="gate-title">RETRIEVE</div>
          <div className="gate-desc">RAG TOP-K VECTOR LOOKUP OVER CVE KNOW-BASE</div>
          <div className="gate-telemetry">
            {currentGate === 'RETRIEVE' ? 'STATUS: MATCHING QDRANT VECTORS...' : 'STATUS: QDRANT ONLINE'}
          </div>
        </div>

        <div className={`gate-booth ${currentGate === 'GROUND' ? 'active' : ''}`}>
          <div className="gate-title">GROUND</div>
          <div className="gate-desc">OFFLINE QUANTIZED LLM INFERENCE & ATTRIBUTION</div>
          <div className="gate-telemetry">
            {currentGate === 'GROUND' ? 'STATUS: GENERATING GGUF TOKENS...' : 'STATUS: MISTRAL-7B READY'}
          </div>
        </div>

        <div className={`gate-booth ${currentGate === 'INSPECT' ? 'active' : ''}`}>
          <div className="gate-title">INSPECT</div>
          <div className="gate-desc">HYBRID IOC SCAN & DEPENDENCY VULN VALIDATION</div>
          <div className="gate-telemetry">
            {currentGate === 'INSPECT' ? 'STATUS: CROSS-REFERENCING IOCS...' : 'STATUS: FILTER CLEAN'}
          </div>
        </div>
      </div>
    </div>
  );
}
