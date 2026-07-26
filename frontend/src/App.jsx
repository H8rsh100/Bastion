import React from 'react';
import './index.css';

function App() {
  return (
    <div className="app-container">
      <header>
        <div className="brand-title">BASTION</div>
        <div className="thesis">Security intelligence that never leaves the building</div>
      </header>
      <main>
        <div className="pane">
          <div className="pane-header">SYSTEM STATUS</div>
          <p className="mono">CHECKPOINT ACTIVE. WAITING FOR INSPECTION PIPELINE.</p>
        </div>
      </main>
    </div>
  );
}

export default App;
