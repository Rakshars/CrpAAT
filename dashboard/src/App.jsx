import React, { useState, useEffect, useRef } from 'react';

// Threat states definitions
const THREAT_STATES = {
  0: {
    name: 'SAFE',
    color: '#00e676', // Green
    desc: 'Operational state is normal. No malicious behaviors reported. Standard RSA & AES handshake enabled.',
    className: 'state-0',
    offset: 565.48 * (1 - 0.1) // 10% filled
  },
  1: {
    name: 'ELEVATED',
    color: '#ffb800', // Yellow
    desc: 'Elevated threat. Detected failed authentication or timestamp drift. Key surveillance increased.',
    className: 'state-1',
    offset: 565.48 * (1 - 0.4) // 40% filled
  },
  2: {
    name: 'HIGH',
    color: '#ff007f', // Magenta/Orange
    desc: 'Brute-force cracking or packet tampering detected! Intruder IP blocked. Rotating AES key channels.',
    className: 'state-2',
    offset: 565.48 * (1 - 0.75) // 75% filled
  },
  3: {
    name: 'CRITICAL',
    color: '#ff1744', // Red
    desc: 'CRITICAL INFRASTRUCTURE REPLAY ATTACK! Server active honeypot initiated. Attacker trapped in decoy environment.',
    className: 'state-3',
    offset: 565.48 * (1 - 1.0) // 100% filled
  }
};

function App() {
  // Connection states
  const [serverIpInput, setServerIpInput] = useState('localhost');
  const [connectedServerIp, setConnectedServerIp] = useState('localhost');
  const [connectionStatus, setConnectionStatus] = useState('disconnected'); // disconnected, connecting, connected

  // Telemetry States
  const [threatLevel, setThreatLevel] = useState(0);
  const [sessionsCount, setSessionsCount] = useState(0);
  const [tampersCount, setTampersCount] = useState(0);
  const [blockedAdversaries, setBlockedAdversaries] = useState({}); // ip -> seconds
  const [rsaModulus, setRsaModulus] = useState('Generating Modulus on Startup...');
  const [aesSessionKey, setAesSessionKey] = useState('Awaiting AES Key Exchange...');
  const [aesRotated, setAesRotated] = useState(false);
  const [packets, setPackets] = useState([]);
  const [logs, setLogs] = useState([]);

  const consoleEndRef = useRef(null);

  // Auto-scroll logs console when logs update
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollTop = consoleEndRef.current.scrollHeight;
    }
  }, [logs]);

  // Dynamic connection to EventSource
  useEffect(() => {
    setConnectionStatus('connecting');
    setLogs([]);
    setPackets([]);
    setSessionsCount(0);
    setTampersCount(0);
    setRsaModulus('Awaiting Server Response...');
    setAesSessionKey('Awaiting AES Key Exchange...');
    
    // Auto-resolve localhost IP or connect to custom input
    const targetHost = connectedServerIp.trim() || 'localhost';
    const sseUrl = `http://${targetHost}:8080/events`;
    
    console.log(`Connecting to secure telemetry SSE at: ${sseUrl}`);
    const eventSource = new EventSource(sseUrl);

    eventSource.onopen = () => {
      setConnectionStatus('connected');
    };

    eventSource.onmessage = (event) => {
      try {
        const ssePayload = JSON.parse(event.data);
        const eventType = ssePayload.event;
        const payload = ssePayload.data;
        const globalThreat = ssePayload.threat_level;
        
        // Sync threat state
        setThreatLevel(globalThreat);
        
        // Sync blocked IPs cooldown timers
        if (ssePayload.blocked_ips) {
          const freshBlocks = {};
          for (let ip in ssePayload.blocked_ips) {
            freshBlocks[ip] = parseFloat(ssePayload.blocked_ips[ip]);
          }
          setBlockedAdversaries(freshBlocks);
        }

        // Process Log Entries
        if (eventType === 'log') {
          setLogs((prev) => {
            const next = [...prev, payload];
            return next.slice(-100); // keep last 100 entries
          });
          
          // Parse metrics
          if (payload.category === 'NETWORK') {
            if (payload.message.includes('New TCP connection')) {
              setSessionsCount((c) => c + 1);
            } else if (payload.message.includes('socket closed')) {
              setSessionsCount((c) => Math.max(0, c - 1));
            }
          }
          if (payload.category === 'ATTACK' && payload.message.includes('HMAC validation failed')) {
            setTampersCount((c) => c + 1);
          }
          
          // Parse rotating crypto keys
          if (payload.category === 'CRYPTO') {
            if (payload.message.includes('RSA-1024 Key Modulus N')) {
              const modulus = payload.message.split('N generated: ')[1];
              setRsaModulus(modulus);
            }
            if (payload.message.includes('AES-256 Session Key successfully decrypted')) {
              const aesKey = payload.message.split('established: ')[1];
              setAesSessionKey(aesKey + '... (Rotating/Established)');
              setAesRotated(true);
              setTimeout(() => setAesRotated(false), 3000); // Flash visual effect
            }
          }
        }
        
        // Process Packet Stream Cards
        if (eventType === 'packet') {
          setPackets((prev) => {
            const next = [payload, ...prev];
            return next.slice(0, 25); // keep last 25 cards
          });
        }
      } catch (e) {
        console.error('Error parsing SSE event:', e);
      }
    };

    eventSource.onerror = () => {
      setConnectionStatus('disconnected');
    };

    return () => {
      eventSource.close();
    };
  }, [connectedServerIp]);

  // Blocked Adversary Cooldown countdown clock (100ms ticker)
  useEffect(() => {
    const timer = setInterval(() => {
      setBlockedAdversaries((prev) => {
        const next = { ...prev };
        let changed = false;
        for (let ip in next) {
          if (next[ip] > 0.1) {
            next[ip] -= 0.1;
            changed = true;
          } else {
            delete next[ip];
            changed = true;
          }
        }
        return changed ? next : prev;
      });
    }, 100);

    return () => clearInterval(timer);
  }, []);

  const handleConnectClick = (e) => {
    e.preventDefault();
    setConnectedServerIp(serverIpInput);
  };

  const currentThreat = THREAT_STATES[threatLevel] || THREAT_STATES[0];
  const activeBlockedIps = Object.keys(blockedAdversaries);

  return (
    <div className="app-root">
      
      {/* Dynamic flashing warning strobe when honeypot trap isolates attacker */}
      {threatLevel === 3 && (
        <div className="alarm-banner">
          🔥 ALARM: ACTIVE CRITICAL CYBERATTACK IN PROGRESS — ADAPTIVE HONEYPOT FEEDER ACTIVE (TRAPPING IP)
        </div>
      )}

      {/* Top Application Header bar */}
      <header className="app-header">
        <div className="brand-container">
          <div className="logo-shield">🛡️</div>
          <div className="brand-text">
            <h1>Adaptive CryptoShield</h1>
            <p>Live Intrusion Monitoring & Defensive Cryptanalysis Console</p>
          </div>
        </div>

        {/* Dynamic IP Configuration controls */}
        <div className="ip-config-bar">
          <span className="ip-config-label">Server Host:</span>
          <input 
            type="text" 
            className="ip-config-input" 
            value={serverIpInput} 
            onChange={(e) => setServerIpInput(e.target.value)} 
            placeholder="localhost"
          />
          <button className="ip-config-btn" onClick={handleConnectClick}>
            Connect
          </button>
        </div>

        {/* Server listener beacon indicators */}
        <div className="server-badge" style={{ 
          color: connectionStatus === 'connected' ? 'var(--neon-green)' : connectionStatus === 'connecting' ? 'var(--neon-yellow)' : 'var(--neon-red)',
          borderColor: connectionStatus === 'connected' ? 'rgba(0, 230, 118, 0.25)' : connectionStatus === 'connecting' ? 'rgba(255, 184, 0, 0.25)' : 'rgba(255, 23, 68, 0.25)',
          background: connectionStatus === 'connected' ? 'rgba(0, 230, 118, 0.08)' : connectionStatus === 'connecting' ? 'rgba(255, 184, 0, 0.08)' : 'rgba(255, 23, 68, 0.08)'
        }}>
          {connectionStatus === 'connected' && <span className="pulse-dot"></span>}
          {connectionStatus === 'connected' ? 'SECURE CHANNEL ONLINE' : connectionStatus === 'connecting' ? 'CONNECTING TELEMETRY...' : 'CHANNEL OFFLINE'}
        </div>
      </header>

      {/* Dashboard Grid layout */}
      <main className="dashboard-grid">
        
        {/* Left Hand side control cards */}
        <section className="col-left">
          
          {/* Circular SVG Threat assessment Gauge */}
          <div className={`panel threat-panel state-${threatLevel}`}>
            <div className="panel-title" style={{ width: '100%' }}>
              <span className="title-icon">&gt;_</span> Threat Assessment Level
            </div>
            
            <div className="threat-gauge-container">
              <svg className="gauge-svg">
                <circle className="gauge-track" cx="100" cy="100" r="90"></circle>
                <circle 
                  className="gauge-fill active" 
                  cx="100" 
                  cy="100" 
                  r="90" 
                  style={{ 
                    strokeDashoffset: currentThreat.offset,
                    stroke: currentThreat.color
                  }}
                ></circle>
              </svg>
              <div className="threat-gauge-center">
                <span className="threat-level-value" style={{ color: currentThreat.color }}>
                  {threatLevel}
                </span>
                <span className="threat-level-label">LEVEL</span>
              </div>
            </div>
            
            <div className="threat-status-text" style={{ color: currentThreat.color }}>
              {currentThreat.name}
            </div>
            <p className="threat-desc">{currentThreat.desc}</p>
          </div>

          {/* Core IDS stats counter grid */}
          <div className="panel">
            <div className="panel-title">
              <span className="title-icon">&gt;_</span> Firewall & IDS Statistics
            </div>
            <div className="metrics-grid">
              <div className="metric-card">
                <div className="metric-title">Active Sockets</div>
                <div className="metric-value">{sessionsCount}</div>
              </div>
              <div className="metric-card">
                <div className="metric-title">TAMPER ALERTS</div>
                <div className="metric-value" style={{ color: 'var(--neon-magenta)' }}>
                  {tampersCount}
                </div>
              </div>
            </div>

            {/* Blocked IPs cooldown countdown list */}
            <div className="blocked-ips-panel">
              <div className="blocked-ips-header">
                <span>Blocked Adversaries</span>
                <span style={{ color: 'var(--neon-red)' }}>● LIVE COOLDOWNS</span>
              </div>
              <table className="blocked-ips-table">
                <thead>
                  <tr>
                    <th>Adversary IP</th>
                    <th>Block Duration Remaining</th>
                  </tr>
                </thead>
                <tbody>
                  {activeBlockedIps.length === 0 ? (
                    <tr>
                      <td colSpan="2" className="no-blocked-adversaries">
                        No blocked adversaries detected.
                      </td>
                    </tr>
                  ) : (
                    activeBlockedIps.map((ip) => (
                      <tr key={ip}>
                        <td className="ip-address">{ip}</td>
                        <td className="cooldown">
                          {blockedAdversaries[ip] ? blockedAdversaries[ip].toFixed(1) : '0.0'}s remaining
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Cryptographic Key displays */}
          <div className="panel">
            <div className="panel-title">
              <span className="title-icon">&gt;_</span> RSA & Rotating AES Key Blocks
            </div>
            <div className="keys-section">
              <div className="key-box">
                <div className="key-box-header">
                  <span>Host Server RSA-1024 Modulus N</span>
                  <span className="key-badge">ASYMMETRIC KEY</span>
                </div>
                <div className="key-text">{rsaModulus}</div>
              </div>
              
              <div className={`key-box aes-active ${aesRotated ? 'aes-rotation-effect' : ''}`}>
                <div className="key-box-header">
                  <span>Active Client AES-256 Session Key</span>
                  <span className="key-badge">SYMMETRIC ROTATION</span>
                </div>
                <div className="key-text">{aesSessionKey}</div>
              </div>
            </div>
          </div>

        </section>

        {/* Right Hand side console cards */}
        <section className="col-right">
          
          {/* Scrolling Packet stream deck */}
          <div className="panel sniffer-panel">
            <div className="panel-title">
              <span className="title-icon">&gt;_</span> Live Packet Sniffer / Decryption Telemetry
            </div>
            <div className="packet-list">
              {packets.length === 0 ? (
                <div className="packet-card-placeholder">
                  Awaiting active secure socket transmissions...
                </div>
              ) : (
                packets.map((pkt, idx) => {
                  let statusClass = 'pack-passed';
                  if (pkt.status === 'tampered') statusClass = 'pack-tampered';
                  else if (pkt.status === 'replay') statusClass = 'pack-replay';
                  else if (pkt.summary.includes('Honeypot') || pkt.summary.includes('fake') || pkt.detail.includes('FAKE')) {
                    statusClass = 'pack-decoy';
                  }

                  return (
                    <div key={idx} className={`packet-card ${statusClass}`}>
                      <div className="packet-card-meta">
                        <span className="packet-type-badge">{pkt.type}</span>
                        <span className="packet-direction">{pkt.direction}</span>
                        <span>{new Date().toLocaleTimeString()}</span>
                      </div>
                      <div className="packet-card-summary">{pkt.summary}</div>
                      <div className="packet-card-detail">{pkt.detail}</div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Autoscrolling alerts console */}
          <div className="panel console-panel">
            <div className="panel-title">
              <span className="title-icon">&gt;_</span> Host Intrusion Detection & Defense Event Logs
            </div>
            <div className="console-output" ref={consoleEndRef}>
              {logs.map((log, idx) => (
                <div key={idx} className={`console-line line-${log.level}`}>
                  <span className="console-time">[{log.timestamp ? log.timestamp.split(' ')[1] : ''}]</span>
                  <span className={`console-cat cat-${log.category}`}>[{log.category}]</span>
                  <span className="console-msg">{log.message}</span>
                </div>
              ))}
            </div>
          </div>

        </section>

      </main>
    </div>
  );
}

export default App;
