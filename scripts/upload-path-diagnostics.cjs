// Local, opt-in diagnostics for a running development Hub. No payloads or IDs
// are printed. Wrappers restore on exit or automatically after thirty minutes.
// Run with Node 22+: node scripts/upload-path-diagnostics.cjs
const install = () => {
  const cache = process.mainModule.require('module')._cache;
  const entry = Object.entries(cache).find(([p]) => p.endsWith('/private-transport-sidecar.js'));
  if (!entry) throw new Error('Hub sidecar module is not loaded');
  globalThis.__uploadPathDiagnostic?.stop();
  const proto = entry[1].exports.PrivateTransportSidecar.prototype;
  const original = proto.sendPrivateReliable;
  const stats = { sends: 0, bytes: 0, sendMs: 0, sendMaxMs: 0, ackMs: 0, ackMaxMs: 0, acks: 0, errors: 0 };
  const tracked = new Map();
  const peers = new Map();
  const started = Date.now();
  const observe = (sidecar, sessionId) => {
    if (!peers.has(sidecar)) {
      const handler = e => {
        const key = e.sessionId + ':' + e.messageId;
        const since = tracked.get(key);
        if (since === undefined || e.event !== 'reliableMessage') return;
        tracked.delete(key);
        const ms = performance.now() - since;
        stats.acks++; stats.ackMs += ms; stats.ackMaxMs = Math.max(stats.ackMaxMs, ms);
      };
      sidecar.on('event', handler);
      peers.set(sidecar, { handler, sessions: new Set() });
    }
    peers.get(sidecar).sessions.add(sessionId);
  };
  async function wrapped(sessionId, messageId, data, ...rest) {
    if (data.length <= 65536) return original.call(this, sessionId, messageId, data, ...rest);
    observe(this, sessionId);
    const key = sessionId + ':' + messageId;
    const since = performance.now();
    // Bounded even when a peer never acknowledges.
    if (tracked.size >= 64) tracked.delete(tracked.keys().next().value);
    tracked.set(key, since);
    stats.sends++; stats.bytes += data.length;
    try { return await original.call(this, sessionId, messageId, data, ...rest); }
    catch (e) { stats.errors++; tracked.delete(key); throw e; }
    finally { const ms = performance.now() - since; stats.sendMs += ms; stats.sendMaxMs = Math.max(stats.sendMaxMs, ms); }
  }
  proto.sendPrivateReliable = wrapped;
  const timer = setTimeout(() => globalThis.__uploadPathDiagnostic?.stop(), 1800000);
  globalThis.__uploadPathDiagnostic = {
    async sample() {
      const quic = [];
      for (const [sidecar, { sessions }] of peers) for (const id of sessions) {
        try { quic.push(await sidecar.sessionMetrics(id)); } catch { /* closed */ }
      }
      return { elapsedMs: Date.now() - started, ...stats, awaitingAck: tracked.size, quic };
    },
    stop() {
      clearTimeout(timer);
      if (proto.sendPrivateReliable === wrapped) proto.sendPrivateReliable = original;
      for (const [s, { handler }] of peers) s.off('event', handler);
      tracked.clear(); peers.clear(); delete globalThis.__uploadPathDiagnostic;
    },
  };
  return true;
};

const installClient = () => {
  globalThis.__uploadClientDiagnostic?.stop();
  const stats = {};
  const restorers = [];
  for (const [target, name, key] of [
    [crypto.subtle, 'encrypt', 'encryption'],
    [crypto.subtle, 'digest', 'hashing'],
    [Blob.prototype, 'arrayBuffer', 'fileReads'],
  ]) {
    const original = target[name];
    stats[key] = { calls: 0, ms: 0, maxMs: 0 };
    async function wrapped(...args) {
      const since = performance.now();
      try { return await original.apply(this, args); }
      finally {
        const ms = performance.now() - since;
        stats[key].calls++; stats[key].ms += ms;
        stats[key].maxMs = Math.max(stats[key].maxMs, ms);
      }
    }
    target[name] = wrapped;
    restorers.push(() => { if (target[name] === wrapped) target[name] = original; });
  }
  const timer = setTimeout(() => globalThis.__uploadClientDiagnostic?.stop(), 1800000);
  globalThis.__uploadClientDiagnostic = { stats, stop() {
    clearTimeout(timer); restorers.forEach(fn => fn()); delete globalThis.__uploadClientDiagnostic;
  } };
  return true;
};

(async () => {
  const [target] = await (await fetch('http://127.0.0.1:5858/json/list')).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let seq = 0;
  const pending = new Map();
  ws.onmessage = e => {
    const response = JSON.parse(e.data);
    const entry = pending.get(response.id);
    if (entry) { pending.delete(response.id); entry(response); }
  };
  async function evaluate(expression) {
    const id = ++seq;
    const reply = new Promise(resolve => pending.set(id, resolve));
    ws.send(JSON.stringify({ id, method: 'Runtime.evaluate', params: { expression, awaitPromise: true, returnByValue: true } }));
    const response = await reply;
    if (response.error || response.result?.exceptionDetails) throw new Error('Diagnostic evaluation failed');
    return response.result.result.value;
  }
  const frames = "process.mainModule.require('electron').webContents.getAllWebContents().flatMap(w=>w.mainFrame.framesInSubtree).filter(f=>f.url.startsWith('http://127.0.0.1:12393/'))";
  const inFrames = expression => `Promise.all(${frames}.map(f=>f.executeJavaScript(${JSON.stringify(expression)}).catch(()=>null)))`;
  let stopped = false;
  async function stop() {
    if (stopped) return;
    stopped = true;
    await evaluate('globalThis.__uploadPathDiagnostic?.stop()').catch(() => {});
    await evaluate(inFrames('globalThis.__uploadClientDiagnostic?.stop()')).catch(() => {});
    ws.close();
  }
  process.on('SIGINT', () => { void stop(); });
  process.on('SIGTERM', () => { void stop(); });
  try {
    await evaluate(`(${install.toString()})()`);
    console.log('Client instrumentation:', await evaluate(inFrames(`(${installClient.toString()})()`)));
    console.log('READY: upload a test file; numeric samples every five seconds. Expires in thirty minutes.');
    const end = Date.now() + 1790000;
    while (!stopped && Date.now() < end) {
      const hub = await evaluate('globalThis.__uploadPathDiagnostic?.sample()');
      const client = await evaluate(inFrames('globalThis.__uploadClientDiagnostic?.stats'));
      console.log(JSON.stringify({ time: new Date().toISOString(), hub, client }));
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  } finally { await stop(); }
})().catch(() => { console.error('Diagnostics stopped: inspector unavailable or evaluation failed.'); process.exitCode = 1; });
