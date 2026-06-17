// Live doublethink demo driver. Runs entirely in the browser against the public
// broker. It generates a fresh secret here, creates a throwaway ephemeral channel,
// connects two parties, has A send one end-to-end-encrypted message to B, and
// shows the on-wire ciphertext vs the plaintext only the secret-holder recovers,
// then proves a wrong secret cannot read it. Nothing persists.
//
// crypto lives in demo-crypto.js (verified byte-compatible with the Go broker);
// secretbox is vendored tweetnacl (window.nacl).
import {
  generateSecret, registrationKey, challengeResponse, session, seal, open, _internal,
} from "./demo-crypto.js";

const BASE = "https://api.caleidoscode.io";
const WSS = "wss://api.caleidoscode.io/ws";
const { b64encode } = _internal;
const enc = new TextEncoder();
const dec = new TextDecoder();

const runBtn = document.getElementById("demo-run");
const out = document.getElementById("demo-out");
const msgInput = document.getElementById("demo-msg");

function reset() { out.innerHTML = ""; out.hidden = false; }
function step(label, valueHtml, cls) {
  const d = document.createElement("div");
  d.className = "demo-step";
  d.innerHTML = `<div class="demo-label">${label}</div>` +
    (cls ? `<div class="${cls}">${valueHtml}</div>` : `<span class="demo-mono">${valueHtml}</span>`);
  out.appendChild(d);
}
function esc(s) { return s.replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

// One authenticated WebSocket attach as a holder of `secret` on `channel`.
function attach(channel, secret) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(WSS);
    ws.binaryType = "arraybuffer";
    let stage = 0;
    const t = setTimeout(() => { ws.close(); reject(new Error("timeout")); }, 12000);
    ws.onopen = () => ws.send(JSON.stringify({ channel }));
    ws.onmessage = (ev) => {
      const m = JSON.parse(typeof ev.data === "string" ? ev.data : dec.decode(ev.data));
      if (stage === 0) {
        const challenge = Uint8Array.from(atob(m.challenge), c => c.charCodeAt(0));
        const resp = challengeResponse(secret, challenge);
        ws.send(JSON.stringify({ response: b64encode(resp) }));
        stage = 1;
      } else if (stage === 1) {
        clearTimeout(t);
        if (m.ok) resolve(ws); else { ws.close(); reject(new Error(m.error || "not authorized")); }
        stage = 2;
      }
    };
    ws.onerror = () => { clearTimeout(t); reject(new Error("connection failed")); };
  });
}

async function runDemo() {
  runBtn.disabled = true;
  reset();
  let a, b;
  try {
    const nacl = window.nacl;
    if (!nacl || !nacl.secretbox) throw new Error("crypto library not loaded");

    // 1. fresh secret + ephemeral channel, created right here in the browser.
    const secret = generateSecret();
    const channel = "demo/" + b64encode(crypto.getRandomValues(new Uint8Array(8))).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
    step("1. secret generated in your browser (shared between the two parties, never sent to the broker)", esc(secret));

    const createResp = await fetch(BASE + "/channel", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel, auth_key: registrationKey(secret), retain: false }),
    });
    if (createResp.status === 429) throw new Error("the public demo broker is busy (rate limit shared across visitors); wait a minute and try again. This is the abuse control working, not a fault in your request.");
    if (!createResp.ok) throw new Error("channel create failed (HTTP " + createResp.status + ")");
    step("2. ephemeral channel created on the live broker", esc(channel));

    // 2. both parties attach with the secret.
    a = await attach(channel, secret);
    b = await attach(channel, secret);
    step("3. both parties attached", "<span class='demo-ok'>authenticated with the shared secret</span>", "");

    // collect what B receives.
    const received = new Promise((resolve) => {
      b.onmessage = (ev) => {
        const env = JSON.parse(typeof ev.data === "string" ? ev.data : dec.decode(ev.data));
        resolve(env);
      };
    });

    // 3. A seals a message and publishes it.
    const plaintext = (msgInput.value || "hello").slice(0, 200);
    const sa = session(secret, "a");
    const sealed = seal(sa, enc.encode(plaintext), nacl);
    const payloadB64 = b64encode(sealed);
    const envelope = { channel, type: "request", id: "demo", payload: payloadB64, ts: new Date().toISOString() };
    const wire = JSON.stringify(envelope);
    a.send(wire);
    step("4. what party A typed (plaintext)", esc(plaintext));
    step("5. the exact bytes the broker relays (ciphertext; this is all the operator ever sees)", esc(wire));

    // 4. B receives and decrypts with the correct secret.
    const env = await received;
    const blob = Uint8Array.from(atob(env.payload), c => c.charCodeAt(0));
    const sb = session(secret, "b");
    const opened = open(sb, blob, nacl);
    step("6. what party B recovers with the secret", opened ? esc(dec.decode(opened)) : "<span class='demo-bad'>decrypt failed</span>", opened ? "demo-ok demo-mono" : "demo-bad");

    // 5. wrong secret cannot read the same bytes.
    const wrong = session(generateSecret(), "b");
    const wrongOpen = open(wrong, blob, nacl);
    step("7. the same bytes, opened with the WRONG secret",
      wrongOpen ? "<span class='demo-bad'>unexpectedly decrypted</span>" : "decryption refused: knowing the channel grants nothing without the secret",
      wrongOpen ? "demo-bad" : "demo-ok");
  } catch (e) {
    step("demo error", "<span class='demo-bad'>" + esc(String(e.message || e)) + "</span>", "");
  } finally {
    try { a && a.close(); } catch (_) {}
    try { b && b.close(); } catch (_) {}
    runBtn.disabled = false;
  }
}

runBtn.addEventListener("click", runDemo);
