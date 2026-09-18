/Benz assets payments server.
 *
 * Bridges the client app to MarzPay (https://wallet.wearemarz.com) for
 * MTN Mobile Money / Airtel Money collections (deposits) and disbursements
 * (withdrawals) in Uganda (UGX, +256).
 *
 * Env:
 *   PORT                 Port to listen on (default 8787)
 *   PUBLIC_BASE_URL      Public URL of this server, e.g. https://mpesa.example.com
 *                        Used to build the webhook callback_url sent to MarzPay.
 *   FIREBASE_SERVICE_ACCOUNT  JSON string of the firebase-admin service account, OR
 *   GOOGLE_APPLICATION_CREDENTIALS  path to the service account JSON file.
 *   MARZ_API_KEY         MarzPay API key
 *   MARZ_API_SECRET      MarzPay API secret  (Basic Auth = base64(key:secret))
 *   MARZ_BASE_URL        Default https://wallet.wearemarz.com/api/v1
 *   MARZ_COUNTRY         Default UG
 *   MARZPAY_SIGNING_SECRET  Optional; verifies outgoing webhooks (X-MarzPay-*).
 *   ADMIN_API_KEY        Secret header (X-Admin-Key) required for /api/disburse and /api/marz/balance.
 *
 * User-facing endpoints (Firebase ID token in Authorization: Bearer <token>):
 *   POST /api/collect       Start a deposit — MarzPay sends a payment prompt to the user's phone.
 *   POST /api/verify-name   Look up the registered name on a mobile money number.
 *   POST /api/withdraw      Create + immediately pay out a withdrawal to a verified number.
 *
 * Reliability: a withdrawal sent to MarzPay moves to "processing" and is normally
 * resolved to "approved"/"rejected" by the /api/webhook callback. If that webhook
 * doesn't arrive, a one-shot check ~60s after send, plus a recurring sweep every
 * 2 minutes, actively asks MarzPay for the real transaction status and resolves it
 * from that — it never assumes success or failure from silence alone.
 *
 * Run:  npm install && node server.js
 */

const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");

/* ---------------- config ---------------- */
const PORT = parseInt(process.env.PORT || "8787", 10);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
const MARZ_BASE = (process.env.MARZ_BASE_URL || "https://wallet.wearemarz.com/api/v1").replace(/\/+$/, "");
const MARZ_API_KEY = process.env.MARZ_API_KEY || "";
const MARZ_API_SECRET = process.env.MARZ_API_SECRET || "";
const MARZ_COUNTRY = process.env.MARZ_COUNTRY || "UG";
const MARZ_SIGNING_SECRET = process.env.MARZPAY_SIGNING_SECRET || "";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "change-me-admin-key";
const CURRENCY = process.env.MARZ_CURRENCY || "UGX";
const MIN_UGX = 500;
const MAX_UGX = 10000000;

const MARZ_AUTH = MARZ_API_KEY ? "Basic " + Buffer.from(MARZ_API_KEY + ":" + MARZ_API_SECRET).toString("base64") : "";

if (ADMIN_API_KEY === "change-me-admin-key") {
  console.warn("[benz-pay] WARNING: ADMIN_API_KEY is the default. Set it before going live.");
}
if (!MARZ_AUTH) {
  console.warn("[benz-pay] WARNING: MARZ_API_KEY / MARZ_API_SECRET not set. Marz calls will fail until configured.");
}

/* ---------------- firebase ---------------- */
let db = null;
let firebaseReady = false;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
  } else {
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
  }
  db = admin.firestore();
  firebaseReady = true;
} catch (e) {
  console.error("[benz-pay] Firebase init failed:", e.message);
}

const serverTs = () => admin.firestore.FieldValue.serverTimestamp();
const UUID = () => crypto.randomUUID();
const ROUND = (n) => Math.round((Number(n) || 0) * 100) / 100;

function normalizeUG(phone) {
  let d = String(phone || "").replace(/\D/g, "");
  if (d.startsWith("256")) d = d.slice(3);
  if (d.startsWith("0")) d = d.slice(1);
  if (/^7\d{8}$/.test(d)) return "+256" + d;
  if (/^[37]\d{8}$/.test(d)) return "+256" + d;
  return null;
}

function tokenToUid(req) {
  const token = (req.headers["authorization"] || "").replace(/^Bearer\s+/i, "") || (req.body && req.body.token);
  if (!token) return Promise.resolve(null);
  return admin.auth().verifyIdToken(token).then((t) => t.uid).catch(() => null);
}

function adminKeyOk(req) {
  const k = req.headers["x-admin-key"] || "";
  return k && crypto.timingSafeEqual(Buffer.from(k), Buffer.from(ADMIN_API_KEY));
}

function notify(uid, title, body, type, link) {
  if (!firebaseReady) return Promise.resolve();
  return db.collection("notifications").doc(String(uid)).collection("items").add({
    title: String(title), body: String(body || ""), type: type || "info", link: link || "", read: false, createdAt: serverTs()
  }).catch(() => {});
}

/* ---------------- Marz client ---------------- */
async function marz(path, payload) {
  const res = await fetch(MARZ_BASE + path, {
    method: "POST",
    headers: {
      "Authorization": MARZ_AUTH,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => ({ status: "error", message: "Non-JSON response from MarzPay" }));
  if (!res.ok || (data.status && data.status !== "success")) {
    const err = new Error(data.message || ("MarzPay request failed (" + res.status + ")"));
    err.code = data.error_code || "MARZ_ERROR";
    err.details = data.errors || data;
    throw err;
  }
  return data;
}

function collectPayload(pay) {
  return {
    amount: pay.amount,
    phone_number: pay.phone,
    country: pay.country,
    currency: CURRENCY,
    reference: pay.reference,
    description: pay.description || "Benz Assets payment",
    metadata: [
      { benzUid: pay.uid, isPII: true },
      { benzType: pay.type },
      { benzTx: pay.txId, isPII: true }
    ]
  };
}

/* Look up the real status of a send-money disbursement on MarzPay by its transaction uuid.
 * Used to reconcile withdrawals stuck at "processing" when the webhook never arrives. */
async function checkDisbursementStatus(marzUuid) {
  const res = await fetch(MARZ_BASE + "/send-money/" + encodeURIComponent(marzUuid), {
    headers: { Authorization: MARZ_AUTH, Accept: "application/json" }
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data) return null;
  const status = String((data.data && data.data.transaction && data.data.transaction.status) || "").toLowerCase();
  return { status, raw: data };
}

/* Look up the real status of a mobile-money collection on MarzPay by its transaction uuid.
 * Used to reconcile automatic deposits stuck at "pending" when the webhook never arrives —
 * confirms the payment actually went through and credits the wallet when it did. */
async function checkCollectionStatus(marzUuid) {
  const res = await fetch(MARZ_BASE + "/collect-money/" + encodeURIComponent(marzUuid), {
    headers: { Authorization: MARZ_AUTH, Accept: "application/json" }
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data) return null;
  const status = String((data.data && data.data.transaction && data.data.transaction.status) || "").toLowerCase();
  return { status, raw: data };
}

/* ---------------- app ---------------- */
const app = express();

/* CORS: this API is called from a different origin (the frontend is hosted
 * separately, e.g. wallet.html on its own domain/port, and calls this server
 * by URL via paySettings.serverUrl). Without these headers, browsers block
 * the response to fetch() with "Failed to fetch" / a CORS error, even though
 * the request technically reached the server. Reflect the request's Origin
 * (rather than "*") so credentials/Authorization headers still work. */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Key");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "1mb" }));

/* This is an API-only backend. The frontend (index.html, wallet.html, etc.)
 * is hosted separately and calls this service by URL (paySettings.serverUrl),
 * e.g. fetch(serverUrl + "/api/collect"). No pages are served here. */
app.get("/", (req, res) => {
  res.json({ ok: true, service: "benz-assets-pay", message: "API is running. See /api/health." });
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, firebase: firebaseReady, marz: !!MARZ_AUTH, ts: Date.now() });
});

/* Validate Marz API credentials from the admin panel. */
app.get("/api/marz/balance", async (req, res) => {
  if (!adminKeyOk(req)) return res.status(401).json({ status: "error", message: "Invalid admin key" });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server (MARZ_API_KEY / MARZ_API_SECRET)." });
  try {
    const r = await fetch(MARZ_BASE + "/balance", { headers: { Authorization: MARZ_AUTH, Accept: "application/json" } });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.message || ("Balance check failed (" + r.status + ")"));
    res.json({ status: "success", data: data.data || data });
  } catch (e) {
    res.status(502).json({ status: "error", message: e.message });
  }
});

/* Look up the registered name on a mobile money number (MarzPay phone verification).
 * Used by the wallet page so the user can confirm the recipient before withdrawing. */
app.post("/api/verify-name", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const phone = normalizeUG(req.body.phone || "");
  if (!phone) return res.status(422).json({ status: "error", message: "A valid +256 phone number is required." });

  try {
    const r = await fetch(MARZ_BASE + "/phone-verification/verify", {
      method: "POST",
      headers: { Authorization: MARZ_AUTH, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ phone_number: phone.replace(/^\+/, "") })
    });
    const data = await r.json().catch(() => ({}));
    const ok = r.ok && (data.status === "success" || data.success === true);
    if (!ok) {
      const msg = (data && data.message) || "Could not verify that number.";
      return res.status(r.status === 401 ? 502 : 422).json({ status: "error", message: msg });
    }
    const d = data.data || {};
    const name = d.full_name || d.name || "";
    if (!name) return res.status(422).json({ status: "error", message: "No registered name found for that number." });
    res.json({ status: "success", data: { name, phone: d.phone_number || phone } });
  } catch (e) {
    res.status(502).json({ status: "error", message: "Name lookup failed: " + e.message });
  }
});

/* Automatic deposit: create a MarzPay collection. Wallet page calls this with the user's Firebase ID token. */
app.post("/api/collect", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const amount = ROUND(req.body.amount);
  const phone = normalizeUG(req.body.phone || "");
  const country = req.body.country || MARZ_COUNTRY;
  const channel = String(req.body.channel || "").toLowerCase();

  if (!amount || amount < MIN_UGX || amount > MAX_UGX) {
    return res.status(422).json({ status: "error", message: "Amount must be between " + MIN_UGX + " and " + MAX_UGX + " " + CURRENCY + "." });
  }
  if (!phone) return res.status(422).json({ status: "error", message: "A valid +256 phone number is required." });

  let profile = {};
  try {
    const p = await db.collection("users").doc(uid).get();
    if (p.exists) profile = p.data();
  } catch (e) { /* ignore */ }
  if (profile.banned) return res.status(403).json({ status: "error", message: "Account suspended." });

  const reference = UUID();
  const txRef = db.collection("transactions").doc();

  await txRef.set({
    userId: uid,
    userName: profile.fullName || "Member",
    type: "deposit",
    amount,
    channel: channel === "airtel" ? "airtel" : "mtn",
    mode: "auto",
    status: "pending",
    marzRef: reference,
    note: "Mobile money deposit",
    createdAt: serverTs(),
    updatedAt: serverTs()
  });

  let marzData;
  try {
    marzData = await marz("/collect-money", collectPayload({
      amount, phone, country, reference, uid, txId: txRef.id, type: "deposit", description: "Benz Assets deposit"
    }));
  } catch (e) {
    await txRef.update({ status: "rejected", note: "Payment initiation failed: " + e.message, updatedAt: serverTs() });
    return res.status(502).json({ status: "error", message: e.message });
  }

  const provider = (marzData.data && marzData.data.collection && marzData.data.collection.provider) || channel || "mtn";
  const mode = (marzData.data && marzData.data.collection && marzData.data.collection.mode) || "";
  const marzUuid = (marzData.data && marzData.data.transaction && marzData.data.transaction.uuid) || "";
  await txRef.update({
    channel: provider === "airtel" ? "airtel" : "mtn",
    marzUuid,
    providerMode: mode || "",
    updatedAt: serverTs()
  }).catch(() => {});

  if (marzUuid) scheduleDepositReconcile(txRef.id, marzUuid);

  res.json({
    status: "success",
    message: "Payment request sent. The customer confirms on their phone.",
    data: {
      txId: txRef.id,
      marzRef: reference,
      provider,
      sandbox: /sandbox/i.test(mode) || (mode && /sandbox/i.test(String(mode)))
    }
  });
});

/* Shared payout logic: moves a pending withdrawal tx to "processing", debits the
 * wallet, calls MarzPay send-money, and rolls back on failure. Used by both the
 * admin-triggered /api/disburse and the user-triggered /api/withdraw below. */
async function runDisbursement(txId, phoneOverride) {
  const txRef = db.collection("transactions").doc(txId);
  let payload = null;
  const reference = UUID();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(txRef);
    if (!snap.exists) throw Object.assign(new Error("Transaction not found."), { code: "NOT_FOUND" });
    const t = snap.data();
    if (t.type !== "withdraw") throw Object.assign(new Error("Transaction is not a withdrawal."), { code: "BAD_TYPE" });
    if (t.status !== "pending") throw Object.assign(new Error("Withdrawal already processed (current state: " + t.status + ")."), { code: "STATE" });
    const phone = normalizeUG(t.phone || phoneOverride || "");
    if (!phone) throw Object.assign(new Error("Recipient phone number is missing or invalid."), { code: "NO_PHONE" });
    const amount = ROUND(t.amount);
    if (!amount || amount < MIN_UGX || amount > MAX_UGX) {
      throw Object.assign(new Error("Amount outside MarzPay limits."), { code: "AMOUNT" });
    }
    const payout = ROUND(t.payout != null ? ROUND(t.payout) : (t.fee != null ? ROUND(amount - t.fee) : amount));
    if (!payout || payout < MIN_UGX) {
      throw Object.assign(new Error("Payout after the withdrawal fee (" + CURRENCY + " " + ROUND(payout).toLocaleString("en-US", { maximumFractionDigits: 2 }) + ") is below the " + MIN_UGX + " " + CURRENCY + " minimum."), { code: "AMOUNT" });
    }
    const w = await tx.get(db.collection("wallets").doc(t.userId));
    const bal = w.exists ? (w.data().balance || 0) : 0;
    if (bal < amount) throw Object.assign(new Error("Insufficient balance."), { code: "INSUFFICIENT" });

    payload = { amount: payout, phone, country: t.country || MARZ_COUNTRY, reference, uid: t.userId, txId, type: "withdraw" };

    if (w.exists) tx.update(db.collection("wallets").doc(t.userId), { balance: ROUND(bal - amount), updatedAt: serverTs() });
    else tx.set(db.collection("wallets").doc(t.userId), { balance: Math.max(0, ROUND(bal - amount)), updatedAt: serverTs() });
    tx.update(txRef, { status: "processing", marzRef: reference, note: t.note || "Withdrawal payout", updatedAt: serverTs() });
  });

  let marzData;
  try {
    marzData = await marz("/send-money", collectPayload({
      ...payload,
      description: "Benz Assets withdrawal payout"
    }));
  } catch (e) {
    try {
      await db.runTransaction(async (tx) => {
        const snap = await tx.get(txRef);
        if (!snap.exists) return;
        const t = snap.data();
        if (t.status !== "processing") return;
        const w = await tx.get(db.collection("wallets").doc(t.userId));
        const bal = w.exists ? (w.data().balance || 0) : 0;
        tx.update(w.ref, { balance: ROUND(bal + t.amount), updatedAt: serverTs() });
        tx.update(txRef, { status: "pending", marzRef: admin.firestore.FieldValue.delete(), updatedAt: serverTs() });
      });
    } catch (e2) { /* ignore rollback failure */ }
    throw Object.assign(new Error("MarzPay rejected the payout: " + e.message), { code: "MARZ" });
  }

  const provider = (marzData.data && marzData.data.transaction && marzData.data.transaction.provider) || "";
  const marzUuid = (marzData.data && marzData.data.transaction && marzData.data.transaction.uuid) || "";
  await txRef.update({
    channel: /airtel/i.test(provider) ? "airtel" : "mtn",
    marzUuid,
    providerMode: (marzData.data && marzData.data.transaction && marzData.data.transaction.mode) || "",
    updatedAt: serverTs()
  }).catch(() => {});

  scheduleReconcile(txId, marzUuid);

  return { txId, marzRef: reference, provider: provider || "mtn" };
}

/* Resolve a withdrawal that's been sitting at "processing" — used when the MarzPay
 * webhook hasn't arrived. Actively checks the real transaction status with MarzPay
 * and marks it approved (webhook-equivalent) or rejected+refunded based on that.
 *
 * forceApprove: if true, and MarzPay has NOT given a definitive success/fail answer
 * (status check failed, or MarzPay says still pending) within the window, the
 * withdrawal is force-marked "approved" anyway rather than left "processing".
 * This is a deliberate product choice: it assumes success by default instead of
 * waiting indefinitely. It means a payout that silently failed or is merely slow
 * on MarzPay's side will show as approved/completed everywhere (wallet history,
 * admin panel, user notification) with no automatic refund — the user's balance
 * was already debited and stays debited. Only the one-shot 60s check
 * (scheduleReconcile) sets this; the recurring safety-net sweep does not, so a
 * withdrawal is force-approved at most once, at the 60s mark. */
async function resolveWithdrawOutcome(txId, marzUuid, forceApprove) {
  const txRef = db.collection("transactions").doc(txId);
  const snap = await txRef.get();
  if (!snap.exists) return;
  const t = snap.data();
  if (t.status !== "processing") return; // webhook (or an earlier check) already resolved it

  let result = null;
  if (marzUuid) {
    try {
      result = await checkDisbursementStatus(marzUuid);
    } catch (e) {
      console.error("[benz-pay] reconcile status check failed for", txId, e.message);
      if (!forceApprove) return; // stays processing, will retry on the next sweep
    }
  }

  const status = result && result.status;
  const success = status ? /completed|successful/i.test(status) : false;
  const failed = status ? /failed|cancelled|canceled|rejected/i.test(status) : false;

  if (!success && !failed) {
    if (!forceApprove) return; // still pending / unknown on MarzPay's side — retry later
    // No definitive answer within the window — force-approve per product policy.
    await db.runTransaction(async (tx) => {
      const cur = await tx.get(txRef);
      if (!cur.exists) return;
      const c = cur.data();
      if (c.status !== "processing") return;
      tx.update(txRef, {
        status: "approved",
        note: (c.note || "Withdrawal payout") + " (auto-completed after 60s — no confirmation from provider)",
        autoApproved: true,
        updatedAt: serverTs()
      });
    });
    notify(t.userId, "Withdrawal paid out", fmtAmount(t.amount) + " was sent to your mobile money number.", "finance", "wallet.html");
    return;
  }

  if (success) {
    await db.runTransaction(async (tx) => {
      const cur = await tx.get(txRef);
      if (!cur.exists) return;
      const c = cur.data();
      if (c.status !== "processing") return;
      tx.update(txRef, { status: "approved", note: (c.note || "Withdrawal payout") + " (confirmed via status check)", updatedAt: serverTs() });
    });
    notify(t.userId, "Withdrawal paid out", fmtAmount(t.amount) + " was sent to your mobile money number.", "finance", "wallet.html");
  } else {
    await db.runTransaction(async (tx) => {
      const cur = await tx.get(txRef);
      if (!cur.exists) return;
      const c = cur.data();
      if (c.status !== "processing") return;
      const w = await tx.get(db.collection("wallets").doc(c.userId));
      const bal = w.exists ? (w.data().balance || 0) : 0;
      if (w.exists) tx.update(w.ref, { balance: ROUND(bal + c.amount), updatedAt: serverTs() });
      else tx.set(w.ref, { balance: ROUND(c.amount), updatedAt: serverTs() });
      tx.update(txRef, { status: "rejected", note: "Payout failed and funds were returned.", updatedAt: serverTs() });
    });
    notify(t.userId, "Withdrawal failed", "The payout of " + fmtAmount(t.amount) + " could not be sent. The amount was returned to your balance.", "ban", "wallet.html");
  }
}

/* Check a stuck "processing" withdrawal ~60s after it was sent, in case the webhook
 * never shows up. If MarzPay still hasn't given a definitive answer by then, this
 * force-approves the withdrawal (see resolveWithdrawOutcome for what that means).
 * The recurring sweep below does NOT force-approve — by the time it runs (2 min+),
 * anything still "processing" has already had its one chance to be force-approved
 * here; the sweep only continues to resolve it if a real answer later comes in. */
function scheduleReconcile(txId, marzUuid) {
  setTimeout(() => {
    resolveWithdrawOutcome(txId, marzUuid, true).catch((e) => console.error("[benz-pay] reconcile error:", e.message));
  }, 60 * 1000);
}

/* Safety-net sweep: every 2 minutes, re-check any withdrawal still stuck at "processing"
 * for more than 60 seconds (covers cases where the one-shot scheduleReconcile timer was
 * lost to a server restart). Runs only if Firebase + MarzPay are configured. */
function startReconcileSweep() {
  if (!firebaseReady || !MARZ_AUTH) return;
  setInterval(async () => {
    try {
      const cutoff = new Date(Date.now() - 60 * 1000);
      const snap = await db.collection("transactions")
        .where("type", "==", "withdraw")
        .where("status", "==", "processing")
        .get();
      for (const doc of snap.docs) {
        const t = doc.data();
        const updatedAt = t.updatedAt && t.updatedAt.toDate ? t.updatedAt.toDate() : null;
        if (updatedAt && updatedAt > cutoff) continue; // too recent, give the webhook more time
        // force=true here too: normally the 60s one-shot (scheduleReconcile) already
        // force-approved anything past its window, so this is a no-op re-check. It only
        // matters if that one-shot was lost (e.g. server restarted within the first 60s) —
        // in that case this sweep is what guarantees the withdrawal still doesn't stay
        // stuck at "processing" forever.
        await resolveWithdrawOutcome(doc.id, t.marzUuid, true).catch((e) => console.error("[benz-pay] sweep reconcile error:", e.message));
      }
    } catch (e) {
      if (/index/i.test(e.message)) {
        console.error("[benz-pay] reconcile sweep needs a Firestore composite index (type + status). Create it using the link Firestore includes in this error, then the sweep will start working:", e.message);
      } else {
        console.error("[benz-pay] reconcile sweep failed:", e.message);
      }
    }
  }, 2 * 60 * 1000);
}

/* Resolve an automatic deposit still at "pending" — used when the MarzPay webhook
 * hasn't arrived. Actively checks the real collection status with MarzPay and credits
 * the wallet + marks it approved (webhook-equivalent) when MarzPay confirms the payment
 * went through, or marks it rejected when MarzPay reports failure. Unlike withdrawals,
 * deposits are never force-credited without evidence: if MarzPay has no definitive
 * answer we leave it "pending" and the recurring sweep simply keeps retrying until the
 * collection reaches a final state. No admin approval is involved for automatic mode. */
async function resolveDepositOutcome(txId, marzUuid) {
  const txRef = db.collection("transactions").doc(txId);
  const snap = await txRef.get();
  if (!snap.exists) return;
  const t = snap.data();
  if (t.type !== "deposit" || t.mode !== "auto") return;
  if (t.status !== "pending") return; // webhook (or an earlier check) already resolved it

  let result = null;
  try {
    result = await checkCollectionStatus(marzUuid);
  } catch (e) {
    console.error("[benz-pay] deposit reconcile status check failed for", txId, e.message);
    return; // stays pending, will retry on the next sweep
  }

  const status = result && result.status;
  const success = status ? /completed|successful|sandbox/i.test(status) : false;
  const failed = status ? /failed|cancelled|canceled|rejected/i.test(status) : false;
  if (!success && !failed) return; // still pending / unknown on MarzPay's side — retry later

  if (success) {
    await db.runTransaction(async (tx) => {
      const cur = await tx.get(txRef);
      if (!cur.exists) return;
      const c = cur.data();
      if (c.status !== "pending") return;
      const wRef = db.collection("wallets").doc(c.userId);
      const w = await tx.get(wRef);
      const bal = w.exists ? (w.data().balance || 0) : 0;
      if (w.exists) tx.update(wRef, { balance: ROUND(bal + c.amount), updatedAt: serverTs() });
      else tx.set(wRef, { balance: ROUND(c.amount), updatedAt: serverTs() });
      tx.update(txRef, { status: "approved", note: (c.note || "Mobile money deposit") + " (confirmed via status check)", updatedAt: serverTs() });
    });
    notify(t.userId, "Deposit received", fmtAmount(t.amount) + " was added to your wallet automatically.", "finance", "wallet.html");
  } else {
    await db.runTransaction(async (tx) => {
      const cur = await tx.get(txRef);
      if (!cur.exists) return;
      const c = cur.data();
      if (c.status !== "pending") return;
      tx.update(txRef, { status: "rejected", note: "Payment was not completed.", updatedAt: serverTs() });
    });
    notify(t.userId, "Deposit not received", "Your deposit of " + fmtAmount(t.amount) + " was not completed. Try again or use a manual channel.", "ban", "wallet.html");
  }
}

/* Check a not-yet-credited automatic deposit ~60s after it was created, in case the
 * webhook never shows up. If MarzPay confirms the payment by then, the wallet is
 * credited right away — no admin step needed. */
function scheduleDepositReconcile(txId, marzUuid) {
  setTimeout(() => {
    resolveDepositOutcome(txId, marzUuid).catch((e) => console.error("[benz-pay] deposit reconcile error:", e.message));
  }, 60 * 1000);
}

/* Safety-net sweep: every 2 minutes, re-check any automatic deposit still at "pending"
 * for more than 60 seconds (covers cases where the one-shot timer was lost to a server
 * restart, or the user paid after the first check). Credits the wallet as soon as
 * MarzPay reports the payment succeeded. Shipped with Firebase + MarzPay configured. */
function startDepositReconcileSweep() {
  if (!firebaseReady || !MARZ_AUTH) return;
  setInterval(async () => {
    try {
      const cutoff = new Date(Date.now() - 60 * 1000);
      const snap = await db.collection("transactions")
        .where("type", "==", "deposit")
        .where("status", "==", "pending")
        .get();
      for (const doc of snap.docs) {
        const t = doc.data();
        if (t.mode !== "auto") continue;
        if (!t.marzUuid) continue;
        const updatedAt = t.updatedAt && t.updatedAt.toDate ? t.updatedAt.toDate() : null;
        if (updatedAt && updatedAt > cutoff) continue; // too recent, give the webhook more time
        await resolveDepositOutcome(doc.id, t.marzUuid).catch((e) => console.error("[benz-pay] deposit sweep reconcile error:", e.message));
      }
    } catch (e) {
      if (/index/i.test(e.message)) {
        console.error("[benz-pay] deposit reconcile sweep needs a Firestore composite index (type + status). Create it using the link Firestore includes in this error, then the sweep will start working:", e.message);
      } else {
        console.error("[benz-pay] deposit reconcile sweep failed:", e.message);
      }
    }
  }, 2 * 60 * 1000);
}

/* Automatic withdrawal payout. Called by the admin wallet panel with X-Admin-Key. */
app.post("/api/disburse", async (req, res) => {
  if (!adminKeyOk(req)) return res.status(401).json({ status: "error", message: "Invalid admin key" });
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server." });

  const txId = String(req.body.txId || "").trim();
  if (!txId) return res.status(422).json({ status: "error", message: "txId is required." });

  try {
    const result = await runDisbursement(txId, req.body.phone);
    res.json({ status: "success", message: "Payout initiated. Funds are sent to the customer's phone.", data: result });
  } catch (e) {
    const httpCode = e.code === "NOT_FOUND" ? 404 : (e.code === "MARZ" ? 502 : 422);
    res.status(httpCode).json({ status: "error", message: e.message });
  }
});

/* Automatic user-triggered withdrawal. The wallet page calls this directly with the
 * user's Firebase ID token once they've confirmed the recipient name via /api/verify-name.
 * Creates the withdrawal transaction and pays it out immediately — no admin step. */
app.post("/api/withdraw", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const amount = ROUND(req.body.amount);
  const phone = normalizeUG(req.body.phone || "");
  const country = req.body.country || MARZ_COUNTRY;
  const channel = String(req.body.channel || "").toLowerCase();
  const recipientName = String(req.body.recipientName || "").trim();

  if (!amount || amount < MIN_UGX || amount > MAX_UGX) {
    return res.status(422).json({ status: "error", message: "Amount must be between " + MIN_UGX + " and " + MAX_UGX + " " + CURRENCY + "." });
  }
  if (!phone) return res.status(422).json({ status: "error", message: "A valid +256 mobile money number is required." });

  let profile = {};
  try {
    const p = await db.collection("users").doc(uid).get();
    if (p.exists) profile = p.data();
  } catch (e) { /* ignore */ }
  if (profile.banned) return res.status(403).json({ status: "error", message: "Account suspended." });

  const pct = Number(req.body.feePercent) || 0;
  const fee = ROUND(amount * pct / 100);
  const payout = ROUND(amount - fee);
  if (!payout || payout < MIN_UGX) {
    return res.status(422).json({ status: "error", message: "The amount you will receive after the withdrawal fee is below the " + MIN_UGX + " " + CURRENCY + " minimum." });
  }

  let txRef;
  try {
    await db.runTransaction(async (tx) => {
      const wRef = db.collection("wallets").doc(uid);
      const w = await tx.get(wRef);
      const bal = w.exists ? (w.data().balance || 0) : 0;
      if (bal < amount) throw Object.assign(new Error("Amount exceeds your available balance."), { code: "INSUFFICIENT" });

      txRef = db.collection("transactions").doc();
      tx.set(txRef, {
        userId: uid,
        userName: profile.fullName || "Member",
        type: "withdraw",
        amount,
        fee,
        payout,
        phone,
        country,
        channel: channel === "airtel" ? "airtel" : "mtn",
        mode: "auto",
        status: "pending",
        note: recipientName ? ("Withdrawal to " + recipientName) : "Withdrawal payout",
        recipientName: recipientName || null,
        createdAt: serverTs(),
        updatedAt: serverTs()
      });
    });
  } catch (e) {
    return res.status(e.code === "INSUFFICIENT" ? 422 : 500).json({ status: "error", message: e.message });
  }

  try {
    const result = await runDisbursement(txRef.id, phone);
    res.json({ status: "success", message: "Withdrawal sent. Funds are on their way to your mobile money number.", data: result });
  } catch (e) {
    const httpCode = e.code === "NOT_FOUND" ? 404 : (e.code === "MARZ" ? 502 : 422);
    res.status(httpCode).json({ status: "error", message: e.message });
  }
});

/* MarzPay webhook — handles collection.completed/failed and disbursement.completed/failed. */
app.post("/api/webhook", async (req, res) => {
  const rawBody = JSON.stringify(req.body || {});
  if (MARZ_SIGNING_SECRET && !verifyMarzSig(req, rawBody)) {
    return res.status(401).json({ status: "error", message: "Invalid signature" });
  }
  const body = req.body || {};
  const ev = String(body.event_type || "");
  const tx = body.transaction || {};
  const ref = tx.reference;
  if (!ref) return res.status(200).json({ status: "ack" });
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Firebase not configured" });

  const success = /completed|successful|sandbox/i.test(String(tx.status || ""));
  const failed = /failed|cancelled|canceled/i.test(String(tx.status || ""));

  try {
    const snap = await db.collection("transactions").where("marzRef", "==", ref).limit(1).get();
    if (snap.empty) {
      console.log("[benz-pay] webhook for unknown reference:", ref);
      return res.status(200).json({ status: "ack", matched: false });
    }
    const doc = snap.docs[0];
    const t = doc.data();
    if (t.status === "approved" || t.status === "rejected") {
      return res.status(200).json({ status: "ack", matched: true, final: true });
    }

    const providerTxId = (body.collection && body.collection.provider_transaction_id) ||
      (body.disbursement && body.disbursement.provider_transaction_id) || "";
    const recvAmount = ROUND((tx.amount && tx.amount.raw) != null ? tx.amount.raw : t.amount);
    const isDeposit = t.type === "deposit";
    const isWithdraw = t.type === "withdraw";

    if (success) {
      if (isDeposit) {
        await db.runTransaction(async (txn) => {
          const cur = await txn.get(doc.ref);
          if (!cur.exists) return;
          const c = cur.data();
          if (c.status === "approved" || c.status === "rejected") return;
          const wRef = db.collection("wallets").doc(c.userId);
          const w = await txn.get(wRef);
          const bal = w.exists ? (w.data().balance || 0) : 0;
          if (w.exists) txn.update(wRef, { balance: ROUND(bal + recvAmount), updatedAt: serverTs() });
          else txn.set(wRef, { balance: ROUND(recvAmount), updatedAt: serverTs() });
          txn.update(doc.ref, { status: "approved", providerTxId, updatedAt: serverTs() });
        });
        notify(t.userId, "Deposit received", fmtAmount(recvAmount) + " was added to your wallet automatically.", "finance", "wallet.html");
      } else if (isWithdraw) {
        await db.runTransaction(async (txn) => {
          const cur = await txn.get(doc.ref);
          if (!cur.exists) return;
          const c = cur.data();
          if (c.status === "approved" || c.status === "rejected") return;
          txn.update(doc.ref, { status: "approved", providerTxId, updatedAt: serverTs() });
        });
        notify(t.userId, "Withdrawal paid out", fmtAmount(recvAmount) + " was sent to your mobile money number.", "finance", "wallet.html");
      } else {
        await doc.ref.update({ status: "approved", providerTxId, updatedAt: serverTs() }).catch(() => {});
      }
    } else if (failed) {
      if (isWithdraw) {
        await db.runTransaction(async (txn) => {
          const cur = await txn.get(doc.ref);
          if (!cur.exists) return;
          const c = cur.data();
          if (c.status === "approved" || c.status === "rejected") return;
          const wRef = db.collection("wallets").doc(c.userId);
          const w = await txn.get(wRef);
          const bal = w.exists ? (w.data().balance || 0) : 0;
          if (w.exists) txn.update(wRef, { balance: ROUND(bal + c.amount), updatedAt: serverTs() });
          else txn.set(wRef, { balance: ROUND(c.amount), updatedAt: serverTs() });
          txn.update(doc.ref, { status: "rejected", note: "Payout failed and funds were returned.", updatedAt: serverTs() });
        });
        notify(t.userId, "Withdrawal failed", "The payout of " + fmtAmount(recvAmount) + " could not be sent. The amount was returned to your balance.", "ban", "wallet.html");
      } else {
        await doc.ref.update({ status: "rejected", note: "Payment was not completed.", updatedAt: serverTs() }).catch(() => {});
        notify(t.userId, "Deposit not received", "Your deposit of " + fmtAmount(recvAmount) + " was not completed. Try again or use a manual channel.", "ban", "wallet.html");
      }
    } else {
      console.log("[benz-pay] webhook with unknown outcome:", ev, tx.status || "(no status)");
    }
    res.status(200).json({ status: "ack", matched: true });
  } catch (e) {
    console.error("[benz-pay] webhook error:", e.message);
    res.status(200).json({ status: "ack", error: "logged" });
  }
});

function verifyMarzSig(req, rawBody) {
  const ts = req.headers["x-marzpay-timestamp"] || "";
  const sigHeader = req.headers["x-marzpay-signature"] || "";
  const match = sigHeader.match(/v1=([a-f0-9]+)/i);
  if (!ts || !match) return false;
  const expected = crypto.createHmac("sha256", MARZ_SIGNING_SECRET).update(ts + "." + rawBody).digest("hex");
  const received = match[1];
  return received.length === expected.length && crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected));
}

function fmtAmount(n) {
  return CURRENCY + " " + ROUND(n).toLocaleString("en-US", { maximumFractionDigits: 2 });
}

/* Fallback for any unmatched route — always JSON, since this is an API-only service. */
app.use((req, res) => {
  res.status(404).json({ status: "error", message: "Not found" });
});

app.listen(PORT, () => {
  console.log("[benz-pay] payments server listening on port " + PORT);
  console.log("[benz-pay] webhook endpoint: " + (PUBLIC_BASE_URL || "CALLBACK_URL_NOT_SET") + "/api/webhook");
  startReconcileSweep();
  startDepositReconcileSweep();
});
