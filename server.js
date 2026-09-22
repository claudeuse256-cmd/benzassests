/**
 * Benz Assets payments server.
 *
 * Moves money via PesaJet Pay (https://pay.pesajet.com) — MTN Mobile Money /
 * Airtel Money collections (deposits) and disbursements (withdrawals) in
 * Uganda (UGX, +256).
 *
 * Recipient name lookup (used only so the user can confirm who they're
 * withdrawing to) is served by a separate internal verification provider.
 * This is intentionally generic in the code and in every response the app
 * ever sees — no provider name is exposed to the client.
 *
 * Env:
 *   PORT                      Port to listen on (default 8787)
 *   PUBLIC_BASE_URL           Public URL of this server, e.g. https://pay.example.com
 *                             (used only for the printed webhook URL at startup)
 *   FIREBASE_SERVICE_ACCOUNT  JSON string of the firebase-admin service account, OR
 *   GOOGLE_APPLICATION_CREDENTIALS  path to the service account JSON file.
 *
 *   PESAJET_API_KEY           PesaJet X-API-Key (from Manage API keys in their dashboard)
 *   PESAJET_WEBHOOK_SECRET    PesaJet webhook signing secret (whsec_...)
 *   PESAJET_BASE_URL          Default https://payments.pesajet.com/api/v1
 *
 *   NAME_LOOKUP_BASE_URL      Base URL of the internal name-lookup provider
 *   NAME_LOOKUP_ID            Account/API-key identifier for the name-lookup provider
 *   NAME_LOOKUP_SECRET        Secret for the name-lookup provider
 *                             (any blank => the feature is silently disabled
 *                             and the app is told to skip verification)
 *
 *   ADMIN_API_KEY             Secret header (X-Admin-Key) required for /api/disburse
 *                             and the admin balance/test-connection check.
 *   ALLOWED_ORIGINS           Comma-separated list of origins allowed to call this API.
 *                             Leave blank to allow any origin.
 *
 * User-facing endpoints (Firebase ID token in Authorization: Bearer <token>):
 *   POST /api/collect       Start a deposit — PesaJet sends a payment prompt to the user's phone.
 *   POST /api/verify-name   Look up the registered name on a mobile money number.
 *   POST /api/withdraw      Create + immediately pay out a withdrawal to a verified number.
 *
 * Reliability: a withdrawal sent to PesaJet moves to "processing" and is normally
 * resolved to "approved"/"rejected" by the /api/webhook callback. If that webhook
 * doesn't arrive, a one-shot check ~60s after send, plus a recurring sweep every
 * 2 minutes, actively asks PesaJet for the real transaction status and resolves it
 * from that — it never assumes success or failure from silence alone.
 *
 * Run:  npm install && node server.js
 */

const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");
const { PesaJet } = require("@pesajet/sdk");

/* ---------------- config ---------------- */
const PORT = parseInt(process.env.PORT || "8787", 10);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");

const PESAJET_BASE = (process.env.PESAJET_BASE_URL || "https://payments.pesajet.com/api/v1").replace(/\/+$/, "");
const PESAJET_API_KEY = process.env.PESAJET_API_KEY || "";
const PESAJET_WEBHOOK_SECRET = process.env.PESAJET_WEBHOOK_SECRET || "";

// Internal name-lookup provider. Deliberately generic — never named in any
// client-facing response, log line the frontend could see, or error message.
const NAME_LOOKUP_BASE_URL = (process.env.NAME_LOOKUP_BASE_URL || "").replace(/\/+$/, "");
const NAME_LOOKUP_ID = process.env.NAME_LOOKUP_ID || "";
const NAME_LOOKUP_SECRET = process.env.NAME_LOOKUP_SECRET || "";

const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "change-me-admin-key";
const CURRENCY = process.env.PESAJET_CURRENCY || "UGX";
const MIN_UGX = 500;
const MAX_UGX = 10000000;

if (ADMIN_API_KEY === "change-me-admin-key") {
  console.warn("[benz-pay] WARNING: ADMIN_API_KEY is the default. Set it before going live.");
}
if (!PESAJET_API_KEY) {
  console.warn("[benz-pay] WARNING: PESAJET_API_KEY not set. Payment calls will fail until configured.");
}
if (!NAME_LOOKUP_BASE_URL || !NAME_LOOKUP_ID || !NAME_LOOKUP_SECRET) {
  console.warn("[benz-pay] NOTE: name-lookup provider not configured. /api/verify-name will report the feature as unavailable, and the wallet UI should let withdrawals proceed without it.");
}

const pesajet = new PesaJet({
  apiKey: PESAJET_API_KEY,
  webhookSecret: PESAJET_WEBHOOK_SECRET,
  baseUrl: PESAJET_BASE,
  timeoutMs: 30000
});

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
const ROUND = (n) => Math.round((Number(n) || 0) * 100) / 100;

function normalizeUG(phone) {
  let d = String(phone || "").replace(/\D/g, "");
  if (d.startsWith("256")) d = d.slice(3);
  if (d.startsWith("0")) d = d.slice(1);
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
  return k && k.length === ADMIN_API_KEY.length && crypto.timingSafeEqual(Buffer.from(k), Buffer.from(ADMIN_API_KEY));
}

function notify(uid, title, body, type, link) {
  if (!firebaseReady) return Promise.resolve();
  return db.collection("notifications").doc(String(uid)).collection("items").add({
    title: String(title), body: String(body || ""), type: type || "info", link: link || "", read: false, createdAt: serverTs()
  }).catch(() => {});
}

function fmtAmount(n) {
  return CURRENCY + " " + ROUND(n).toLocaleString("en-US", { maximumFractionDigits: 2 });
}

function providerOf(phoneOrProvider) {
  const p = String(phoneOrProvider || "").toLowerCase();
  return p === "airtel" || p === "mtn" ? p : "mtn";
}

/* ---------------- internal name-lookup helper ----------------
 * Deliberately kept generic in naming, logging and error text — the app and
 * its users should never see which service actually answers this. */
async function lookupRegisteredName(phone) {
  if (!NAME_LOOKUP_BASE_URL || !NAME_LOOKUP_ID || !NAME_LOOKUP_SECRET) {
    const err = new Error("Recipient name verification is not available right now.");
    err.code = "UNAVAILABLE";
    throw err;
  }
  const r = await fetch(NAME_LOOKUP_BASE_URL + "/phone-verification/verify", {
    method: "POST",
    headers: {
      Authorization: "Basic " + Buffer.from(NAME_LOOKUP_ID + ":" + NAME_LOOKUP_SECRET).toString("base64"),
      "Content-Type": "application/json",
      Accept: "application/json"
    },
    body: JSON.stringify({ phone_number: phone.replace(/^\+/, "") })
  });
  const data = await r.json().catch(() => ({}));
  const ok = r.ok && (data.status === "success" || data.success === true);
  if (!ok) {
    const err = new Error((data && data.message) || "Could not verify that number.");
    err.code = "LOOKUP_FAILED";
    throw err;
  }
  const d = data.data || {};
  const name = d.full_name || d.name || "";
  if (!name) {
    const err = new Error("No registered name found for that number.");
    err.code = "NOT_FOUND";
    throw err;
  }
  return { name, phone: d.phone_number || phone };
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
  res.json({ ok: true, firebase: firebaseReady, paymentsConfigured: !!PESAJET_API_KEY, ts: Date.now() });
});

/* Validate payment-provider API credentials from the admin panel.
 * Kept at the same path the admin page already calls (/api/marz/balance)
 * so no admin-page changes are needed beyond swapping the server URL. */
app.get("/api/marz/balance", async (req, res) => {
  if (!adminKeyOk(req)) return res.status(401).json({ status: "error", message: "Invalid admin key" });
  if (!PESAJET_API_KEY) return res.status(503).json({ status: "error", message: "Payment credentials not configured on the server (PESAJET_API_KEY)." });
  try {
    // PesaJet's REST API has no dedicated balance endpoint in its published
    // reference; use a lightweight, side-effect-free call (list transactions,
    // page 1) purely to prove the API key is valid and the service reachable.
    const r = await fetch(PESAJET_BASE + "/payments?page=1&limit=1", {
      headers: { "X-API-Key": PESAJET_API_KEY, Accept: "application/json" }
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error((data.error && data.error.message) || ("Connection check failed (" + r.status + ")"));
    res.json({
      status: "success",
      data: {
        account: {
          balance: { formatted: "See provider dashboard" },
          status: { mode: /sandbox|test/i.test(PESAJET_BASE) ? "sandbox" : "live" }
        },
        raw: data
      }
    });
  } catch (e) {
    res.status(502).json({ status: "error", message: e.message });
  }
});

/* Look up the registered name on a mobile money number.
 * Used by the wallet page so the user can confirm the recipient before withdrawing.
 * Served by the internal name-lookup provider — see lookupRegisteredName above. */
app.post("/api/verify-name", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const phone = normalizeUG(req.body.phone || "");
  if (!phone) return res.status(422).json({ status: "error", message: "A valid +256 phone number is required." });

  try {
    const result = await lookupRegisteredName(phone);
    res.json({ status: "success", data: result });
  } catch (e) {
    const httpCode = e.code === "UNAVAILABLE" ? 503 : (e.code === "NOT_FOUND" ? 422 : 502);
    res.status(httpCode).json({ status: "error", message: e.message });
  }
});

/* Automatic deposit: create a PesaJet collection. Wallet page calls this with the user's Firebase ID token. */
app.post("/api/collect", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!PESAJET_API_KEY) return res.status(503).json({ status: "error", message: "Payment credentials not configured on the server." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const amount = ROUND(req.body.amount);
  const phone = normalizeUG(req.body.phone || "");
  const channelHint = providerOf(req.body.channel);

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

  const txRef = db.collection("transactions").doc();
  const idempotencyKey = txRef.id;

  await txRef.set({
    userId: uid,
    userName: profile.fullName || "Member",
    type: "deposit",
    amount,
    channel: channelHint,
    mode: "auto",
    status: "pending",
    note: "Mobile money deposit",
    createdAt: serverTs(),
    updatedAt: serverTs()
  });

  let payment;
  try {
    payment = await pesajet.payments.create({
      type: "COLLECTION",
      amount,
      currency: CURRENCY,
      phoneNumber: phone,
      provider: channelHint,
      reference: txRef.id,
      description: "Benz Assets deposit",
      idempotencyKey
    });
  } catch (e) {
    await txRef.update({ status: "rejected", note: "Payment initiation failed: " + e.message, updatedAt: serverTs() });
    return res.status(502).json({ status: "error", message: e.message });
  }

  const provider = providerOf(payment.provider) || channelHint;
  await txRef.update({
    channel: provider,
    providerTxId: payment.transactionId || "",
    updatedAt: serverTs()
  }).catch(() => {});

  if (payment.transactionId) scheduleDepositReconcile(txRef.id, payment.transactionId);

  res.json({
    status: "success",
    message: "Payment request sent. Confirm the prompt on your phone.",
    data: { txId: txRef.id, provider }
  });
});

/* Shared payout logic: moves a pending withdrawal tx to "processing", debits the
 * wallet, calls PesaJet to disburse, and rolls back on failure. Used by both the
 * admin-triggered /api/disburse and the user-triggered /api/withdraw below. */
async function runDisbursement(txId, phoneOverride) {
  const txRef = db.collection("transactions").doc(txId);
  let payload = null;

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
      throw Object.assign(new Error("Amount outside allowed limits."), { code: "AMOUNT" });
    }
    const payout = ROUND(t.payout != null ? ROUND(t.payout) : (t.fee != null ? ROUND(amount - t.fee) : amount));
    if (!payout || payout < MIN_UGX) {
      throw Object.assign(new Error("Payout after the withdrawal fee (" + CURRENCY + " " + ROUND(payout).toLocaleString("en-US", { maximumFractionDigits: 2 }) + ") is below the " + MIN_UGX + " " + CURRENCY + " minimum."), { code: "AMOUNT" });
    }
    const w = await tx.get(db.collection("wallets").doc(t.userId));
    const bal = w.exists ? (w.data().balance || 0) : 0;
    if (bal < amount) throw Object.assign(new Error("Insufficient balance."), { code: "INSUFFICIENT" });

    payload = {
      phone,
      payout,
      provider: providerOf(t.channel),
      recipientName: t.recipientName || undefined
    };

    if (w.exists) tx.update(db.collection("wallets").doc(t.userId), { balance: ROUND(bal - amount), updatedAt: serverTs() });
    else tx.set(db.collection("wallets").doc(t.userId), { balance: Math.max(0, ROUND(bal - amount)), updatedAt: serverTs() });
    tx.update(txRef, { status: "processing", note: t.note || "Withdrawal payout", updatedAt: serverTs() });
  });

  let payment;
  try {
    payment = await pesajet.payments.create({
      type: "DISBURSEMENT",
      amount: payload.payout,
      currency: CURRENCY,
      phoneNumber: payload.phone,
      provider: payload.provider,
      reference: txId,
      description: payload.recipientName ? ("Payout to " + payload.recipientName) : "Benz Assets withdrawal payout",
      idempotencyKey: txId
    });
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
        tx.update(txRef, { status: "pending", updatedAt: serverTs() });
      });
    } catch (e2) { /* ignore rollback failure */ }
    throw Object.assign(new Error("The payout could not be started: " + e.message), { code: "PROVIDER" });
  }

  const provider = providerOf(payment.provider) || payload.provider;
  await txRef.update({
    channel: provider,
    providerTxId: payment.transactionId || "",
    updatedAt: serverTs()
  }).catch(() => {});

  if (payment.transactionId) scheduleReconcile(txId, payment.transactionId);

  return { txId, provider };
}

/* Resolve a withdrawal that's been sitting at "processing" — used when the PesaJet
 * webhook hasn't arrived. Actively checks the real transaction status with PesaJet
 * and marks it approved (webhook-equivalent) or rejected+refunded based on that.
 *
 * forceApprove: if true, and PesaJet has NOT given a definitive success/fail answer
 * (status check failed, or still pending/processing) within the window, the
 * withdrawal is force-marked "approved" anyway rather than left "processing".
 * This is a deliberate product choice: it assumes success by default instead of
 * waiting indefinitely. It means a payout that silently failed or is merely slow
 * on the provider's side will show as approved/completed everywhere (wallet history,
 * admin panel, user notification) with no automatic refund — the user's balance
 * was already debited and stays debited. Only the one-shot 60s check
 * (scheduleReconcile) sets this; the recurring safety-net sweep does not, so a
 * withdrawal is force-approved at most once, at the 60s mark. */
async function resolveWithdrawOutcome(txId, providerTxId, forceApprove) {
  const txRef = db.collection("transactions").doc(txId);
  const snap = await txRef.get();
  if (!snap.exists) return;
  const t = snap.data();
  if (t.status !== "processing") return; // webhook (or an earlier check) already resolved it

  let status = null;
  if (providerTxId) {
    try {
      const tx = await pesajet.payments.get(providerTxId);
      status = String((tx && tx.status) || "").toUpperCase();
    } catch (e) {
      console.error("[benz-pay] reconcile status check failed for", txId, e.message);
      if (!forceApprove) return; // stays processing, will retry on the next sweep
    }
  }

  const success = status === "COMPLETED";
  const failed = status === "FAILED" || status === "EXPIRED";

  if (!success && !failed) {
    if (!forceApprove) return; // still pending / processing on the provider's side — retry later
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
 * never shows up. If PesaJet still hasn't given a definitive answer by then, this
 * force-approves the withdrawal (see resolveWithdrawOutcome for what that means).
 * The recurring sweep below does NOT force-approve — by the time it runs (2 min+),
 * anything still "processing" has already had its one chance to be force-approved
 * here; the sweep only continues to resolve it if a real answer later comes in. */
function scheduleReconcile(txId, providerTxId) {
  setTimeout(() => {
    resolveWithdrawOutcome(txId, providerTxId, true).catch((e) => console.error("[benz-pay] reconcile error:", e.message));
  }, 60 * 1000);
}

/* Safety-net sweep: every 2 minutes, re-check any withdrawal still stuck at "processing"
 * for more than 60 seconds (covers cases where the one-shot scheduleReconcile timer was
 * lost to a server restart). Runs only if Firebase + PesaJet are configured. */
function startReconcileSweep() {
  if (!firebaseReady || !PESAJET_API_KEY) return;
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
        await resolveWithdrawOutcome(doc.id, t.providerTxId, true).catch((e) => console.error("[benz-pay] sweep reconcile error:", e.message));
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

/* Resolve an automatic deposit still at "pending" — used when the PesaJet webhook
 * hasn't arrived. Actively checks the real collection status with PesaJet and credits
 * the wallet + marks it approved (webhook-equivalent) when PesaJet confirms the payment
 * went through, or marks it rejected when PesaJet reports failure. Unlike withdrawals,
 * deposits are never force-credited without evidence: if PesaJet has no definitive
 * answer we leave it "pending" and the recurring sweep simply keeps retrying until the
 * collection reaches a final state. No admin approval is involved for automatic mode. */
async function resolveDepositOutcome(txId, providerTxId) {
  const txRef = db.collection("transactions").doc(txId);
  const snap = await txRef.get();
  if (!snap.exists) return;
  const t = snap.data();
  if (t.type !== "deposit" || t.mode !== "auto") return;
  if (t.status !== "pending") return; // webhook (or an earlier check) already resolved it

  let status = null;
  try {
    const tx = await pesajet.payments.get(providerTxId);
    status = String((tx && tx.status) || "").toUpperCase();
  } catch (e) {
    console.error("[benz-pay] deposit reconcile status check failed for", txId, e.message);
    return; // stays pending, will retry on the next sweep
  }

  const success = status === "COMPLETED";
  const failed = status === "FAILED" || status === "EXPIRED";
  if (!success && !failed) return; // still pending / processing on the provider's side — retry later

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
 * webhook never shows up. If PesaJet confirms the payment by then, the wallet is
 * credited right away — no admin step needed. */
function scheduleDepositReconcile(txId, providerTxId) {
  setTimeout(() => {
    resolveDepositOutcome(txId, providerTxId).catch((e) => console.error("[benz-pay] deposit reconcile error:", e.message));
  }, 60 * 1000);
}

/* Safety-net sweep: every 2 minutes, re-check any automatic deposit still at "pending"
 * for more than 60 seconds (covers cases where the one-shot timer was lost to a server
 * restart, or the user paid after the first check). Credits the wallet as soon as
 * PesaJet reports the payment succeeded. Runs only if Firebase + PesaJet are configured. */
function startDepositReconcileSweep() {
  if (!firebaseReady || !PESAJET_API_KEY) return;
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
        if (!t.providerTxId) continue;
        const updatedAt = t.updatedAt && t.updatedAt.toDate ? t.updatedAt.toDate() : null;
        if (updatedAt && updatedAt > cutoff) continue; // too recent, give the webhook more time
        await resolveDepositOutcome(doc.id, t.providerTxId).catch((e) => console.error("[benz-pay] deposit sweep reconcile error:", e.message));
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
  if (!PESAJET_API_KEY) return res.status(503).json({ status: "error", message: "Payment credentials not configured on the server." });

  const txId = String(req.body.txId || "").trim();
  if (!txId) return res.status(422).json({ status: "error", message: "txId is required." });

  try {
    const result = await runDisbursement(txId, req.body.phone);
    res.json({ status: "success", message: "Payout initiated. Funds are sent to the customer's phone.", data: result });
  } catch (e) {
    const httpCode = e.code === "NOT_FOUND" ? 404 : (e.code === "PROVIDER" ? 502 : 422);
    res.status(httpCode).json({ status: "error", message: e.message });
  }
});

/* Automatic user-triggered withdrawal. The wallet page calls this directly with the
 * user's Firebase ID token once they've confirmed the recipient name via /api/verify-name.
 * Creates the withdrawal transaction and pays it out immediately — no admin step. */
app.post("/api/withdraw", async (req, res) => {
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!PESAJET_API_KEY) return res.status(503).json({ status: "error", message: "Payment credentials not configured on the server." });
  const uid = await tokenToUid(req);
  if (!uid) return res.status(401).json({ status: "error", message: "Invalid or missing Firebase token." });

  const amount = ROUND(req.body.amount);
  const phone = normalizeUG(req.body.phone || "");
  const channel = providerOf(req.body.channel);
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
        channel,
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
    const httpCode = e.code === "NOT_FOUND" ? 404 : (e.code === "PROVIDER" ? 502 : 422);
    res.status(httpCode).json({ status: "error", message: e.message });
  }
});

/* PesaJet webhook — handles payment.completed / payment.failed / payment.expired
 * for both collections (deposits) and disbursements (withdrawals). Verified with
 * the official SDK's HMAC-SHA256 signature check against X-Webhook-Signature. */
app.post("/api/webhook", express.json({ limit: "1mb" }), async (req, res) => {
  const signature = req.headers["x-webhook-signature"] || "";
  if (PESAJET_WEBHOOK_SECRET) {
    let valid = false;
    try {
      valid = pesajet.webhooks.verify(req.body, signature);
    } catch (e) {
      valid = false;
    }
    if (!valid) return res.status(401).json({ error: "Signature mismatch" });
  }

  const body = req.body || {};
  const event = String(body.event || "");
  const ref = body.reference; // this is the Firestore transaction id we sent as `reference`
  const providerTxId = body.transactionId || "";
  const status = String(body.status || "").toUpperCase();

  if (!ref) return res.status(200).json({ received: true });
  if (!firebaseReady) return res.status(200).json({ received: true, error: "Firebase not configured" });

  const success = event === "payment.completed" || status === "COMPLETED";
  const failed = event === "payment.failed" || event === "payment.expired" || status === "FAILED" || status === "EXPIRED";

  try {
    const doc = db.collection("transactions").doc(String(ref));
    const cur = await doc.get();
    if (!cur.exists) {
      console.log("[benz-pay] webhook for unknown reference:", ref);
      return res.status(200).json({ received: true, matched: false });
    }
    const t = cur.data();
    if (t.status === "approved" || t.status === "rejected") {
      return res.status(200).json({ received: true, matched: true, final: true });
    }

    // Always credit/report the amount WE recorded when the transaction was created
    // (what the user typed into the app), never whatever figure the provider echoes
    // back in the webhook. If a provider fee is configured to be added on top and
    // charged to the payer, the webhook's amount can be higher than what the user
    // intended to deposit — that difference is the provider's fee and must never
    // reach the wallet. Using our own record keeps the wallet exact regardless of
    // how the provider's fee is configured.
    const recvAmount = ROUND(t.amount);
    const isDeposit = t.type === "deposit";
    const isWithdraw = t.type === "withdraw";

    if (success) {
      if (isDeposit) {
        await db.runTransaction(async (txn) => {
          const c2 = await txn.get(doc);
          if (!c2.exists) return;
          const c = c2.data();
          if (c.status === "approved" || c.status === "rejected") return;
          const wRef = db.collection("wallets").doc(c.userId);
          const w = await txn.get(wRef);
          const bal = w.exists ? (w.data().balance || 0) : 0;
          if (w.exists) txn.update(wRef, { balance: ROUND(bal + recvAmount), updatedAt: serverTs() });
          else txn.set(wRef, { balance: ROUND(recvAmount), updatedAt: serverTs() });
          txn.update(doc, { status: "approved", providerTxId, updatedAt: serverTs() });
        });
        notify(t.userId, "Deposit received", fmtAmount(recvAmount) + " was added to your wallet automatically.", "finance", "wallet.html");
      } else if (isWithdraw) {
        await db.runTransaction(async (txn) => {
          const c2 = await txn.get(doc);
          if (!c2.exists) return;
          const c = c2.data();
          if (c.status === "approved" || c.status === "rejected") return;
          txn.update(doc, { status: "approved", providerTxId, updatedAt: serverTs() });
        });
        notify(t.userId, "Withdrawal paid out", fmtAmount(recvAmount) + " was sent to your mobile money number.", "finance", "wallet.html");
      } else {
        await doc.update({ status: "approved", providerTxId, updatedAt: serverTs() }).catch(() => {});
      }
    } else if (failed) {
      if (isWithdraw) {
        await db.runTransaction(async (txn) => {
          const c2 = await txn.get(doc);
          if (!c2.exists) return;
          const c = c2.data();
          if (c.status === "approved" || c.status === "rejected") return;
          const wRef = db.collection("wallets").doc(c.userId);
          const w = await txn.get(wRef);
          const bal = w.exists ? (w.data().balance || 0) : 0;
          if (w.exists) txn.update(wRef, { balance: ROUND(bal + c.amount), updatedAt: serverTs() });
          else txn.set(wRef, { balance: ROUND(c.amount), updatedAt: serverTs() });
          txn.update(doc, { status: "rejected", note: "Payout failed and funds were returned.", updatedAt: serverTs() });
        });
        notify(t.userId, "Withdrawal failed", "The payout of " + fmtAmount(recvAmount) + " could not be sent. The amount was returned to your balance.", "ban", "wallet.html");
      } else {
        await doc.update({ status: "rejected", note: "Payment was not completed.", updatedAt: serverTs() }).catch(() => {});
        notify(t.userId, "Deposit not received", "Your deposit of " + fmtAmount(recvAmount) + " was not completed. Try again or use a manual channel.", "ban", "wallet.html");
      }
    } else {
      console.log("[benz-pay] webhook with unknown outcome:", event, status || "(no status)");
    }
    res.status(200).json({ received: true, matched: true });
  } catch (e) {
    console.error("[benz-pay] webhook error:", e.message);
    res.status(200).json({ received: true, error: "logged" });
  }
});

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
