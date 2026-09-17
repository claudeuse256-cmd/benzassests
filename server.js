/* Benz Assets payments server.
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

/* ---------------- app ---------------- */
const app = express();
app.use(express.json({ limit: "1mb" }));

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
  await txRef.update({
    channel: provider === "airtel" ? "airtel" : "mtn",
    marzUuid: (marzData.data && marzData.data.transaction && marzData.data.transaction.uuid) || "",
    providerMode: mode || "",
    updatedAt: serverTs()
  }).catch(() => {});

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

/* Automatic withdrawal payout. Called by the admin wallet panel with X-Admin-Key. */
app.post("/api/disburse", async (req, res) => {
  if (!adminKeyOk(req)) return res.status(401).json({ status: "error", message: "Invalid admin key" });
  if (!firebaseReady) return res.status(500).json({ status: "error", message: "Server Firebase is not configured." });
  if (!MARZ_AUTH) return res.status(503).json({ status: "error", message: "MarzPay credentials not configured on the server." });

  const txId = String(req.body.txId || "").trim();
  if (!txId) return res.status(422).json({ status: "error", message: "txId is required." });

  const txRef = db.collection("transactions").doc(txId);

  let payload = null;
  let reference = UUID();

  try {
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(txRef);
      if (!snap.exists) throw Object.assign(new Error("Transaction not found."), { code: "NOT_FOUND" });
      const t = snap.data();
      if (t.type !== "withdraw") throw Object.assign(new Error("Transaction is not a withdrawal."), { code: "BAD_TYPE" });
      if (t.status !== "pending") throw Object.assign(new Error("Withdrawal already processed (current state: " + t.status + ")."), { code: "STATE" });
      const phone = normalizeUG(t.phone || req.body.phone || "");
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
  } catch (e) {
    return res.status(e.code === "NOT_FOUND" ? 404 : 422).json({ status: "error", message: e.message });
  }

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
    return res.status(502).json({ status: "error", message: "MarzPay rejected the payout: " + e.message });
  }

  const provider = (marzData.data && marzData.data.transaction && marzData.data.transaction.provider) || "";
  await txRef.update({
    channel: /airtel/i.test(provider) ? "airtel" : "mtn",
    marzUuid: (marzData.data && marzData.data.transaction && marzData.data.transaction.uuid) || "",
    providerMode: (marzData.data && marzData.data.transaction && marzData.data.transaction.mode) || "",
    updatedAt: serverTs()
  }).catch(() => {});

  res.json({
    status: "success",
    message: "Payout initiated. Funds are sent to the customer's phone.",
    data: { txId, marzRef: reference, provider: provider || "mtn" }
  });
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

app.listen(PORT, () => {
  console.log("[benz-pay] payments server listening on port " + PORT);
  console.log("[benz-pay] webhook endpoint: " + (PUBLIC_BASE_URL || "CALLBACK_URL_NOT_SET") + "/api/webhook");
});