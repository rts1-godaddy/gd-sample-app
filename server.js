import crypto from "node:crypto";
import express from "express";

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.GODADDY_WEBHOOK_SECRET;

if (!WEBHOOK_SECRET) {
  console.error("GODADDY_WEBHOOK_SECRET is required");
  process.exit(1);
}

const app = express();

// Capture raw body for HMAC verification, then parse JSON.
app.use(
  express.json({
    verify(req, _res, buf) {
      req.rawBody = buf;
    },
  })
);

// --- HMAC verification -------------------------------------------------------

function verifySignature(rawBody, signature, secret) {
  const expected =
    "sha256=" + crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

// --- Health check ------------------------------------------------------------

app.get("/health", (_req, res) => res.json({ ok: true }));

// --- Webhook endpoint --------------------------------------------------------

app.post("/webhooks", (req, res) => {
  const signature = req.headers["x-godaddy-signature-sha256"];
  if (!signature || !verifySignature(req.rawBody, signature, WEBHOOK_SECRET)) {
    console.warn("Rejected: invalid or missing signature");
    return res.status(401).json({ error: "invalid signature" });
  }

  const eventId = req.headers["x-godaddy-event-id"];
  const eventType = req.headers["x-godaddy-event-type"];
  const deliveryId = req.headers["x-godaddy-delivery-id"];

  console.log(
    JSON.stringify({
      received: eventType,
      eventId,
      deliveryId,
      storeId: req.body.storeId,
      timestamp: req.body.timestamp,
    })
  );

  // Respond 200 immediately — process asynchronously in production.
  res.status(200).json({ received: true });
});

// --- Launch endpoint (Installer opens this URL during install) ----------------

app.get("/launch", (req, res) => {
  const { installation_id, store_id, return_url, release_version, timestamp, hmac } =
    req.query;

  console.log(
    JSON.stringify({
      launch: { installation_id, store_id, release_version, timestamp },
    })
  );

  // TODO: verify launch HMAC, then initiate OAuth PKCE flow.
  // For now, just acknowledge the launch.
  res.json({
    status: "launched",
    installation_id,
    store_id,
  });
});

// -----------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`gd-sample-app listening on :${PORT}`);
});
