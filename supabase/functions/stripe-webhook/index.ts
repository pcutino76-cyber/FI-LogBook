import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, stripe-signature",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

type MetadataUpdates = {
  plan_tier?: "premium" | "free";
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  subscription_status?: string;
};

const encoder = new TextEncoder();
const STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300;

function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function parseStripeSignature(signature: string): { timestamp: number; signatures: string[] } | null {
  const parts = signature.split(",").map((part) => part.trim());
  const timestampRaw = parts.find((part) => part.startsWith("t="))?.slice(2);
  const signatures = parts.filter((part) => part.startsWith("v1=")).map((part) => part.slice(3));

  if (!timestampRaw || signatures.length === 0) return null;

  const timestamp = Number.parseInt(timestampRaw, 10);
  if (!Number.isFinite(timestamp)) return null;

  return { timestamp, signatures };
}

async function verifyStripeSignature(rawBody: string, signatureHeader: string, webhookSecret: string): Promise<boolean> {
  const parsed = parseStripeSignature(signatureHeader);
  if (!parsed) return false;

  const now = Math.floor(Date.now() / 1000);
  const ageInSeconds = Math.abs(now - parsed.timestamp);
  if (ageInSeconds > STRIPE_SIGNATURE_TOLERANCE_SECONDS) return false;

  const signedPayload = `${parsed.timestamp}.${rawBody}`;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(webhookSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sigBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(signedPayload));
  const computedSignature = Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return parsed.signatures.some((sig) => secureCompare(sig, computedSignature));
}

async function updateUserAppMetadata(
  supabase: ReturnType<typeof createClient>,
  userId: string,
  updates: MetadataUpdates,
): Promise<void> {
  const { data: existing, error: getError } = await supabase.auth.admin.getUserById(userId);
  if (getError || !existing?.user) throw new Error("Failed to load user");

  const current = existing.user.app_metadata ?? {};
  const nextMetadata = { ...current, ...updates };

  const { error: updateError } = await supabase.auth.admin.updateUserById(userId, {
    app_metadata: nextMetadata,
  });

  if (updateError) throw new Error("Failed to update user metadata");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const stripeWebhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseServiceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? Deno.env.get("SUPABASE_SECRET_KEY");

    if (!stripeWebhookSecret || !supabaseUrl || !supabaseServiceRoleKey) {
      return new Response(JSON.stringify({ error: "Server misconfiguration" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const signature = req.headers.get("Stripe-Signature");
    if (!signature) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const rawBody = await req.text();
    const isValidSignature = await verifyStripeSignature(rawBody, signature, stripeWebhookSecret);

    if (!isValidSignature) {
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const event = JSON.parse(rawBody);
    const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data?.object;
        const userId = session?.metadata?.supabase_user_id;

        if (userId) {
          await updateUserAppMetadata(supabase, userId, {
            plan_tier: "premium",
            stripe_customer_id: typeof session.customer === "string" ? session.customer : "",
            stripe_subscription_id: typeof session.subscription === "string" ? session.subscription : "",
            subscription_status: "active",
          });
        }
        break;
      }

      case "customer.subscription.updated": {
        const subscription = event.data?.object;
        const userId = subscription?.metadata?.supabase_user_id;
        const status = subscription?.status;

        if (userId && typeof status === "string") {
          const updates: MetadataUpdates = {
            stripe_customer_id: typeof subscription.customer === "string" ? subscription.customer : "",
            stripe_subscription_id: typeof subscription.id === "string" ? subscription.id : "",
            subscription_status: status,
          };

          if (status === "active" || status === "trialing") {
            updates.plan_tier = "premium";
          } else if (status === "canceled" || status === "unpaid" || status === "incomplete_expired") {
            updates.plan_tier = "free";
          }

          await updateUserAppMetadata(supabase, userId, updates);
        }
        break;
      }

      case "customer.subscription.deleted": {
        const subscription = event.data?.object;
        const userId = subscription?.metadata?.supabase_user_id;

        if (userId) {
          await updateUserAppMetadata(supabase, userId, {
            plan_tier: "free",
            stripe_customer_id: typeof subscription.customer === "string" ? subscription.customer : "",
            stripe_subscription_id: typeof subscription.id === "string" ? subscription.id : "",
            subscription_status: "canceled",
          });
        }
        break;
      }

      default:
        break;
    }

    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (_err) {
    return new Response(JSON.stringify({ error: "Internal server error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
