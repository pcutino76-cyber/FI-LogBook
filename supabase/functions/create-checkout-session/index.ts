import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const stripeSecretKey = Deno.env.get("STRIPE_SECRET_KEY");
    const stripePriceId = Deno.env.get("STRIPE_PRICE_ID");
    const siteUrl = Deno.env.get("SITE_URL");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY");

    if (!stripeSecretKey || !stripePriceId || !siteUrl || !supabaseUrl || !supabaseAnonKey) {
      return new Response(JSON.stringify({ error: "Server misconfiguration" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      global: {
        headers: {
          Authorization: authHeader,
        },
      },
    });

    const { data, error } = await supabase.auth.getUser();

    if (error || !data.user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const user = data.user;
    const body = new URLSearchParams({
      mode: "subscription",
      "line_items[0][price]": stripePriceId,
      "line_items[0][quantity]": "1",
      "metadata[supabase_user_id]": user.id,
      "subscription_data[metadata][supabase_user_id]": user.id,
      success_url: `${siteUrl}?checkout=success`,
      cancel_url: `${siteUrl}?checkout=cancelled`,
    });

    if (user.email) {
      body.set("customer_email", user.email);
    }

    const stripeResponse = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${stripeSecretKey}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!stripeResponse.ok) {
      return new Response(JSON.stringify({ error: "Failed to create checkout session" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const session = await stripeResponse.json();

    if (!session?.url) {
      return new Response(JSON.stringify({ error: "Failed to create checkout session" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ url: session.url }), {
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
