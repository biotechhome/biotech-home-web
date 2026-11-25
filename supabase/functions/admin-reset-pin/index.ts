// admin-reset-pin -- Supabase Edge Function (Deno)
// An ACTIVE ADMIN can (a) generate a new 6-digit PIN for an OFFLINE student, or
// (b) correct the student's mobile number (which also generates a new PIN, because
// the login password is <mobile><PIN>). The PIN is returned once and never stored.
// Verify JWT must be OFF: the token is verified below with auth.getUser().
// Request (POST JSON): { "action": "reset_pin" | "set_mobile", "student_id": "<uuid>", "mobile": "01XXXXXXXXX" (set_mobile only) }
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = ["https://biotechhome.github.io", "http://localhost:5500", "http://127.0.0.1:5500"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MOBILE_RE = /^01[3-9][0-9]{8}$/;

function cors(req: Request): Record<string, string> {
  const o = req.headers.get("Origin") ?? "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
const reply = (req: Request, status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors(req), "Content-Type": "application/json", "Cache-Control": "no-store" } });

function newPin(): string {
  const a = new Uint32Array(1);
  let n: number;
  do { crypto.getRandomValues(a); n = a[0]; } while (n >= 4294000000); // avoid modulo bias
  return String(n % 1000000).padStart(6, "0");
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return reply(req, 405, { error: "Method not allowed" });
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return reply(req, 500, { error: "Server is not configured" });

  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!token) return reply(req, 401, { error: "Login required" });
  const admin = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: caller, error: ce } = await admin.auth.getUser(token);
  if (ce || !caller?.user) return reply(req, 401, { error: "Invalid or expired session" });
  const { data: me } = await admin.from("profiles").select("role,status").eq("id", caller.user.id).maybeSingle();
  if (!me || me.role !== "admin" || me.status !== "active") return reply(req, 403, { error: "Admins only" });

  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return reply(req, 400, { error: "Invalid JSON" }); }
  const action = String(b.action ?? "");
  const id = String(b.student_id ?? "");
  if (!["reset_pin", "set_mobile"].includes(action)) return reply(req, 400, { error: "Bad action" });
  if (!UUID_RE.test(id)) return reply(req, 400, { error: "Bad student id" });

  const { data: st } = await admin.from("profiles").select("id,role,student_type,student_code,mobile,status").eq("id", id).maybeSingle();
  if (!st) return reply(req, 404, { error: "Student not found" });
  if (st.role !== "student") return reply(req, 403, { error: "Only students can be changed here" });
  if (st.student_type !== "offline") return reply(req, 400, { error: "Only offline students use a PIN" });

  let mobile = st.mobile as string | null;
  if (action === "set_mobile") {
    mobile = String(b.mobile ?? "");
    if (!MOBILE_RE.test(mobile)) return reply(req, 400, { error: "Invalid mobile number" });
  }
  if (!mobile) return reply(req, 400, { error: "Student has no mobile number. Set it first." });

  const pin = newPin();
  const { error: pe } = await admin.auth.admin.updateUserById(id, { password: mobile + pin });
  if (pe) return reply(req, 500, { error: "Could not update the password" });

  if (action === "set_mobile") {
    const patch: Record<string, unknown> = { mobile };
    if (st.status === "pending") patch.status = "active";
    const { error: me2 } = await admin.from("profiles").update(patch).eq("id", id);
    if (me2) return reply(req, 500, { error: "Password changed but the mobile could not be saved. Try again." });
  }
  return reply(req, 200, { ok: true, student_code: st.student_code, mobile, pin });
});
