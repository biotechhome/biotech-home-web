// admin-student-action -- Supabase Edge Function (Deno)
// An ACTIVE ADMIN can archive, restore or permanently delete a student.
//   archive : profiles.status = 'blocked' + auth ban (student cannot log in), data is kept
//   restore : profiles.status = 'active'  + ban lifted
//   delete  : photo removed, auth user deleted (profile, fees, marks, attendance cascade). Irreversible.
// Deploy with "Verify JWT" OFF: the token is verified below with auth.getUser().
// Request (POST JSON): { "action": "archive|restore|delete", "student_id": "<uuid>" }
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = ["https://biotechhome.github.io", "http://localhost:5500", "http://127.0.0.1:5500"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  new Response(JSON.stringify(body), { status, headers: { ...cors(req), "Content-Type": "application/json" } });

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
  if (!["archive", "restore", "delete"].includes(action)) return reply(req, 400, { error: "Bad action" });
  if (!UUID_RE.test(id)) return reply(req, 400, { error: "Bad student id" });
  if (id === caller.user.id) return reply(req, 400, { error: "You cannot change your own account" });

  const { data: st } = await admin.from("profiles").select("id,role,photo_path").eq("id", id).maybeSingle();
  if (!st) return reply(req, 404, { error: "Student not found" });
  if (st.role !== "student") return reply(req, 403, { error: "Only students can be changed here" });

  if (action === "archive" || action === "restore") {
    const { error: pe } = await admin.from("profiles").update({ status: action === "archive" ? "blocked" : "active" }).eq("id", id);
    if (pe) return reply(req, 500, { error: "Could not update" });
    const { error: ae } = await admin.auth.admin.updateUserById(id, { ban_duration: action === "archive" ? "876000h" : "none" });
    if (ae) return reply(req, 500, { error: "Could not update login" });
    return reply(req, 200, { ok: true, action });
  }

  // delete
  if (st.photo_path) await admin.storage.from("student-photos").remove([st.photo_path]);
  const { error: de } = await admin.auth.admin.deleteUser(id);
  if (de) return reply(req, 409, { error: "Could not delete (online payments may exist). Archive instead." });
  return reply(req, 200, { ok: true, action });
});
