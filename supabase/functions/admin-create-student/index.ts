// =============================================================================
// admin-create-student  --  Supabase Edge Function (Deno)
//
// Lets an ADMIN create an OFFLINE student account.
//   Login of the student:  student ID + mobile + 6-digit PIN
//   Technical identity  :  e-mail  <ID-lowercase>@s.biotechhome.invalid
//                          password = <mobile><PIN>   (e.g. 01712345678123456)
//
// Security rules
//   * The caller must send a valid session token (Authorization: Bearer ...).
//   * The caller must be an ACTIVE admin in public.profiles. Anyone else: 403.
//   * The service-role key is read from the function's own environment only.
//     It is never sent to a client and never written to a file.
//   * The password / PIN is never returned or logged.
//   * Deploy with "Verify JWT" OFF: the token is verified in the code below
//     with auth.getUser(), which also works with the new API keys.
//
// Request  (POST, JSON):
//   { "student_code": "ST1001", "full_name": "...", "mobile": "017XXXXXXXX",
//     "pin": "123456", "batch_id": "<uuid, optional>" }
// Response: 201 { "id": "<uuid>", "student_code": "ST1001" }  or  { "error": "..." }
// =============================================================================

import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = [
  "https://biotechhome.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const CODE_RE = /^[A-Za-z0-9-]{3,20}$/;
const MOBILE_RE = /^01[3-9][0-9]{8}$/;
const PIN_RE = /^[0-9]{6}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function reply(req: Request, status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(req) });
  if (req.method !== "POST") return reply(req, 405, { error: "Method not allowed" });

  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return reply(req, 500, { error: "Server is not configured" });

  // ---- 1. Who is calling? ---------------------------------------------------
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (!token) return reply(req, 401, { error: "Login required" });

  const admin = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: caller, error: callerErr } = await admin.auth.getUser(token);
  if (callerErr || !caller?.user) return reply(req, 401, { error: "Invalid or expired session" });

  // ---- 2. Is the caller an active admin? -------------------------------------
  const { data: me } = await admin
    .from("profiles")
    .select("role,status")
    .eq("id", caller.user.id)
    .maybeSingle();
  if (!me || me.role !== "admin" || me.status !== "active") {
    return reply(req, 403, { error: "Admins only" });
  }

  // ---- 3. Validate the input -------------------------------------------------
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return reply(req, 400, { error: "Invalid JSON" });
  }

  const studentCode = String(body.student_code ?? "").trim().toUpperCase();
  const fullName = String(body.full_name ?? "").trim();
  const mobile = String(body.mobile ?? "").trim();
  const pin = String(body.pin ?? "").trim();
  const batchId = body.batch_id == null || body.batch_id === "" ? null : String(body.batch_id);

  if (!CODE_RE.test(studentCode)) return reply(req, 400, { error: "Student ID must be 3-20 letters, digits or hyphens" });
  if (fullName.length < 2 || fullName.length > 80) return reply(req, 400, { error: "Name must be 2-80 characters" });
  if (!MOBILE_RE.test(mobile)) return reply(req, 400, { error: "Mobile must be 11 digits, like 01712345678" });
  if (!PIN_RE.test(pin)) return reply(req, 400, { error: "PIN must be exactly 6 digits" });
  if (batchId !== null && !UUID_RE.test(batchId)) return reply(req, 400, { error: "Invalid batch id" });

  // ---- 4. Create the login account -------------------------------------------
  const email = `${studentCode.toLowerCase()}@s.biotechhome.invalid`;
  const { data: created, error: createErr } = await admin.auth.admin.createUser({
    email,
    password: mobile + pin,
    email_confirm: true,
    // app_metadata can only be written by server code: this flag tells the
    // sign-up trigger to leave profile creation to this function.
    app_metadata: { created_by_admin: true, student_type: "offline" },
    user_metadata: { full_name: fullName },
  });
  if (createErr || !created?.user) {
    const taken = /already|registered|exists/i.test(createErr?.message ?? "");
    return reply(req, taken ? 409 : 400, {
      error: taken ? "This student ID is already registered" : "Could not create the account",
    });
  }
  const newId = created.user.id;

  // ---- 5. Create the profile (undo the account if this fails) ----------------
  const { error: profileErr } = await admin.from("profiles").insert({
    id: newId,
    role: "student",
    student_type: "offline",
    student_code: studentCode,
    full_name: fullName,
    mobile,
    status: "active",
  });
  if (profileErr) {
    await admin.auth.admin.deleteUser(newId);
    const dup = profileErr.code === "23505";
    return reply(req, dup ? 409 : 400, {
      error: dup ? "This student ID or mobile number is already registered" : "Could not save the student",
    });
  }

  // ---- 6. Optional: add to a batch -------------------------------------------
  if (batchId) {
    const { error: batchErr } = await admin.from("batch_members").insert({ batch_id: batchId, student_id: newId });
    if (batchErr) {
      return reply(req, 201, { id: newId, student_code: studentCode, warning: "Student created, but the batch could not be set" });
    }
  }

  return reply(req, 201, { id: newId, student_code: studentCode });
});
