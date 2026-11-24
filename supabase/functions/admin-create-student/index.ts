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
//   { "session_year": 2028, "full_name": "...", "mobile": "017XXXXXXXX", "batch_id": "<uuid, optional>",
//     "class_time": "২টা (optional)", "has_photo": true,
//     "fee": { "month": "November", "year": 2026, "status": "paid|due|partial", "amount": 500 } (optional) }
// The student ID (auto-increment) and the 6-digit PIN are generated HERE.
// Response: 201 { "id", "student_code", "pin" }  (the PIN is shown once, never stored in clear)
// =============================================================================

import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = [
  "https://biotechhome.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const MONTHS = ["January","February","March","April","May","June","July","August","September","October","November","December"];
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

  const sessionYear = Number(body.session_year);
  const fullName = String(body.full_name ?? "").trim();
  const mobile = String(body.mobile ?? "").trim();
  const batchId = body.batch_id == null || body.batch_id === "" ? null : String(body.batch_id);
  const classTime = String(body.class_time ?? "").trim().slice(0, 20) || null;
  const hasPhoto = body.has_photo === true;
  const fee = (body.fee && typeof body.fee === "object") ? body.fee as Record<string, unknown> : null;

  if (!Number.isInteger(sessionYear) || sessionYear < 2020 || sessionYear > 2100) return reply(req, 400, { error: "Invalid session" });
  if (fullName.length < 2 || fullName.length > 80) return reply(req, 400, { error: "Name must be 2-80 characters" });
  if (!MOBILE_RE.test(mobile)) return reply(req, 400, { error: "Mobile must be 11 digits, like 01712345678" });
  if (batchId !== null && !UUID_RE.test(batchId)) return reply(req, 400, { error: "Invalid batch id" });
  let feeRow: { fee_month: string; fee_year: number; status: string; amount_bdt: number | null } | null = null;
  if (fee) {
    const st = String(fee.status ?? "").toLowerCase();
    const yr = Number(fee.year);
    const amt = fee.amount == null || fee.amount === "" ? null : Number(fee.amount);
    if (!MONTHS.includes(String(fee.month)) || !["paid", "due", "partial"].includes(st) ||
        !Number.isInteger(yr) || yr < 2020 || yr > 2100 || (amt !== null && (!Number.isInteger(amt) || amt < 0))) {
      return reply(req, 400, { error: "Invalid fee details" });
    }
    feeRow = { fee_month: String(fee.month), fee_year: yr, status: st, amount_bdt: amt };
  }

  // Duplicate rule: the same mobile may appear in different batches (e.g. siblings),
  // but not twice in the SAME batch.
  if (batchId) {
    const { data: dup } = await admin
      .from("batch_members")
      .select("student_id, profiles!inner(mobile)")
      .eq("batch_id", batchId)
      .eq("profiles.mobile", mobile)
      .limit(1);
    if (dup && dup.length > 0) {
      return reply(req, 409, { error: "A student with this mobile number is already in this batch" });
    }
  }

  // PIN: 6 random digits, generated with a cryptographic source.
  const rnd = new Uint32Array(1);
  crypto.getRandomValues(rnd);
  const pin = String(rnd[0] % 1000000).padStart(6, "0");

  // Next student number for this session (auto-increment). Retry if it is somehow taken.
  let studentCode = "";
  let appNo = 0;
  let newId = "";
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data: no, error: noErr } = await admin.rpc("next_student_no", { p_session: sessionYear });
    if (noErr || !no) return reply(req, 400, { error: "This session is not set up" });
    appNo = Number(no);
    studentCode = `${String(sessionYear).slice(2)}-${appNo}`;
    const email = `${studentCode.toLowerCase()}@s.biotechhome.invalid`;
    const { data: created, error: createErr } = await admin.auth.admin.createUser({
      email,
      password: mobile + pin,
      email_confirm: true,
      app_metadata: { created_by_admin: true, student_type: "offline" },
      user_metadata: { full_name: fullName },
    });
    if (created?.user) { newId = created.user.id; break; }
    if (!/already|registered|exists/i.test(createErr?.message ?? "")) {
      return reply(req, 400, { error: "Could not create the account" });
    }
  }
  if (!newId) return reply(req, 409, { error: "Could not find a free student ID, try again" });

  // ---- 5. Create the profile (undo the account if this fails) ----------------
  const { error: profileErr } = await admin.from("profiles").insert({
    id: newId,
    role: "student",
    student_type: "offline",
    student_code: studentCode,
    session_year: sessionYear,
    app_id: appNo,
    full_name: fullName,
    mobile,
    class_time: classTime,
    photo_path: hasPhoto ? `${newId}/photo.jpg` : null,
    status: "active",
  });
  if (profileErr) {
    await admin.auth.admin.deleteUser(newId);
    return reply(req, 400, { error: "Could not save the student" });
  }

  // ---- 6. Optional: batch and first fee record -------------------------------
  const warnings: string[] = [];
  if (batchId) {
    const { error: batchErr } = await admin.from("batch_members").insert({ batch_id: batchId, student_id: newId });
    if (batchErr) warnings.push("batch");
  }
  if (feeRow) {
    const { error: feeErr } = await admin.from("fee_payments").insert({ student_id: newId, ...feeRow });
    if (feeErr) warnings.push("fee");
  }
  return reply(req, 201, { id: newId, student_code: studentCode, pin, warnings });
});
