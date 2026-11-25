// content-access -- Supabase Edge Function (Deno). Verify JWT must be OFF (token checked below).
// POST { item_id } -> video: { kind, title, youtube_id } | file: { kind, title, url (60s signed URL), ext }
// plus { watermark } text. Allowed if: item is a free preview, caller is an active admin, or caller is an
// active student with access (public.student_has_course: free course, course_access row, or an active
// non-expired course_grants row for the student's batch / type / the student). A folder (bundle) item returns
// { kind:'bundle', entry }; then POST { item_id, path } returns that file's bytes (used by the service worker).
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = ["https://biotechhome.github.io", "http://localhost:5500", "http://127.0.0.1:5500"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const cors = (req: Request) => {
  const o = req.headers.get("Origin") ?? "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(o) ? o : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS", "Vary": "Origin",
  };
};
const reply = (req: Request, status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors(req), "Content-Type": "application/json", "Cache-Control": "no-store" } });

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return reply(req, 405, { error: "Method not allowed" });
  const url = Deno.env.get("SUPABASE_URL"), key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return reply(req, 500, { error: "Server is not configured" });
  const admin = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });

  let b: Record<string, unknown>;
  try { b = await req.json(); } catch { return reply(req, 400, { error: "Invalid JSON" }); }
  const itemId = String(b.item_id ?? "");
  const relPath = b.path == null ? null : String(b.path);
  if (!UUID_RE.test(itemId)) return reply(req, 400, { error: "Bad item id" });

  const { data: item } = await admin.from("course_items")
    .select("id,course_id,title,kind,is_preview,is_active,courses(is_paid,is_active)").eq("id", itemId).maybeSingle();
  if (!item) return reply(req, 404, { error: "Not found" });
  const course = item.courses as unknown as { is_paid: boolean; is_active: boolean } | null;

  // who is calling? (optional)
  let uid: string | null = null, prof: { role: string; status: string; full_name: string; student_code: string | null; mobile: string | null } | null = null;
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (token) {
    const { data: u } = await admin.auth.getUser(token);
    uid = u?.user?.id ?? null;
    if (uid) {
      const { data: p } = await admin.from("profiles").select("role,status,full_name,student_code,mobile").eq("id", uid).maybeSingle();
      prof = p ?? null;
    }
  }
  const isAdmin = !!prof && prof.role === "admin" && prof.status === "active";
  if (!isAdmin && (!item.is_active || !course?.is_active)) return reply(req, 404, { error: "Not found" });

  let ok = isAdmin || item.is_preview;
  if (!ok) {
    if (!uid || !prof) return reply(req, 401, { error: "Login required" });
    if (prof.status !== "active") return reply(req, 403, { error: "Account is not active" });
    const { data: has, error: he } = await admin.rpc("student_has_course", { p_student: uid, p_course: item.course_id });
    if (he) return reply(req, 500, { error: "Access check failed" });
    ok = has === true;
  }
  if (!ok) return reply(req, 403, { error: "No access to this course" });

  const { data: f } = await admin.from("course_item_files").select("youtube_id,file_path,bundle_path,bundle_entry").eq("item_id", itemId).maybeSingle();
  if (!f) return reply(req, 404, { error: "Content missing" });
  const watermark = prof ? [prof.full_name, prof.student_code ?? "", prof.mobile ? prof.mobile.slice(0, 3) + "****" + prof.mobile.slice(-3) : ""].filter(Boolean).join(" · ") : "Biotech Home · preview";

  if (f.bundle_path) {
    if (relPath === null) return reply(req, 200, { ok: true, kind: "bundle", title: item.title, entry: f.bundle_entry, watermark });
    if (!/^[A-Za-z0-9_.\/-]{1,200}$/.test(relPath) || relPath.includes("..") || relPath.startsWith("/") || relPath.includes("//"))
      return reply(req, 400, { error: "Bad path" });
    const { data: blob, error: de } = await admin.storage.from("course-content").download(`${f.bundle_path}/${relPath}`);
    if (de || !blob) return reply(req, 404, { error: "File not found" });
    return new Response(blob, { status: 200, headers: { ...cors(req), "Content-Type": "application/octet-stream", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  }
  if (f.youtube_id) return reply(req, 200, { ok: true, kind: item.kind, title: item.title, youtube_id: f.youtube_id, watermark });
  const { data: s, error: se } = await admin.storage.from("course-content").createSignedUrl(f.file_path!, 60);
  if (se || !s) return reply(req, 500, { error: "Could not prepare the file" });
  const ext = (f.file_path!.split(".").pop() ?? "").toLowerCase();
  return reply(req, 200, { ok: true, kind: item.kind, title: item.title, url: s.signedUrl, ext, watermark });
});
