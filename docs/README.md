# Biotech Home — Secure Learning Website

Biotech Home is a coaching center in Rangpur, Bangladesh (teacher: Md. Moksadur Rahman Repon). This project is a secure online learning website for its students. The end-user interface is in Bengali.

## Stack

- **Backend:** Supabase (Auth, Postgres, Storage)
- **Frontend:** static site in `site/`, hosted on GitHub Pages

## Project Goals

1. **Login is mandatory for all content.** No lesson, file, or video is visible to anonymous visitors. Every protected page requires an authenticated session.
2. **Protected content lives in private Supabase Storage.** Buckets are private (never public). Files are served only through short-lived signed URLs, generated for authenticated and authorized users.
3. **Row Level Security (RLS) is enabled on every table.** Access is denied by default and granted only through explicit policies.

## Security Rules

- No password, secret key, or `service_role` key is ever written to any file in this repository.
- Only the publishable (anon) key may appear in client code. Real protection comes from RLS and Storage policies, not from hiding the anon key.

## Repository Layout

| Folder                 | Purpose                                    |
| ---------------------- | ------------------------------------------ |
| `supabase/migrations/` | SQL migrations (schema, RLS, storage policies) |
| `site/`                | Static frontend (Bengali UI)               |
| `docs/`                | Project documentation                      |
