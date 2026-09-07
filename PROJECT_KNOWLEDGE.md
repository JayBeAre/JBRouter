# JBRouter Knowledge Graph

## 1. Project Overview
- **Type**: Cloudflare Worker
- **Purpose**: AI model router (Anthropic-compatible `/v1/messages` API).
- **Core Logic**: Routes requests to provider-based "pools" using keyword matching, with automatic fallback and admin configuration.

## 2. Directory Structure
- **`src/`** (Backend - TypeScript):
  - `index.ts`: Main entry point (fetch handler).
  - `router.ts`: Core routing, provider calling, and SSE streaming logic.
  - `providers.ts`: Logic for managing providers, pools, and role mappings.
  - `config.ts`: Shared constants, KV keys, utility functions (`j`, `aerr`, `mask`).
  - `auth.ts`: Authentication, session management, and password hashing (PBKDF2).
  - `debug.ts`: Debugging diagnostic endpoints (`/debug`, `/debug/zen`).
  - `admin/router.ts`: Admin API route handler.
- **`public/admin/`** (Frontend - Static Assets):
  - `index.html`: Admin panel markup.
  - `style.css`: UI styling.
  - `app.js`: Client-side logic and API interactions.

## 3. Deployment Configuration (`wrangler.toml`)
- **Compatibility Date**: `2026-09-06`
- **Main Script**: `src/index.ts`
- **Static Assets**: Served from `public/` directory via `[assets]` configuration.
- **KV Namespace**:
  - Binding: `CONFIG_KV`
  - ID: `49f33a74442b4d5db5899460df175d72`

## 4. Administrative Details
- **Admin Panel**: Accessible at `/admin`.
- **Default Password**: `changeme123` (Must be changed upon first login).
- **Security**: Password management and API token authentication are configured in the **Security** tab of the admin panel.

## 5. Current State & Workflow
- **Architecture**: Modular (Refactored successfully).
- **Git**: Initialized. The project is synced with GitHub repository `https://github.com/JayBeAre/JBRouter.git`.
- **Development Note**: Backend is TypeScript (compiled by Wrangler); Frontend is JavaScript (served statically).
