# NEXUS Platform — Technical Brief

**Version:** 3.0
**Stack:** Next.js 16 · NestJS 11 · PostgreSQL · Prisma · Zustand · Clerk · Stripe · Tailwind CSS
**Monorepo:** `apps/web` (frontend) + `apps/api-gateway` (backend)

---

## 1. Platform Overview

NEXUS is a full-stack dropshipping e-commerce platform with an integrated multi-tier agent/affiliate network. It enables direct factory-to-customer fulfillment while providing agents with their own storefronts, commission tracking, and team management.

---

## 2. Feature Modules

### 2.1 Storefront (`/store`, `/products`, `/products/[slug]`)
- Product catalog with search (Fuse.js), category filters, grid/list view, sort (trending, price, rating)
- Product detail with 3D canvas, specs, reviews, wishlist
- Add to cart → Zustand `cartStore` → `CartDrawer` opens automatically
- **API:** `GET /products` (NestJS `ProductsController`)

### 2.2 Cart & Checkout (`/checkout`)
- CartDrawer (Zustand `cartStore`, persisted in `nexus-cart-storage`)
- Stripe Elements payment form
- Order placed → `orderStore.addOrder()` → redirect to `/checkout/success`
- 8% tax rate, free shipping over $99

### 2.3 Agents & Teams (`/admin/agents`)
- **Hierarchy:** Director → Senior Agent → Agent → Sub-Agent (tree visualization)
- **Commission tiers:** Bronze (6%), Silver (7%), Gold (8%), Platinum (10%) + override bonuses
- **Leaderboard:** sorted by revenue, filterable by name/region
- **Recruitment form:** invite new agents via email
- **State:** Zustand `agentStore` (`nexus-agent-storage`), seeded from `components/nexus/data.ts`
- **API (future):** `GET /agent`, `POST /agent`

### 2.4 Order Management (`/orders/manage`)
- Admin view of all NEXUS orders with agent attribution and supplier tracking
- Filter by status (pending / processing / shipped / delivered)
- Search by order ID, customer name, product name
- **State:** seeded from `components/nexus/data.ts` → `NEXUS_ORDERS`
- **API (future):** `GET /orders`

### 2.5 Suppliers & Dropship (`/admin/suppliers`)
- Supplier directory: rating, on-time %, return rate, verification status
- 6-step fulfillment pipeline visualization
- Product sourcing request form (24-48h turnaround SLA)
- 4-stage QC process + QC stats dashboard
- **API:** `GET /dropship` (NestJS `DropshipModule`, exists)

### 2.6 Analytics (`/admin/analytics`)
- KPIs: Total Revenue ($1.68M), Gross Margin (42.3%), Active Customers, Countries
- 6-month revenue trend bar chart (built with CSS, migrate to Recharts)
- Top 5 products by sales
- Revenue breakdown by region (5 regions) with progress bars
- Fulfillment metrics: processing time, shipping time, satisfaction, return rate, repeat rate
- Agent network contribution breakdown
- **API (future):** `GET /analytics`

### 2.7 Platform Settings (`/admin/settings`)
- Platform config: store name, currency, language, tax rate, shipping threshold
- Security: 2FA, API keys, webhook URL, admin roles
- Shipping: carrier, delivery estimate, tracking, auto-fulfill, insurance
- Payment gateways: Stripe, PayPal, Crypto (Coinbase), Bank Transfer, Agent Escrow
- Notifications: order, shipping, agent alerts, low stock, commission payout
- Integrations: Shopify, WooCommerce, CJ Dropshipping, Google Analytics, Slack

---

## 3. Data Models

### Agent
```ts
interface Agent {
  id: number;
  name: string;
  level: 'Sub-Agent' | 'Agent' | 'Senior Agent' | 'Director';
  email: string;
  region: string;
  revenue: number;
  commission: number;
  subAgents: number;
  orders: number;
  status: 'active' | 'pending' | 'inactive';
  since: string;       // ISO "YYYY-MM"
  tier: 'bronze' | 'silver' | 'gold' | 'platinum';
  parent?: number;     // parent agent ID
}
```

### Supplier
```ts
interface Supplier {
  id: number;
  name: string;
  country: string;
  rating: number;
  products: number;
  orders: number;
  onTime: number;    // %
  returns: number;   // %
  status: 'verified' | 'pending' | 'suspended';
}
```

### NexusOrder (agent-attributed)
```ts
interface NexusOrder {
  id: string;        // e.g. "NX-2026-00891"
  customer: string;
  product: string;
  agent: string;
  status: 'pending' | 'processing' | 'shipped' | 'delivered';
  date: string;
  total: number;
  tracking: string | null;
  supplier: string;
}
```

> Customer-facing orders use the existing `Order` interface in `types/index.ts`.

---

## 4. File Structure

```
apps/web/
├── types/
│   ├── index.ts              # Product, CartItem, Order, Address
│   └── nexus.ts              # Agent, Supplier, NexusOrder, CommissionTier, Analytics
├── stores/
│   ├── cartStore.ts          # Shopping cart (Zustand + persist)
│   ├── orderStore.ts         # Customer orders (Zustand + persist)
│   ├── favoritesStore.ts     # Wishlist (Zustand)
│   └── agentStore.ts         # Agent network (Zustand + persist)  ← NEW
├── components/
│   └── nexus/
│       ├── data.ts           # Seed data: NEXUS_AGENTS, NEXUS_SUPPLIERS, NEXUS_ORDERS, COMMISSION_TIERS
│       ├── ui/
│       │   ├── badge.tsx         # NexusBadge + statusVariant helper
│       │   ├── stat-card.tsx     # StatCard
│       │   ├── progress-bar.tsx  # ProgressBar
│       │   ├── status-dot.tsx    # StatusDot
│       │   └── tab-btn.tsx       # TabBtn
│       ├── agents/
│       │   └── agent-dashboard.tsx
│       ├── orders/
│       │   └── order-management.tsx
│       ├── suppliers/
│       │   └── supplier-management.tsx
│       ├── analytics/
│       │   └── analytics-dashboard.tsx
│       └── settings/
│           └── admin-settings.tsx
└── app/
    ├── admin/
    │   ├── page.tsx             # Enhanced with sub-section nav tiles
    │   ├── agents/page.tsx      # NEW — AgentDashboard
    │   ├── suppliers/page.tsx   # NEW — SupplierManagement
    │   ├── analytics/page.tsx   # NEW — AnalyticsDashboard
    │   └── settings/page.tsx    # NEW — AdminSettings
    └── orders/
        └── manage/page.tsx      # NEW — OrderManagement (admin view)
```

---

## 5. API Contract

| Method | Endpoint | Status | Used By |
|---|---|---|---|
| `GET` | `/products` | ✅ Live | Storefront, Product Detail |
| `POST` | `/products` | ✅ Live | Admin product creation |
| `GET` | `/dropship` | ✅ Live | Supplier Management |
| `POST` | `/agent/chat` | ✅ Live | AI Assistant |
| `POST` | `/checkout` | ✅ Live | Checkout page (Stripe) |
| `GET` | `/agent` | 🔲 Planned | Agent Dashboard |
| `GET` | `/orders` | 🔲 Planned | Order Management |
| `GET` | `/analytics` | 🔲 Planned | Analytics Dashboard |

---

## 6. Auth & Authorization

All `/admin/*` and `/orders/manage` pages are protected by Clerk auth:
- `useAuth()` → `isSignedIn` gate
- Unauthenticated users see a sign-in prompt
- Future: role-based access (admin vs agent) via Clerk metadata

---

## 7. Verification Checklist

- [ ] `cd 2027-online-shop && npm run dev` — all apps start cleanly
- [ ] `/admin` — navigation tiles visible (Agents, Suppliers, Analytics, Settings)
- [ ] `/admin/agents` — hierarchy tree, leaderboard, commission breakdown, tier cards render
- [ ] `/admin/suppliers` — supplier cards, fulfillment pipeline, sourcing form, QC stats render
- [ ] `/admin/analytics` — KPI cards, revenue chart, top products, region breakdown render
- [ ] `/admin/settings` — all 6 setting panels render
- [ ] `/orders/manage` — NEXUS order table with filter/search works
- [ ] Add item to cart → CartDrawer opens, total updates
- [ ] `npm run build` — TypeScript passes with zero type errors
- [ ] Unauthenticated visit to `/admin/agents` shows sign-in prompt
