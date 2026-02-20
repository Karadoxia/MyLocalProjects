import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { Search, ShoppingCart, User, Package, TrendingUp, Users, Settings, ChevronRight, Star, Heart, Eye, Filter, Grid, List, Plus, Minus, X, Check, AlertCircle, ArrowRight, ArrowLeft, BarChart3, DollarSign, Globe, Truck, Shield, Zap, Bell, MessageSquare, Home, Store, Layers, Award, Target, CreditCard, MapPin, Clock, RefreshCw, ChevronDown, ChevronUp, Copy, ExternalLink, Percent, Box, Clipboard, Mail, Phone, FileText, Download, Upload, MoreHorizontal, LogOut, Edit, Trash2, Image as ImageIcon } from "lucide-react";

// ============================================================
// NEXUS PLATFORM — FULL DROPSHIPPING E-COMMERCE + AGENT SYSTEM
// ============================================================

const COLORS = {
  bg: "#0a0a0f",
  bgCard: "#12121a",
  bgHover: "#1a1a28",
  bgElevated: "#16161f",
  accent: "#00f0ff",
  accentDim: "#00f0ff33",
  accentGlow: "0 0 20px #00f0ff44",
  success: "#00ff88",
  warning: "#ffaa00",
  danger: "#ff3366",
  text: "#e8e8f0",
  textDim: "#8888aa",
  border: "#2a2a3a",
  gradient: "linear-gradient(135deg, #00f0ff, #7b61ff)",
};

// ---- MOCK DATA ----
const PRODUCTS = [
  { id: 1, name: "NEXUS RTX 5090 ULTRA", category: "GPU", price: 1999.99, cost: 1200, supplier: "ShenZhen TechCore", rating: 4.8, reviews: 342, stock: 150, image: "🎮", sales: 1200, trending: true, tags: ["gaming", "pro"] },
  { id: 2, name: "Quantum MechBoard Pro", category: "Peripherals", price: 289.99, cost: 95, supplier: "GZ Keyboards Co", rating: 4.9, reviews: 891, stock: 500, image: "⌨️", sales: 3400, trending: true, tags: ["keyboard", "mechanical"] },
  { id: 3, name: "HoloDisplay 8K 42\"", category: "Monitors", price: 3499.99, cost: 1800, supplier: "Dongguan Visual Ltd", rating: 4.7, reviews: 178, stock: 45, image: "🖥️", sales: 890, trending: false, tags: ["display", "8k"] },
  { id: 4, name: "NEXUS AirPods Quantum", category: "Audio", price: 449.99, cost: 120, supplier: "ShenZhen AudioTech", rating: 4.6, reviews: 2103, stock: 2000, image: "🎧", sales: 8900, trending: true, tags: ["audio", "wireless"] },
  { id: 5, name: "NanoSSD 8TB Gen5", category: "Storage", price: 699.99, cost: 280, supplier: "Xiamen StoragePro", rating: 4.8, reviews: 567, stock: 300, image: "💾", sales: 2300, trending: false, tags: ["storage", "ssd"] },
  { id: 6, name: "CyberMouse X1 Ultra", category: "Peripherals", price: 179.99, cost: 42, supplier: "GZ Keyboards Co", rating: 4.5, reviews: 1456, stock: 800, image: "🖱️", sales: 5600, trending: true, tags: ["mouse", "gaming"] },
  { id: 7, name: "NEXUS Laptop Forge 17", category: "Laptops", price: 2899.99, cost: 1600, supplier: "ShenZhen TechCore", rating: 4.9, reviews: 234, stock: 75, image: "💻", sales: 670, trending: true, tags: ["laptop", "pro"] },
  { id: 8, name: "HyperCam 4K Streamer", category: "Streaming", price: 249.99, cost: 68, supplier: "Dongguan Visual Ltd", rating: 4.4, reviews: 789, stock: 400, image: "📷", sales: 3100, trending: false, tags: ["camera", "streaming"] },
  { id: 9, name: "CloudRouter AX12000", category: "Networking", price: 399.99, cost: 145, supplier: "Xiamen StoragePro", rating: 4.7, reviews: 456, stock: 200, image: "📡", sales: 1800, trending: false, tags: ["router", "wifi"] },
  { id: 10, name: "PowerStation 2000W", category: "Power", price: 599.99, cost: 210, supplier: "ShenZhen TechCore", rating: 4.6, reviews: 321, stock: 150, image: "🔋", sales: 1400, trending: false, tags: ["power", "ups"] },
  { id: 11, name: "SmartDesk Pro Adjustable", category: "Furniture", price: 899.99, cost: 340, supplier: "Foshan FurniTech", rating: 4.8, reviews: 612, stock: 100, image: "🪑", sales: 2100, trending: true, tags: ["desk", "ergonomic"] },
  { id: 12, name: "NEXUS VR Headset Gen3", category: "VR/AR", price: 799.99, cost: 310, supplier: "ShenZhen TechCore", rating: 4.7, reviews: 923, stock: 250, image: "🥽", sales: 4200, trending: true, tags: ["vr", "gaming"] },
];

const CATEGORIES = ["All", "GPU", "Peripherals", "Monitors", "Audio", "Storage", "Laptops", "Streaming", "Networking", "Power", "Furniture", "VR/AR"];

const SUPPLIERS = [
  { id: 1, name: "ShenZhen TechCore", country: "China", rating: 4.8, products: 342, orders: 12500, onTime: 97, returns: 1.2, status: "verified" },
  { id: 2, name: "GZ Keyboards Co", country: "China", rating: 4.9, products: 156, orders: 8900, onTime: 99, returns: 0.8, status: "verified" },
  { id: 3, name: "Dongguan Visual Ltd", country: "China", rating: 4.6, products: 89, orders: 4500, onTime: 94, returns: 2.1, status: "verified" },
  { id: 4, name: "Xiamen StoragePro", country: "China", rating: 4.7, products: 201, orders: 6700, onTime: 96, returns: 1.5, status: "pending" },
  { id: 5, name: "Foshan FurniTech", country: "China", rating: 4.5, products: 78, orders: 3200, onTime: 92, returns: 3.0, status: "verified" },
];

const AGENTS = [
  { id: 1, name: "Sarah Chen", level: "Director", email: "sarah@nexus.com", region: "North America", revenue: 458000, commission: 45800, subAgents: 12, orders: 3400, status: "active", since: "2023-01", tier: "platinum" },
  { id: 2, name: "Marcus Rivera", level: "Senior Agent", email: "marcus@nexus.com", region: "Europe", revenue: 289000, commission: 23120, subAgents: 7, orders: 2100, status: "active", since: "2023-06", tier: "gold", parent: 1 },
  { id: 3, name: "Aisha Patel", level: "Senior Agent", email: "aisha@nexus.com", region: "Asia Pacific", revenue: 367000, commission: 29360, subAgents: 9, orders: 2800, status: "active", since: "2023-03", tier: "gold", parent: 1 },
  { id: 4, name: "Liam O'Brien", level: "Agent", email: "liam@nexus.com", region: "UK & Ireland", revenue: 145000, commission: 10150, subAgents: 3, orders: 980, status: "active", since: "2024-01", tier: "silver", parent: 2 },
  { id: 5, name: "Yuki Tanaka", level: "Agent", email: "yuki@nexus.com", region: "Japan", revenue: 198000, commission: 13860, subAgents: 4, orders: 1500, status: "active", since: "2023-09", tier: "silver", parent: 3 },
  { id: 6, name: "Omar Hassan", level: "Sub-Agent", email: "omar@nexus.com", region: "Middle East", revenue: 78000, commission: 4680, subAgents: 0, orders: 560, status: "active", since: "2024-06", tier: "bronze", parent: 3 },
  { id: 7, name: "Elena Volkov", level: "Sub-Agent", email: "elena@nexus.com", region: "Eastern Europe", revenue: 56000, commission: 3360, subAgents: 0, orders: 420, status: "active", since: "2024-08", tier: "bronze", parent: 2 },
  { id: 8, name: "Carlos Mendez", level: "Sub-Agent", email: "carlos@nexus.com", region: "Latin America", revenue: 43000, commission: 2580, subAgents: 0, orders: 310, status: "pending", since: "2025-01", tier: "bronze", parent: 4 },
];

const ORDERS = [
  { id: "NX-2026-00891", customer: "John D.", product: "NEXUS RTX 5090 ULTRA", agent: "Sarah Chen", status: "delivered", date: "2026-02-18", total: 1999.99, tracking: "TRK9912831", supplier: "ShenZhen TechCore" },
  { id: "NX-2026-00890", customer: "Emma W.", product: "Quantum MechBoard Pro", agent: "Marcus Rivera", status: "shipped", date: "2026-02-17", total: 289.99, tracking: "TRK9912830", supplier: "GZ Keyboards Co" },
  { id: "NX-2026-00889", customer: "Akira S.", product: "NEXUS AirPods Quantum", agent: "Yuki Tanaka", status: "processing", date: "2026-02-17", total: 449.99, tracking: null, supplier: "ShenZhen AudioTech" },
  { id: "NX-2026-00888", customer: "Lisa M.", product: "HoloDisplay 8K 42\"", agent: "Liam O'Brien", status: "shipped", date: "2026-02-16", total: 3499.99, tracking: "TRK9912828", supplier: "Dongguan Visual Ltd" },
  { id: "NX-2026-00887", customer: "David K.", product: "CyberMouse X1 Ultra", agent: "Aisha Patel", status: "delivered", date: "2026-02-15", total: 179.99, tracking: "TRK9912827", supplier: "GZ Keyboards Co" },
  { id: "NX-2026-00886", customer: "Fatima A.", product: "NEXUS VR Headset Gen3", agent: "Omar Hassan", status: "pending", date: "2026-02-19", total: 799.99, tracking: null, supplier: "ShenZhen TechCore" },
  { id: "NX-2026-00885", customer: "Pierre L.", product: "NanoSSD 8TB Gen5", agent: "Elena Volkov", status: "processing", date: "2026-02-18", total: 699.99, tracking: null, supplier: "Xiamen StoragePro" },
  { id: "NX-2026-00884", customer: "Maria G.", product: "SmartDesk Pro", agent: "Carlos Mendez", status: "pending", date: "2026-02-19", total: 899.99, tracking: null, supplier: "Foshan FurniTech" },
];

const COMMISSION_TIERS = [
  { tier: "Bronze", icon: "🥉", minRevenue: 0, rate: 6, override: 0, perks: ["Basic dashboard", "Email support", "Product catalog access"] },
  { tier: "Silver", icon: "🥈", minRevenue: 100000, rate: 7, override: 1, perks: ["Priority support", "Custom storefront", "Training resources", "Sub-agent recruiting"] },
  { tier: "Gold", icon: "🥇", minRevenue: 250000, rate: 8, override: 2, perks: ["Dedicated account manager", "Exclusive products", "Marketing materials", "Team management tools"] },
  { tier: "Platinum", icon: "💎", minRevenue: 400000, rate: 10, override: 3, perks: ["VIP concierge", "First access to drops", "Revenue sharing", "Global team leadership", "Strategy sessions"] },
];

// ---- UTILITY COMPONENTS ----
const Badge = ({ children, color = COLORS.accent, glow = false }) => (
  <span style={{
    padding: "2px 10px", borderRadius: 20, fontSize: 11, fontWeight: 700,
    background: color + "22", color, border: `1px solid ${color}44`,
    letterSpacing: "0.5px", textTransform: "uppercase",
    boxShadow: glow ? `0 0 12px ${color}33` : "none",
  }}>{children}</span>
);

const StatusDot = ({ status }) => {
  const colors = { active: COLORS.success, pending: COLORS.warning, inactive: COLORS.danger, delivered: COLORS.success, shipped: COLORS.accent, processing: COLORS.warning, verified: COLORS.success };
  return <span style={{ width: 8, height: 8, borderRadius: "50%", background: colors[status] || COLORS.textDim, display: "inline-block", boxShadow: `0 0 6px ${colors[status] || COLORS.textDim}` }} />;
};

const StatCard = ({ icon: Icon, label, value, change, color = COLORS.accent }) => (
  <div style={{
    background: COLORS.bgCard, borderRadius: 16, padding: "20px 24px", border: `1px solid ${COLORS.border}`,
    display: "flex", flexDirection: "column", gap: 12, position: "relative", overflow: "hidden",
  }}>
    <div style={{ position: "absolute", top: -20, right: -20, width: 80, height: 80, borderRadius: "50%", background: color + "08" }} />
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      <div style={{ width: 40, height: 40, borderRadius: 12, background: color + "15", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Icon size={20} color={color} />
      </div>
      {change && <span style={{ fontSize: 12, color: change > 0 ? COLORS.success : COLORS.danger, fontWeight: 600 }}>{change > 0 ? "▲" : "▼"} {Math.abs(change)}%</span>}
    </div>
    <div>
      <div style={{ fontSize: 24, fontWeight: 800, color: COLORS.text, fontFamily: "'Orbitron', sans-serif" }}>{value}</div>
      <div style={{ fontSize: 12, color: COLORS.textDim, marginTop: 4, textTransform: "uppercase", letterSpacing: "1px" }}>{label}</div>
    </div>
  </div>
);

const ProgressBar = ({ value, max, color = COLORS.accent }) => (
  <div style={{ width: "100%", height: 6, background: COLORS.border, borderRadius: 3, overflow: "hidden" }}>
    <div style={{ width: `${(value / max) * 100}%`, height: "100%", background: `linear-gradient(90deg, ${color}, ${color}aa)`, borderRadius: 3, transition: "width 0.5s ease" }} />
  </div>
);

const SearchBar = ({ value, onChange, placeholder = "Search..." }) => (
  <div style={{ position: "relative", flex: 1, maxWidth: 400 }}>
    <Search size={16} color={COLORS.textDim} style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
    <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ width: "100%", padding: "10px 14px 10px 40px", background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, outline: "none", boxSizing: "border-box" }}
    />
  </div>
);

const TabBtn = ({ active, children, onClick, icon: Icon, count }) => (
  <button onClick={onClick} style={{
    padding: "10px 18px", background: active ? COLORS.accentDim : "transparent", border: `1px solid ${active ? COLORS.accent : "transparent"}`,
    borderRadius: 10, color: active ? COLORS.accent : COLORS.textDim, fontSize: 13, fontWeight: 600,
    cursor: "pointer", display: "flex", alignItems: "center", gap: 8, transition: "all 0.2s", whiteSpace: "nowrap",
  }}>
    {Icon && <Icon size={15} />}{children}
    {count !== undefined && <span style={{ background: active ? COLORS.accent : COLORS.border, color: active ? COLORS.bg : COLORS.textDim, padding: "1px 7px", borderRadius: 10, fontSize: 11, fontWeight: 700 }}>{count}</span>}
  </button>
);

// ==========================
// MAIN SECTIONS
// ==========================

// 1. STOREFRONT
const StoreFront = ({ cart, setCart, wishlist, setWishlist }) => {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [view, setView] = useState("grid");
  const [sortBy, setSortBy] = useState("trending");
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [qty, setQty] = useState(1);

  const filtered = useMemo(() => {
    let items = PRODUCTS.filter(p => (category === "All" || p.category === category) && (p.name.toLowerCase().includes(search.toLowerCase()) || p.tags.some(t => t.includes(search.toLowerCase()))));
    if (sortBy === "trending") items.sort((a, b) => b.sales - a.sales);
    if (sortBy === "price-low") items.sort((a, b) => a.price - b.price);
    if (sortBy === "price-high") items.sort((a, b) => b.price - a.price);
    if (sortBy === "rating") items.sort((a, b) => b.rating - a.rating);
    return items;
  }, [search, category, sortBy]);

  const addToCart = (product, quantity = 1) => {
    setCart(prev => {
      const existing = prev.find(i => i.id === product.id);
      if (existing) return prev.map(i => i.id === product.id ? { ...i, qty: i.qty + quantity } : i);
      return [...prev, { ...product, qty: quantity }];
    });
  };

  if (selectedProduct) {
    const p = selectedProduct;
    return (
      <div style={{ animation: "fadeIn 0.3s ease" }}>
        <button onClick={() => { setSelectedProduct(null); setQty(1); }} style={{ background: "none", border: "none", color: COLORS.accent, cursor: "pointer", display: "flex", alignItems: "center", gap: 6, marginBottom: 24, fontSize: 14 }}>
          <ArrowLeft size={16} /> Back to catalog
        </button>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 40 }}>
          <div style={{ background: COLORS.bgCard, borderRadius: 24, display: "flex", alignItems: "center", justifyContent: "center", minHeight: 400, fontSize: 120, border: `1px solid ${COLORS.border}` }}>
            {p.image}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", gap: 8 }}>{p.trending && <Badge color={COLORS.danger} glow>🔥 TRENDING</Badge>}<Badge>{p.category}</Badge></div>
            <h2 style={{ fontSize: 32, fontWeight: 800, color: COLORS.text, fontFamily: "'Orbitron', sans-serif", margin: 0, lineHeight: 1.2 }}>{p.name}</h2>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ display: "flex", gap: 2 }}>{[...Array(5)].map((_, i) => <Star key={i} size={16} fill={i < Math.floor(p.rating) ? "#ffaa00" : "none"} color="#ffaa00" />)}</div>
              <span style={{ color: COLORS.textDim, fontSize: 14 }}>{p.rating} ({p.reviews} reviews)</span>
            </div>
            <div style={{ fontSize: 40, fontWeight: 900, color: COLORS.accent, fontFamily: "'Orbitron', sans-serif" }}>${p.price.toLocaleString()}</div>
            <p style={{ color: COLORS.textDim, lineHeight: 1.7 }}>Premium-grade component sourced directly from verified manufacturer ({p.supplier}). Ships worldwide with tracking. Backed by NEXUS quality guarantee and 30-day returns.</p>
            <div style={{ display: "flex", gap: 8, alignItems: "center", padding: "12px 0" }}>
              <span style={{ color: COLORS.textDim, fontSize: 13 }}>QTY:</span>
              <button onClick={() => setQty(Math.max(1, qty - 1))} style={{ width: 36, height: 36, borderRadius: 8, background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, color: COLORS.text, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><Minus size={14} /></button>
              <span style={{ width: 40, textAlign: "center", fontWeight: 700, color: COLORS.text }}>{qty}</span>
              <button onClick={() => setQty(qty + 1)} style={{ width: 36, height: 36, borderRadius: 8, background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, color: COLORS.text, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><Plus size={14} /></button>
            </div>
            <div style={{ display: "flex", gap: 12 }}>
              <button onClick={() => { addToCart(p, qty); setSelectedProduct(null); setQty(1); }} style={{ flex: 1, padding: "14px 28px", background: COLORS.gradient, border: "none", borderRadius: 12, color: COLORS.bg, fontWeight: 800, fontSize: 15, cursor: "pointer", letterSpacing: "1px" }}>ADD TO CART — ${(p.price * qty).toLocaleString()}</button>
              <button onClick={() => setWishlist(prev => prev.includes(p.id) ? prev.filter(x => x !== p.id) : [...prev, p.id])} style={{ width: 50, height: 50, borderRadius: 12, background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, color: wishlist.includes(p.id) ? COLORS.danger : COLORS.textDim, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Heart size={20} fill={wishlist.includes(p.id) ? COLORS.danger : "none"} />
              </button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginTop: 12 }}>
              {[["🚀", "Fast Shipping", "5-10 days"], ["🛡️", "Guaranteed", "30-day returns"], ["📦", "Stock", `${p.stock} units`]].map(([icon, t, s]) => (
                <div key={t} style={{ padding: 14, background: COLORS.bgCard, borderRadius: 12, border: `1px solid ${COLORS.border}`, textAlign: "center" }}>
                  <div style={{ fontSize: 20 }}>{icon}</div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: COLORS.text, marginTop: 4 }}>{t}</div>
                  <div style={{ fontSize: 11, color: COLORS.textDim }}>{s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Hero Banner */}
      <div style={{ background: `linear-gradient(135deg, #0a0a2e, #1a0a3e)`, borderRadius: 20, padding: "40px 48px", marginBottom: 32, position: "relative", overflow: "hidden", border: `1px solid ${COLORS.border}` }}>
        <div style={{ position: "absolute", top: 0, right: 0, width: "50%", height: "100%", background: "radial-gradient(circle at 70% 50%, #00f0ff08, transparent 60%)" }} />
        <Badge color={COLORS.danger} glow>⚡ FLASH DEALS — UP TO 40% OFF</Badge>
        <h2 style={{ fontSize: 36, fontWeight: 900, color: COLORS.text, margin: "16px 0 8px", fontFamily: "'Orbitron', sans-serif" }}>NEXUS CATALOG</h2>
        <p style={{ color: COLORS.textDim, fontSize: 15, maxWidth: 500, lineHeight: 1.6 }}>Enterprise-grade hardware. Factory-direct pricing. Global dropship fulfillment. Access 12,000+ products from verified manufacturers.</p>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap", alignItems: "center" }}>
        <SearchBar value={search} onChange={setSearch} placeholder="Search products, tags..." />
        <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{ padding: "10px 14px", background: COLORS.bgCard, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 13 }}>
          <option value="trending">🔥 Trending</option>
          <option value="price-low">💰 Price: Low → High</option>
          <option value="price-high">💎 Price: High → Low</option>
          <option value="rating">⭐ Top Rated</option>
        </select>
        <div style={{ display: "flex", gap: 4 }}>
          <button onClick={() => setView("grid")} style={{ padding: 8, background: view === "grid" ? COLORS.accentDim : "transparent", border: `1px solid ${view === "grid" ? COLORS.accent : COLORS.border}`, borderRadius: 8, color: view === "grid" ? COLORS.accent : COLORS.textDim, cursor: "pointer" }}><Grid size={16} /></button>
          <button onClick={() => setView("list")} style={{ padding: 8, background: view === "list" ? COLORS.accentDim : "transparent", border: `1px solid ${view === "list" ? COLORS.accent : COLORS.border}`, borderRadius: 8, color: view === "list" ? COLORS.accent : COLORS.textDim, cursor: "pointer" }}><List size={16} /></button>
        </div>
      </div>

      {/* Categories */}
      <div style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        {CATEGORIES.map(c => (
          <button key={c} onClick={() => setCategory(c)} style={{
            padding: "6px 16px", borderRadius: 20, fontSize: 12, fontWeight: 600, cursor: "pointer", border: `1px solid ${category === c ? COLORS.accent : COLORS.border}`,
            background: category === c ? COLORS.accentDim : "transparent", color: category === c ? COLORS.accent : COLORS.textDim, transition: "all 0.2s"
          }}>{c}</button>
        ))}
      </div>

      {/* Products Grid */}
      <div style={{ display: "grid", gridTemplateColumns: view === "grid" ? "repeat(auto-fill, minmax(240px, 1fr))" : "1fr", gap: 16 }}>
        {filtered.map(p => (
          <div key={p.id} onClick={() => setSelectedProduct(p)} style={{
            background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, overflow: "hidden", cursor: "pointer",
            transition: "all 0.2s", display: view === "list" ? "flex" : "block",
          }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = COLORS.accent + "66"; e.currentTarget.style.transform = "translateY(-2px)"; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = COLORS.border; e.currentTarget.style.transform = "none"; }}
          >
            <div style={{ background: COLORS.bgHover, display: "flex", alignItems: "center", justifyContent: "center", height: view === "grid" ? 160 : 100, width: view === "list" ? 120 : "auto", fontSize: view === "grid" ? 60 : 40, position: "relative", flexShrink: 0 }}>
              {p.image}
              {p.trending && <span style={{ position: "absolute", top: 10, left: 10, background: COLORS.danger + "dd", color: "#fff", padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700 }}>🔥 HOT</span>}
              <button onClick={e => { e.stopPropagation(); setWishlist(prev => prev.includes(p.id) ? prev.filter(x => x !== p.id) : [...prev, p.id]); }} style={{ position: "absolute", top: 10, right: 10, width: 30, height: 30, borderRadius: "50%", background: COLORS.bg + "cc", border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Heart size={14} fill={wishlist.includes(p.id) ? COLORS.danger : "none"} color={wishlist.includes(p.id) ? COLORS.danger : COLORS.textDim} />
              </button>
            </div>
            <div style={{ padding: 16 }}>
              <div style={{ fontSize: 10, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "1px", marginBottom: 4 }}>{p.category}</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, marginBottom: 8, lineHeight: 1.3 }}>{p.name}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                <Star size={12} fill="#ffaa00" color="#ffaa00" /><span style={{ fontSize: 12, color: COLORS.textDim }}>{p.rating} ({p.reviews})</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 20, fontWeight: 900, color: COLORS.accent, fontFamily: "'Orbitron', sans-serif" }}>${p.price}</span>
                <button onClick={e => { e.stopPropagation(); addToCart(p); }} style={{ width: 36, height: 36, borderRadius: 10, background: COLORS.gradient, border: "none", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Plus size={16} color={COLORS.bg} />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
      {filtered.length === 0 && <div style={{ textAlign: "center", padding: 60, color: COLORS.textDim }}>No products found. Try different search terms.</div>}
    </div>
  );
};

// 2. AGENT MANAGEMENT DASHBOARD
const AgentDashboard = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [searchAgent, setSearchAgent] = useState("");

  const totalRevenue = AGENTS.reduce((s, a) => s + a.revenue, 0);
  const totalCommissions = AGENTS.reduce((s, a) => s + a.commission, 0);
  const totalOrders = AGENTS.reduce((s, a) => s + a.orders, 0);

  const filteredAgents = AGENTS.filter(a => a.name.toLowerCase().includes(searchAgent.toLowerCase()) || a.region.toLowerCase().includes(searchAgent.toLowerCase()));

  const getSubAgents = (parentId) => AGENTS.filter(a => a.parent === parentId);

  const AgentTree = ({ agent, depth = 0 }) => {
    const subs = getSubAgents(agent.id);
    return (
      <div style={{ marginLeft: depth * 28 }}>
        <div onClick={() => setSelectedAgent(agent)} style={{
          display: "flex", alignItems: "center", gap: 12, padding: "12px 16px", background: selectedAgent?.id === agent.id ? COLORS.accentDim : COLORS.bgCard,
          borderRadius: 12, border: `1px solid ${selectedAgent?.id === agent.id ? COLORS.accent : COLORS.border}`, marginBottom: 6, cursor: "pointer", transition: "all 0.2s"
        }}>
          {depth > 0 && <div style={{ width: 20, borderLeft: `2px solid ${COLORS.accent}33`, borderBottom: `2px solid ${COLORS.accent}33`, height: 12, marginLeft: -14 }} />}
          <div style={{ width: 36, height: 36, borderRadius: "50%", background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 14, color: COLORS.bg, flexShrink: 0 }}>
            {agent.name.split(" ").map(n => n[0]).join("")}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontWeight: 700, color: COLORS.text, fontSize: 13 }}>{agent.name}</span>
              <StatusDot status={agent.status} />
            </div>
            <div style={{ fontSize: 11, color: COLORS.textDim }}>{agent.level} · {agent.region}</div>
          </div>
          <div style={{ textAlign: "right" }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: COLORS.accent, fontFamily: "'Orbitron', sans-serif" }}>${(agent.revenue / 1000).toFixed(0)}K</div>
            <Badge color={agent.tier === "platinum" ? "#00f0ff" : agent.tier === "gold" ? "#ffaa00" : agent.tier === "silver" ? "#aaaacc" : "#cd7f32"}>{agent.tier}</Badge>
          </div>
        </div>
        {subs.map(s => <AgentTree key={s.id} agent={s} depth={depth + 1} />)}
      </div>
    );
  };

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
        <TabBtn active={activeTab === "overview"} onClick={() => setActiveTab("overview")} icon={BarChart3}>Overview</TabBtn>
        <TabBtn active={activeTab === "hierarchy"} onClick={() => setActiveTab("hierarchy")} icon={Users}>Hierarchy</TabBtn>
        <TabBtn active={activeTab === "commissions"} onClick={() => setActiveTab("commissions")} icon={DollarSign}>Commissions</TabBtn>
        <TabBtn active={activeTab === "recruitment"} onClick={() => setActiveTab("recruitment")} icon={Plus}>Recruit Agent</TabBtn>
        <TabBtn active={activeTab === "tiers"} onClick={() => setActiveTab("tiers")} icon={Award}>Tier Program</TabBtn>
      </div>

      {activeTab === "overview" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
            <StatCard icon={Users} label="Total Agents" value={AGENTS.length} change={18} color={COLORS.accent} />
            <StatCard icon={DollarSign} label="Network Revenue" value={`$${(totalRevenue / 1000).toFixed(0)}K`} change={24} color={COLORS.success} />
            <StatCard icon={Percent} label="Total Commissions" value={`$${(totalCommissions / 1000).toFixed(0)}K`} change={21} color="#7b61ff" />
            <StatCard icon={Package} label="Network Orders" value={totalOrders.toLocaleString()} change={15} color={COLORS.warning} />
          </div>

          {/* Agent Performance Table */}
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: COLORS.text }}>Agent Performance Leaderboard</h3>
              <SearchBar value={searchAgent} onChange={setSearchAgent} placeholder="Search agents..." />
            </div>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                    {["#", "Agent", "Level", "Region", "Revenue", "Commission", "Orders", "Sub-Agents", "Tier", "Status"].map(h => (
                      <th key={h} style={{ padding: "12px 16px", textAlign: "left", fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "1px", fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredAgents.sort((a, b) => b.revenue - a.revenue).map((a, i) => (
                    <tr key={a.id} onClick={() => setSelectedAgent(a)} style={{ borderBottom: `1px solid ${COLORS.border}`, cursor: "pointer", transition: "background 0.2s" }}
                      onMouseEnter={e => e.currentTarget.style.background = COLORS.bgHover}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                      <td style={{ padding: "12px 16px", fontSize: 13, color: COLORS.textDim, fontWeight: 700 }}>{i + 1}</td>
                      <td style={{ padding: "12px 16px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                          <div style={{ width: 32, height: 32, borderRadius: "50%", background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 12, color: COLORS.bg }}>{a.name.split(" ").map(n => n[0]).join("")}</div>
                          <span style={{ fontWeight: 600, color: COLORS.text, fontSize: 13 }}>{a.name}</span>
                        </div>
                      </td>
                      <td style={{ padding: "12px 16px", fontSize: 13, color: COLORS.textDim }}>{a.level}</td>
                      <td style={{ padding: "12px 16px", fontSize: 13, color: COLORS.textDim }}>{a.region}</td>
                      <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 700, color: COLORS.success, fontFamily: "'Orbitron', sans-serif" }}>${a.revenue.toLocaleString()}</td>
                      <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 700, color: COLORS.accent }}>${a.commission.toLocaleString()}</td>
                      <td style={{ padding: "12px 16px", fontSize: 13, color: COLORS.text }}>{a.orders}</td>
                      <td style={{ padding: "12px 16px", fontSize: 13, color: COLORS.text }}>{a.subAgents}</td>
                      <td style={{ padding: "12px 16px" }}><Badge color={a.tier === "platinum" ? "#00f0ff" : a.tier === "gold" ? "#ffaa00" : a.tier === "silver" ? "#aaaacc" : "#cd7f32"}>{a.tier}</Badge></td>
                      <td style={{ padding: "12px 16px" }}><StatusDot status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === "hierarchy" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
          <div>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, marginBottom: 16 }}>🌐 Organization Tree</h3>
            {AGENTS.filter(a => !a.parent).map(a => <AgentTree key={a.id} agent={a} />)}
          </div>
          <div>
            {selectedAgent ? (
              <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24, position: "sticky", top: 20 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
                  <div style={{ width: 56, height: 56, borderRadius: "50%", background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 20, color: COLORS.bg }}>
                    {selectedAgent.name.split(" ").map(n => n[0]).join("")}
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: COLORS.text }}>{selectedAgent.name}</h3>
                    <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                      <Badge>{selectedAgent.level}</Badge>
                      <Badge color={selectedAgent.tier === "platinum" ? "#00f0ff" : selectedAgent.tier === "gold" ? "#ffaa00" : "#aaaacc"}>{selectedAgent.tier}</Badge>
                    </div>
                  </div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
                  {[
                    ["Revenue", `$${selectedAgent.revenue.toLocaleString()}`, COLORS.success],
                    ["Commission", `$${selectedAgent.commission.toLocaleString()}`, COLORS.accent],
                    ["Orders", selectedAgent.orders, COLORS.warning],
                    ["Sub-Agents", selectedAgent.subAgents, "#7b61ff"],
                  ].map(([label, val, c]) => (
                    <div key={label} style={{ padding: 14, background: COLORS.bgHover, borderRadius: 12, textAlign: "center" }}>
                      <div style={{ fontSize: 18, fontWeight: 800, color: c, fontFamily: "'Orbitron', sans-serif" }}>{val}</div>
                      <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 2 }}>{label}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {[["📧", "Email", selectedAgent.email], ["🌍", "Region", selectedAgent.region], ["📅", "Member Since", selectedAgent.since]].map(([icon, label, val]) => (
                    <div key={label} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: `1px solid ${COLORS.border}` }}>
                      <span style={{ fontSize: 13, color: COLORS.textDim }}>{icon} {label}</span>
                      <span style={{ fontSize: 13, color: COLORS.text, fontWeight: 600 }}>{val}</span>
                    </div>
                  ))}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 20 }}>
                  <button style={{ flex: 1, padding: "10px", background: COLORS.gradient, border: "none", borderRadius: 10, color: COLORS.bg, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>✉️ Message</button>
                  <button style={{ flex: 1, padding: "10px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontWeight: 700, fontSize: 13, cursor: "pointer" }}>📊 Full Report</button>
                </div>
              </div>
            ) : (
              <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 40, textAlign: "center", color: COLORS.textDim }}>
                <Users size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
                <p>Select an agent from the tree to view details</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === "commissions" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
            <StatCard icon={DollarSign} label="Paid This Month" value="$87.4K" change={12} color={COLORS.success} />
            <StatCard icon={Clock} label="Pending Payout" value="$23.1K" color={COLORS.warning} />
            <StatCard icon={TrendingUp} label="Avg Commission Rate" value="7.8%" change={5} color="#7b61ff" />
          </div>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
            <div style={{ padding: "16px 20px", borderBottom: `1px solid ${COLORS.border}` }}>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: COLORS.text }}>Commission Breakdown</h3>
            </div>
            {AGENTS.sort((a, b) => b.commission - a.commission).map(a => (
              <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 16, padding: "14px 20px", borderBottom: `1px solid ${COLORS.border}` }}>
                <div style={{ width: 36, height: 36, borderRadius: "50%", background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 12, color: COLORS.bg, flexShrink: 0 }}>
                  {a.name.split(" ").map(n => n[0]).join("")}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, color: COLORS.text, fontSize: 13 }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: COLORS.textDim }}>{a.level} · {a.region}</div>
                </div>
                <div style={{ width: 200 }}>
                  <ProgressBar value={a.commission} max={50000} color={COLORS.accent} />
                  <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 4 }}>{((a.commission / a.revenue) * 100).toFixed(1)}% rate</div>
                </div>
                <div style={{ textAlign: "right", minWidth: 100 }}>
                  <div style={{ fontSize: 16, fontWeight: 800, color: COLORS.success, fontFamily: "'Orbitron', sans-serif" }}>${a.commission.toLocaleString()}</div>
                  <div style={{ fontSize: 11, color: COLORS.textDim }}>of ${a.revenue.toLocaleString()}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "recruitment" && (
        <div style={{ maxWidth: 700 }}>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 32 }}>
            <h3 style={{ fontSize: 20, fontWeight: 800, color: COLORS.text, margin: "0 0 8px", fontFamily: "'Orbitron', sans-serif" }}>➕ Recruit New Agent</h3>
            <p style={{ color: COLORS.textDim, fontSize: 14, marginBottom: 24 }}>Onboard a new agent or sub-agent into the NEXUS network. They'll receive login credentials and training materials automatically.</p>
            {[
              ["Full Name", "text", "e.g. John Smith"],
              ["Email Address", "email", "e.g. john@example.com"],
              ["Phone Number", "tel", "e.g. +1 555 123 4567"],
              ["Region / Territory", "text", "e.g. Southeast Asia"],
            ].map(([label, type, ph]) => (
              <div key={label} style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "1px" }}>{label}</label>
                <input type={type} placeholder={ph} style={{ width: "100%", padding: "12px 16px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
              </div>
            ))}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "1px" }}>Role Level</label>
              <select style={{ width: "100%", padding: "12px 16px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, boxSizing: "border-box" }}>
                <option>Sub-Agent</option><option>Agent</option><option>Senior Agent</option><option>Director</option>
              </select>
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "1px" }}>Assign to Parent Agent</label>
              <select style={{ width: "100%", padding: "12px 16px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, boxSizing: "border-box" }}>
                {AGENTS.filter(a => a.level !== "Sub-Agent").map(a => <option key={a.id}>{a.name} ({a.level} — {a.region})</option>)}
              </select>
            </div>
            <button style={{ width: "100%", padding: "14px", background: COLORS.gradient, border: "none", borderRadius: 12, color: COLORS.bg, fontWeight: 800, fontSize: 15, cursor: "pointer", letterSpacing: "1px", marginTop: 8 }}>🚀 SEND INVITATION</button>
          </div>
        </div>
      )}

      {activeTab === "tiers" && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {COMMISSION_TIERS.map((t, i) => (
            <div key={t.tier} style={{
              background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${i === 3 ? COLORS.accent : COLORS.border}`, padding: 24,
              position: "relative", overflow: "hidden",
              boxShadow: i === 3 ? COLORS.accentGlow : "none",
            }}>
              {i === 3 && <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 3, background: COLORS.gradient }} />}
              <div style={{ fontSize: 36, marginBottom: 8 }}>{t.icon}</div>
              <h4 style={{ fontSize: 18, fontWeight: 800, color: COLORS.text, margin: "0 0 4px", fontFamily: "'Orbitron', sans-serif" }}>{t.tier}</h4>
              <div style={{ fontSize: 12, color: COLORS.textDim, marginBottom: 16 }}>Min Revenue: ${t.minRevenue > 0 ? `${(t.minRevenue / 1000)}K` : "None"}</div>
              <div style={{ padding: "12px 0", borderTop: `1px solid ${COLORS.border}`, borderBottom: `1px solid ${COLORS.border}`, marginBottom: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ fontSize: 13, color: COLORS.textDim }}>Commission Rate</span>
                  <span style={{ fontSize: 16, fontWeight: 800, color: COLORS.accent }}>{t.rate}%</span>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 13, color: COLORS.textDim }}>Override Bonus</span>
                  <span style={{ fontSize: 16, fontWeight: 800, color: COLORS.success }}>{t.override}%</span>
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {t.perks.map(p => (
                  <div key={p} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: COLORS.textDim }}>
                    <Check size={14} color={COLORS.success} />{p}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// 3. ORDER MANAGEMENT
const OrderManagement = () => {
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchOrder, setSearchOrder] = useState("");

  const statusColors = { delivered: COLORS.success, shipped: COLORS.accent, processing: COLORS.warning, pending: COLORS.textDim };
  const filtered = ORDERS.filter(o => (statusFilter === "all" || o.status === statusFilter) && (o.id.toLowerCase().includes(searchOrder.toLowerCase()) || o.customer.toLowerCase().includes(searchOrder.toLowerCase()) || o.product.toLowerCase().includes(searchOrder.toLowerCase())));

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
        <StatCard icon={Package} label="Total Orders" value={ORDERS.length} change={12} color={COLORS.accent} />
        <StatCard icon={Truck} label="Shipped" value={ORDERS.filter(o => o.status === "shipped").length} color={COLORS.accent} />
        <StatCard icon={Check} label="Delivered" value={ORDERS.filter(o => o.status === "delivered").length} color={COLORS.success} />
        <StatCard icon={Clock} label="Processing" value={ORDERS.filter(o => o.status === "processing" || o.status === "pending").length} color={COLORS.warning} />
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 20, alignItems: "center" }}>
        <SearchBar value={searchOrder} onChange={setSearchOrder} placeholder="Search orders, customers..." />
        <div style={{ display: "flex", gap: 6 }}>
          {["all", "pending", "processing", "shipped", "delivered"].map(s => (
            <button key={s} onClick={() => setStatusFilter(s)} style={{
              padding: "8px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer",
              background: statusFilter === s ? (statusColors[s] || COLORS.accent) + "22" : "transparent",
              border: `1px solid ${statusFilter === s ? (statusColors[s] || COLORS.accent) : COLORS.border}`,
              color: statusFilter === s ? (statusColors[s] || COLORS.accent) : COLORS.textDim, textTransform: "capitalize"
            }}>{s}</button>
          ))}
        </div>
      </div>

      <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
              {["Order ID", "Customer", "Product", "Agent", "Supplier", "Status", "Date", "Total", "Tracking"].map(h => (
                <th key={h} style={{ padding: "12px 14px", textAlign: "left", fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "1px", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(o => (
              <tr key={o.id} style={{ borderBottom: `1px solid ${COLORS.border}`, transition: "background 0.2s" }}
                onMouseEnter={e => e.currentTarget.style.background = COLORS.bgHover}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <td style={{ padding: "12px 14px", fontSize: 13, fontWeight: 700, color: COLORS.accent, fontFamily: "monospace" }}>{o.id}</td>
                <td style={{ padding: "12px 14px", fontSize: 13, color: COLORS.text }}>{o.customer}</td>
                <td style={{ padding: "12px 14px", fontSize: 13, color: COLORS.text, maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{o.product}</td>
                <td style={{ padding: "12px 14px", fontSize: 13, color: COLORS.textDim }}>{o.agent}</td>
                <td style={{ padding: "12px 14px", fontSize: 12, color: COLORS.textDim }}>{o.supplier}</td>
                <td style={{ padding: "12px 14px" }}><Badge color={statusColors[o.status]}>{o.status}</Badge></td>
                <td style={{ padding: "12px 14px", fontSize: 12, color: COLORS.textDim }}>{o.date}</td>
                <td style={{ padding: "12px 14px", fontSize: 14, fontWeight: 700, color: COLORS.success }}>${o.total}</td>
                <td style={{ padding: "12px 14px", fontSize: 11, color: COLORS.accent, fontFamily: "monospace" }}>{o.tracking || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// 4. SUPPLIER / DROPSHIP MANAGEMENT
const SupplierManagement = () => {
  const [activeTab, setActiveTab] = useState("suppliers");

  return (
    <div>
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <TabBtn active={activeTab === "suppliers"} onClick={() => setActiveTab("suppliers")} icon={Globe}>Suppliers</TabBtn>
        <TabBtn active={activeTab === "fulfillment"} onClick={() => setActiveTab("fulfillment")} icon={Truck}>Fulfillment Pipeline</TabBtn>
        <TabBtn active={activeTab === "sourcing"} onClick={() => setActiveTab("sourcing")} icon={Search}>Product Sourcing</TabBtn>
        <TabBtn active={activeTab === "quality"} onClick={() => setActiveTab("quality")} icon={Shield}>Quality Control</TabBtn>
      </div>

      {activeTab === "suppliers" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
            <StatCard icon={Globe} label="Active Suppliers" value={SUPPLIERS.filter(s => s.status === "verified").length} color={COLORS.accent} />
            <StatCard icon={Package} label="Total Products" value={SUPPLIERS.reduce((s, x) => s + x.products, 0)} color={COLORS.success} />
            <StatCard icon={Truck} label="Avg On-Time Rate" value={`${(SUPPLIERS.reduce((s, x) => s + x.onTime, 0) / SUPPLIERS.length).toFixed(1)}%`} color={COLORS.warning} />
            <StatCard icon={RefreshCw} label="Avg Return Rate" value={`${(SUPPLIERS.reduce((s, x) => s + x.returns, 0) / SUPPLIERS.length).toFixed(1)}%`} color={COLORS.danger} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            {SUPPLIERS.map(s => (
              <div key={s.id} style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", marginBottom: 16 }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <h4 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: COLORS.text }}>{s.name}</h4>
                      <Badge color={s.status === "verified" ? COLORS.success : COLORS.warning}>{s.status === "verified" ? "✓ Verified" : "⏳ Pending"}</Badge>
                    </div>
                    <div style={{ fontSize: 13, color: COLORS.textDim, marginTop: 4 }}>📍 {s.country}</div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <Star size={14} fill="#ffaa00" color="#ffaa00" />
                    <span style={{ fontSize: 14, fontWeight: 700, color: COLORS.text }}>{s.rating}</span>
                  </div>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                  {[
                    ["Products", s.products, COLORS.accent],
                    ["Orders", s.orders.toLocaleString(), COLORS.success],
                    ["On-Time", `${s.onTime}%`, s.onTime > 95 ? COLORS.success : COLORS.warning],
                    ["Returns", `${s.returns}%`, s.returns < 2 ? COLORS.success : COLORS.danger],
                  ].map(([l, v, c]) => (
                    <div key={l} style={{ textAlign: "center", padding: 8, background: COLORS.bgHover, borderRadius: 8 }}>
                      <div style={{ fontSize: 16, fontWeight: 800, color: c }}>{v}</div>
                      <div style={{ fontSize: 10, color: COLORS.textDim, marginTop: 2 }}>{l}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
                  <button style={{ flex: 1, padding: "8px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text, fontSize: 12, fontWeight: 600, cursor: "pointer" }}>📦 View Products</button>
                  <button style={{ flex: 1, padding: "8px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text, fontSize: 12, fontWeight: 600, cursor: "pointer" }}>💬 Contact</button>
                  <button style={{ flex: 1, padding: "8px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text, fontSize: 12, fontWeight: 600, cursor: "pointer" }}>📊 Analytics</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "fulfillment" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12, marginBottom: 24 }}>
            {[
              ["Order Placed", "📋", 3, COLORS.textDim],
              ["Sent to Supplier", "📤", 2, COLORS.warning],
              ["In Production", "🏭", 4, "#7b61ff"],
              ["Shipped", "🚢", 5, COLORS.accent],
              ["Delivered", "✅", 12, COLORS.success],
            ].map(([label, icon, count, color]) => (
              <div key={label} style={{ background: COLORS.bgCard, borderRadius: 14, border: `1px solid ${COLORS.border}`, padding: 20, textAlign: "center", position: "relative" }}>
                <div style={{ fontSize: 28 }}>{icon}</div>
                <div style={{ fontSize: 24, fontWeight: 900, color, fontFamily: "'Orbitron', sans-serif", margin: "8px 0" }}>{count}</div>
                <div style={{ fontSize: 11, color: COLORS.textDim, textTransform: "uppercase", letterSpacing: "1px" }}>{label}</div>
              </div>
            ))}
          </div>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>Fulfillment Workflow</h3>
            <div style={{ display: "flex", alignItems: "center", gap: 0, justifyContent: "space-between" }}>
              {["Customer Orders", "Auto-Route to Supplier", "Quality Check", "Pack & Ship", "Tracking Push", "Delivery Confirm"].map((step, i) => (
                <div key={step} style={{ display: "flex", alignItems: "center", flex: 1 }}>
                  <div style={{ textAlign: "center", flex: 1 }}>
                    <div style={{ width: 40, height: 40, borderRadius: "50%", background: i < 4 ? COLORS.accent + "22" : COLORS.bgHover, border: `2px solid ${i < 4 ? COLORS.accent : COLORS.border}`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 8px", fontSize: 14, fontWeight: 800, color: i < 4 ? COLORS.accent : COLORS.textDim }}>{i + 1}</div>
                    <div style={{ fontSize: 10, color: i < 4 ? COLORS.text : COLORS.textDim, textTransform: "uppercase", letterSpacing: "0.5px" }}>{step}</div>
                  </div>
                  {i < 5 && <div style={{ width: 30, height: 2, background: i < 3 ? COLORS.accent : COLORS.border, flexShrink: 0 }} />}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === "sourcing" && (
        <div style={{ maxWidth: 700 }}>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 32 }}>
            <h3 style={{ fontSize: 20, fontWeight: 800, color: COLORS.text, margin: "0 0 8px", fontFamily: "'Orbitron', sans-serif" }}>🔍 Product Sourcing Request</h3>
            <p style={{ color: COLORS.textDim, fontSize: 14, marginBottom: 24 }}>Submit a sourcing request and our supplier network will find the best products at factory-direct prices. Average turnaround: 24-48 hours.</p>
            {[
              ["Product Name / Description", "text", "e.g. USB-C Hub 10-in-1 Aluminum"],
              ["Target Price Range (USD)", "text", "e.g. $15 - $25"],
              ["Minimum Order Quantity", "number", "e.g. 100"],
              ["Reference URL (AliExpress, Amazon, etc.)", "url", "Paste product URL here"],
            ].map(([label, type, ph]) => (
              <div key={label} style={{ marginBottom: 16 }}>
                <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "1px" }}>{label}</label>
                <input type={type} placeholder={ph} style={{ width: "100%", padding: "12px 16px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, outline: "none", boxSizing: "border-box" }} />
              </div>
            ))}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: "block", fontSize: 12, color: COLORS.textDim, marginBottom: 6, textTransform: "uppercase", letterSpacing: "1px" }}>Special Requirements</label>
              <textarea rows={3} placeholder="Custom branding, packaging, certifications, etc." style={{ width: "100%", padding: "12px 16px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 14, outline: "none", resize: "vertical", boxSizing: "border-box", fontFamily: "inherit" }} />
            </div>
            <button style={{ width: "100%", padding: "14px", background: COLORS.gradient, border: "none", borderRadius: 12, color: COLORS.bg, fontWeight: 800, fontSize: 15, cursor: "pointer", letterSpacing: "1px" }}>📨 SUBMIT SOURCING REQUEST</button>
          </div>
        </div>
      )}

      {activeTab === "quality" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>🛡️ QC Process</h3>
            {[
              ["Pre-Production Inspection", "Check materials and specs before manufacturing", COLORS.accent],
              ["During Production (DUPRO)", "Random sampling during production run", "#7b61ff"],
              ["Pre-Shipment Inspection", "Final QC before goods leave factory", COLORS.warning],
              ["Loading Supervision", "Verify quantity and condition at loading", COLORS.success],
            ].map(([title, desc, color], i) => (
              <div key={title} style={{ display: "flex", gap: 14, marginBottom: 16 }}>
                <div style={{ width: 36, height: 36, borderRadius: "50%", background: color + "22", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 14, color, flexShrink: 0, border: `2px solid ${color}` }}>{i + 1}</div>
                <div>
                  <div style={{ fontWeight: 700, color: COLORS.text, fontSize: 14 }}>{title}</div>
                  <div style={{ fontSize: 12, color: COLORS.textDim, marginTop: 2 }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>📊 QC Stats (Last 30 Days)</h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {[
                ["Inspections Done", "142", COLORS.accent],
                ["Pass Rate", "96.4%", COLORS.success],
                ["Defect Reports", "8", COLORS.danger],
                ["Avg Resolution", "2.3 days", COLORS.warning],
              ].map(([l, v, c]) => (
                <div key={l} style={{ padding: 16, background: COLORS.bgHover, borderRadius: 12, textAlign: "center" }}>
                  <div style={{ fontSize: 24, fontWeight: 900, color: c, fontFamily: "'Orbitron', sans-serif" }}>{v}</div>
                  <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 4 }}>{l}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// 5. ANALYTICS DASHBOARD
const Analytics = () => (
  <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
      <StatCard icon={DollarSign} label="Total Revenue" value="$1.68M" change={24} color={COLORS.success} />
      <StatCard icon={TrendingUp} label="Gross Margin" value="42.3%" change={3} color={COLORS.accent} />
      <StatCard icon={Users} label="Active Customers" value="12,847" change={18} color="#7b61ff" />
      <StatCard icon={Globe} label="Countries Served" value="47" change={8} color={COLORS.warning} />
    </div>

    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
      {/* Revenue Chart Placeholder */}
      <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>📈 Revenue Trend (6 Months)</h3>
        <div style={{ display: "flex", alignItems: "flex-end", gap: 8, height: 160 }}>
          {[180, 210, 245, 290, 320, 380].map((v, i) => (
            <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 11, color: COLORS.accent, fontWeight: 700 }}>${v}K</span>
              <div style={{ width: "100%", height: `${(v / 400) * 140}px`, background: `linear-gradient(180deg, ${COLORS.accent}, ${COLORS.accent}44)`, borderRadius: "6px 6px 0 0", transition: "height 0.5s ease" }} />
              <span style={{ fontSize: 10, color: COLORS.textDim }}>{["Sep", "Oct", "Nov", "Dec", "Jan", "Feb"][i]}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Top Products */}
      <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>🏆 Top Products</h3>
        {PRODUCTS.sort((a, b) => b.sales - a.sales).slice(0, 5).map((p, i) => (
          <div key={p.id} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: i < 3 ? COLORS.accent : COLORS.textDim, width: 20 }}>#{i + 1}</span>
            <span style={{ fontSize: 22 }}>{p.image}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</div>
              <div style={{ fontSize: 11, color: COLORS.textDim }}>{p.sales.toLocaleString()} sales</div>
            </div>
          </div>
        ))}
      </div>
    </div>

    {/* Geography / Agent Performance */}
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
      <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>🌍 Revenue by Region</h3>
        {[
          ["North America", 458000, 35],
          ["Europe", 345000, 26],
          ["Asia Pacific", 367000, 28],
          ["Middle East", 78000, 6],
          ["Latin America", 43000, 5],
        ].map(([region, rev, pct]) => (
          <div key={region} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 13, color: COLORS.text }}>{region}</span>
              <span style={{ fontSize: 13, color: COLORS.accent, fontWeight: 700 }}>${(rev / 1000).toFixed(0)}K ({pct}%)</span>
            </div>
            <ProgressBar value={pct} max={40} color={COLORS.accent} />
          </div>
        ))}
      </div>
      <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>📦 Fulfillment Metrics</h3>
        {[
          ["Avg Processing Time", "1.8 days", COLORS.success, 90],
          ["Avg Shipping Time", "7.2 days", COLORS.accent, 72],
          ["Customer Satisfaction", "4.7 / 5.0", COLORS.warning, 94],
          ["Return Rate", "2.1%", COLORS.danger, 21],
          ["Repeat Customer Rate", "34%", "#7b61ff", 34],
        ].map(([label, val, color, pct]) => (
          <div key={label} style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 13, color: COLORS.text }}>{label}</span>
              <span style={{ fontSize: 13, color, fontWeight: 700 }}>{val}</span>
            </div>
            <ProgressBar value={pct} max={100} color={color} />
          </div>
        ))}
      </div>
    </div>
  </div>
);

// 6. CART
const CartView = ({ cart, setCart }) => {
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const updateQty = (id, delta) => setCart(prev => prev.map(i => i.id === id ? { ...i, qty: Math.max(1, i.qty + delta) } : i));
  const remove = (id) => setCart(prev => prev.filter(i => i.id !== id));

  if (cart.length === 0) return (
    <div style={{ textAlign: "center", padding: 80 }}>
      <ShoppingCart size={64} color={COLORS.textDim} style={{ opacity: 0.3 }} />
      <h3 style={{ color: COLORS.text, margin: "20px 0 8px" }}>Your cart is empty</h3>
      <p style={{ color: COLORS.textDim }}>Add some products from the catalog to get started.</p>
    </div>
  );

  return (
    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 24 }}>
      <div>
        <h3 style={{ fontSize: 20, fontWeight: 800, color: COLORS.text, marginBottom: 16, fontFamily: "'Orbitron', sans-serif" }}>🛒 Shopping Cart ({cart.length})</h3>
        {cart.map(item => (
          <div key={item.id} style={{ display: "flex", alignItems: "center", gap: 16, padding: 16, background: COLORS.bgCard, borderRadius: 14, border: `1px solid ${COLORS.border}`, marginBottom: 10 }}>
            <div style={{ width: 64, height: 64, background: COLORS.bgHover, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 32, flexShrink: 0 }}>{item.image}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, color: COLORS.text, fontSize: 14 }}>{item.name}</div>
              <div style={{ fontSize: 12, color: COLORS.textDim }}>{item.category}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <button onClick={() => updateQty(item.id, -1)} style={{ width: 28, height: 28, borderRadius: 6, background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, color: COLORS.text, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><Minus size={12} /></button>
              <span style={{ width: 30, textAlign: "center", fontWeight: 700, color: COLORS.text, fontSize: 14 }}>{item.qty}</span>
              <button onClick={() => updateQty(item.id, 1)} style={{ width: 28, height: 28, borderRadius: 6, background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, color: COLORS.text, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><Plus size={12} /></button>
            </div>
            <div style={{ fontSize: 18, fontWeight: 800, color: COLORS.accent, fontFamily: "'Orbitron', sans-serif", minWidth: 100, textAlign: "right" }}>${(item.price * item.qty).toLocaleString()}</div>
            <button onClick={() => remove(item.id)} style={{ width: 32, height: 32, borderRadius: 8, background: "transparent", border: `1px solid ${COLORS.danger}33`, color: COLORS.danger, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}><X size={14} /></button>
          </div>
        ))}
      </div>
      <div style={{ position: "sticky", top: 20 }}>
        <div style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
          <h4 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>Order Summary</h4>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
            {[["Subtotal", `$${total.toLocaleString()}`], ["Shipping", "FREE"], ["Tax (est.)", `$${(total * 0.08).toFixed(2)}`]].map(([l, v]) => (
              <div key={l} style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontSize: 13, color: COLORS.textDim }}>{l}</span>
                <span style={{ fontSize: 13, color: COLORS.text, fontWeight: 600 }}>{v}</span>
              </div>
            ))}
          </div>
          <div style={{ borderTop: `1px solid ${COLORS.border}`, paddingTop: 14, display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
            <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.text }}>Total</span>
            <span style={{ fontSize: 22, fontWeight: 900, color: COLORS.accent, fontFamily: "'Orbitron', sans-serif" }}>${(total * 1.08).toFixed(2)}</span>
          </div>
          <input placeholder="Promo code" style={{ width: "100%", padding: "10px 14px", background: COLORS.bgHover, border: `1px solid ${COLORS.border}`, borderRadius: 10, color: COLORS.text, fontSize: 13, marginBottom: 12, outline: "none", boxSizing: "border-box" }} />
          <button style={{ width: "100%", padding: "14px", background: COLORS.gradient, border: "none", borderRadius: 12, color: COLORS.bg, fontWeight: 800, fontSize: 15, cursor: "pointer", letterSpacing: "1px" }}>⚡ CHECKOUT</button>
          <div style={{ display: "flex", justifyContent: "center", gap: 12, marginTop: 16 }}>
            {["💳 Visa", "💳 MC", "📱 PayPal", "₿ Crypto"].map(m => (
              <span key={m} style={{ fontSize: 10, color: COLORS.textDim, padding: "4px 8px", background: COLORS.bgHover, borderRadius: 6 }}>{m}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// 7. SETTINGS / ADMIN
const AdminSettings = () => (
  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
    {[
      ["⚙️ Platform Settings", [["Store Name", "NEXUS"], ["Default Currency", "USD"], ["Default Language", "English"], ["Tax Rate", "8%"], ["Free Shipping Threshold", "$99"]]],
      ["🔐 Security & Access", [["Two-Factor Auth", "Enabled"], ["API Key", "nx_live_*****3f7"], ["Webhook URL", "https://api.nexus.com/..."], ["Admin Roles", "3 admins, 5 managers"]]],
      ["📦 Shipping Configuration", [["Default Carrier", "DHL Express"], ["Avg Delivery", "5-10 business days"], ["Tracking Integration", "Active"], ["Auto-Fulfill", "Enabled"], ["Insurance", "Optional (2%)"]]],
      ["💰 Payment Gateways", [["Stripe", "✅ Connected"], ["PayPal", "✅ Connected"], ["Crypto (Coinbase)", "✅ Connected"], ["Bank Transfer", "✅ Active"], ["Escrow for Agents", "✅ Enabled"]]],
      ["📧 Notifications", [["Order Confirmation", "Email + SMS"], ["Shipping Updates", "Email + Push"], ["Agent Alerts", "Email + Dashboard"], ["Low Stock Alert", "< 10 units"], ["Commission Payout", "Monthly auto-pay"]]],
      ["🔌 Integrations", [["Shopify Sync", "✅ Active"], ["WooCommerce API", "✅ Active"], ["CJ Dropshipping", "✅ Connected"], ["Google Analytics", "✅ Connected"], ["Slack Notifications", "✅ Enabled"]]],
    ].map(([title, items]) => (
      <div key={title} style={{ background: COLORS.bgCard, borderRadius: 16, border: `1px solid ${COLORS.border}`, padding: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, margin: "0 0 16px" }}>{title}</h3>
        {items.map(([label, value]) => (
          <div key={label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: `1px solid ${COLORS.border}` }}>
            <span style={{ fontSize: 13, color: COLORS.textDim }}>{label}</span>
            <span style={{ fontSize: 13, color: COLORS.text, fontWeight: 600 }}>{value}</span>
          </div>
        ))}
      </div>
    ))}
  </div>
);

// ==========================
// MAIN APP SHELL
// ==========================
export default function NexusPlatform() {
  const [page, setPage] = useState("store");
  const [cart, setCart] = useState([]);
  const [wishlist, setWishlist] = useState([]);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notifications] = useState(5);

  const NAV = [
    { id: "store", label: "Storefront", icon: Store },
    { id: "orders", label: "Orders", icon: Package, count: ORDERS.length },
    { id: "agents", label: "Agents & Teams", icon: Users, count: AGENTS.length },
    { id: "suppliers", label: "Suppliers & Dropship", icon: Globe },
    { id: "analytics", label: "Analytics", icon: BarChart3 },
    { id: "cart", label: "Cart", icon: ShoppingCart, count: cart.length },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  const pageTitle = NAV.find(n => n.id === page)?.label || "";

  return (
    <div style={{ display: "flex", height: "100vh", background: COLORS.bg, fontFamily: "'Segoe UI', -apple-system, sans-serif", color: COLORS.text, overflow: "hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;800;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: ${COLORS.bg}; }
        ::-webkit-scrollbar-thumb { background: ${COLORS.border}; border-radius: 3px; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        select option { background: ${COLORS.bgCard}; color: ${COLORS.text}; }
        input::placeholder, textarea::placeholder { color: ${COLORS.textDim}55; }
      `}</style>

      {/* Sidebar */}
      <div style={{
        width: sidebarCollapsed ? 70 : 240, background: COLORS.bgCard, borderRight: `1px solid ${COLORS.border}`,
        display: "flex", flexDirection: "column", transition: "width 0.3s ease", flexShrink: 0, overflow: "hidden",
      }}>
        {/* Logo */}
        <div style={{ padding: sidebarCollapsed ? "20px 10px" : "20px 20px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 900, fontSize: 16, color: COLORS.bg, fontFamily: "'Orbitron', sans-serif", flexShrink: 0 }}>N</div>
          {!sidebarCollapsed && <div>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontWeight: 900, fontSize: 18, background: COLORS.gradient, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>NEXUS</div>
            <div style={{ fontSize: 9, color: COLORS.textDim, letterSpacing: "2px", textTransform: "uppercase" }}>PLATFORM v3.0</div>
          </div>}
        </div>

        {/* Nav Items */}
        <div style={{ flex: 1, padding: "12px 8px", display: "flex", flexDirection: "column", gap: 2 }}>
          {NAV.map(item => (
            <button key={item.id} onClick={() => setPage(item.id)} style={{
              display: "flex", alignItems: "center", gap: 12, padding: sidebarCollapsed ? "12px 0" : "12px 14px",
              justifyContent: sidebarCollapsed ? "center" : "flex-start",
              background: page === item.id ? COLORS.accentDim : "transparent", border: "none", borderRadius: 10,
              color: page === item.id ? COLORS.accent : COLORS.textDim, cursor: "pointer", transition: "all 0.2s",
              fontSize: 13, fontWeight: page === item.id ? 700 : 500, width: "100%", position: "relative",
            }}>
              {page === item.id && <div style={{ position: "absolute", left: 0, top: "25%", bottom: "25%", width: 3, borderRadius: 2, background: COLORS.accent }} />}
              <item.icon size={18} />
              {!sidebarCollapsed && <span style={{ flex: 1, textAlign: "left" }}>{item.label}</span>}
              {!sidebarCollapsed && item.count > 0 && <span style={{ background: page === item.id ? COLORS.accent : COLORS.border, color: page === item.id ? COLORS.bg : COLORS.textDim, padding: "1px 8px", borderRadius: 10, fontSize: 11, fontWeight: 700 }}>{item.count}</span>}
            </button>
          ))}
        </div>

        {/* User */}
        {!sidebarCollapsed && (
          <div style={{ padding: 16, borderTop: `1px solid ${COLORS.border}`, display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: COLORS.gradient, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 12, color: COLORS.bg }}>AD</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text }}>Admin</div>
              <div style={{ fontSize: 10, color: COLORS.textDim }}>Platform Owner</div>
            </div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Top Bar */}
        <div style={{ padding: "14px 28px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center", background: COLORS.bgCard, flexShrink: 0 }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 800, color: COLORS.text, fontFamily: "'Orbitron', sans-serif", margin: 0 }}>{pageTitle}</h1>
            <div style={{ fontSize: 11, color: COLORS.textDim, marginTop: 2 }}>NEXUS Dropshipping Platform · {new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ position: "relative", cursor: "pointer" }}>
              <Bell size={18} color={COLORS.textDim} />
              {notifications > 0 && <span style={{ position: "absolute", top: -6, right: -6, width: 16, height: 16, borderRadius: "50%", background: COLORS.danger, color: "#fff", fontSize: 9, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{notifications}</span>}
            </div>
            <div style={{ width: 1, height: 24, background: COLORS.border }} />
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: COLORS.success, animation: "pulse 2s infinite" }} />
              <span style={{ fontSize: 12, color: COLORS.success, fontWeight: 600 }}>LIVE</span>
            </div>
          </div>
        </div>

        {/* Page Content */}
        <div style={{ flex: 1, overflow: "auto", padding: 28 }}>
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            {page === "store" && <StoreFront cart={cart} setCart={setCart} wishlist={wishlist} setWishlist={setWishlist} />}
            {page === "orders" && <OrderManagement />}
            {page === "agents" && <AgentDashboard />}
            {page === "suppliers" && <SupplierManagement />}
            {page === "analytics" && <Analytics />}
            {page === "cart" && <CartView cart={cart} setCart={setCart} />}
            {page === "settings" && <AdminSettings />}
          </div>
        </div>
      </div>
    </div>
  );
}
