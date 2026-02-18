import React, { useEffect, useState } from 'react'

function ProductCard({ id, name, price, onAdd }) {
  return (
    <article className="product card" onClick={() => onAdd({ id, name, price })}>
      <div className="media" />
      <h3>{name}</h3>
      <div className="price">{price}€</div>
    </article>
  )
}

export default function App() {
  const [count, setCount] = useState(0)

  async function refresh() {
    try {
      const r = await fetch('/api/cart')
      const j = await r.json()
      if (j && typeof j.total === 'number') setCount(j.total)
    } catch (e) { /* ignore */ }
  }

  useEffect(() => { refresh() }, [])

  async function add(item) {
    try {
      const r = await fetch('/api/cart', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify(item) })
      const j = await r.json()
      if (j && typeof j.total === 'number') setCount(j.total)
    } catch (e) { console.error(e) }
  }

  return (
    <div className="page">
      <header className="nav">
        <div className="logo">BOMBI<span>SHOP</span></div>
        <nav className="nav-actions">
          <button className="btn ghost">Account</button>
          <button className="btn cart" aria-label="Cart">🛒<span className="cart-count">{count}</span></button>
        </nav>
      </header>

      <main className="hero">
        <div className="hero-inner">
          <h1 className="hero-title">Level up with <span className="accent">Premium Tech</span></h1>
          <p className="hero-sub">Futuristic e‑commerce prototype — immersive, fast, and delightful.</p>
          <div className="hero-ctas">
            <button className="btn primary" onClick={() => add({ id: 'wooting-60he', name: 'Wooting 60HE+', price: 159.99 })}>Shop Hall Effect</button>
            <button className="btn secondary">Explore Deals</button>
          </div>
        </div>
        <div className="hero-art" id="hero-art">
          <div className="card floating">Wooting 60HE+</div>
        </div>
      </main>

      <section className="catalog">
        <h2 className="section-title">Featured</h2>
        <div className="grid">
          <ProductCard id="wooting-60he" name="Wooting 60HE+" price={159.99} onAdd={add} />
          <ProductCard id="vision-pro-oled" name="Vision Pro OLED" price={599.99} onAdd={add} />
          <ProductCard id="logitech-gpro" name="Logitech G Pro X" price={119.00} onAdd={add} />
        </div>
      </section>

      <footer className="site-footer">
        <small>© 2026 Bombishop Prototype — immersive UI demo</small>
      </footer>
    </div>
  )
}
