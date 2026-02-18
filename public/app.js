// small interactions: magnetic cursor for hero card + increase cart count
document.addEventListener('DOMContentLoaded', ()=>{
  const card = document.querySelector('.card.floating')
  const heroArt = document.getElementById('hero-art')
  if(card && heroArt){
    heroArt.addEventListener('mousemove', (e)=>{
      const r = heroArt.getBoundingClientRect()
      const dx = (e.clientX - (r.left + r.width/2)) / (r.width/2)
      const dy = (e.clientY - (r.top + r.height/2)) / (r.height/2)
      card.style.transform = `translate(${dx*8}px, ${dy*-10}px) rotateX(${dy*6}deg) rotateY(${dx*6}deg)`
    })
    heroArt.addEventListener('mouseleave', ()=>{ card.style.transform = '' })
  }

  const cartBtn = document.querySelector('.btn.cart')
  const count = document.querySelector('.cart-count')
  let n = 0
  async function refreshCartCount(){
    try{
      const r = await fetch('/api/cart')
      const j = await r.json()
      if(j && typeof j.total === 'number'){
        n = j.total
        if(count) count.textContent = String(n)
      }
    }catch(e){ /* ignore */ }
  }

  if(cartBtn && count){
    cartBtn.addEventListener('click', ()=>{
      cartBtn.animate([{transform:'scale(1)'},{transform:'scale(1.06)'},{transform:'scale(1)'}],{duration:300,easing:'cubic-bezier(.2,.9,.2,1)'})
    })
  }

  // add-to-cart behavior for product cards
  document.querySelectorAll('.product.card').forEach(el=>{
    el.addEventListener('click', async ()=>{
      const titleEl = el.querySelector('h3')
      const priceEl = el.querySelector('.price')
      const name = titleEl? titleEl.textContent.trim() : 'product'
      const price = priceEl? Number(priceEl.textContent.replace(/[€, ]/g,'')) : 0
      const id = name.toLowerCase().replace(/[^a-z0-9]+/g,'-')
      try{
        const r = await fetch('/api/cart', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ id, name, price }) })
        const j = await r.json()
        if(j && typeof j.total === 'number' && count) count.textContent = String(j.total)
      }catch(e){ console.error(e) }
    })
  })

  // wire hero CTA to add a sample product
  const heroCta = document.querySelector('.btn.primary')
  if(heroCta){
    heroCta.addEventListener('click', async ()=>{
      try{
        const r = await fetch('/api/cart', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ id: 'wooting-60he', name: 'Wooting 60HE+', price: 159.99 }) })
        const j = await r.json()
        if(j && typeof j.total === 'number' && count) count.textContent = String(j.total)
      }catch(e){ console.error(e) }
    })
  }

  // initial refresh
  refreshCartCount()
})