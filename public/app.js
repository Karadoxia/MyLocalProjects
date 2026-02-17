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
  if(cartBtn && count){
    cartBtn.addEventListener('click', ()=>{
      n += 1
      count.textContent = String(n)
      cartBtn.animate([{transform:'scale(1)'},{transform:'scale(1.06)'},{transform:'scale(1)'}],{duration:300,easing:'cubic-bezier(.2,.9,.2,1)'})
    })
  }
})