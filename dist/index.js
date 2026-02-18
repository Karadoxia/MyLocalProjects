"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_1 = __importDefault(require("http"));
const PORT = Number(process.env.PORT ?? 3000);
const http = require('http');
const fs = require('fs');
const path = require('path');
const PUBLIC_DIR = path.resolve(process.cwd(), 'public');
// persistence configuration (overridable via CART_FILE / DATA_DIR env)
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(process.cwd(), 'data'))
const CART_FILE = process.env.CART_FILE || path.join(DATA_DIR, 'cart.json')
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};
function serveFile(filePath, res){
  fs.readFile(filePath, (err,data)=>{
    if(err){res.writeHead(404,{'Content-Type':'text/plain'});res.end('Not found');return}
    const ext = path.extname(filePath);
    const type = mime[ext] || 'application/octet-stream';
    res.writeHead(200,{'Content-Type':type,'Cache-Control':'no-store'});
    res.end(data);
  })
}
// simple in-memory cart API (with persisted storage)
const cart = { items: [] };
// load persisted cart (synchronous to avoid race on startup)
try {
  fs.mkdirSync(DATA_DIR, { recursive: true })
  if (fs.existsSync(CART_FILE)) {
    const raw = fs.readFileSync(CART_FILE, 'utf8')
    const parsed = JSON.parse(raw || '{}')
    if (parsed && Array.isArray(parsed.items)) cart.items = parsed.items
  }
} catch (err) { /* ignore */ }

function readJson(req, cb){
  let body = '';
  req.on('data', (c)=> body += c.toString());
  req.on('end', ()=>{ try{ cb(null, body?JSON.parse(body):{}) }catch(e){ cb(e) } });
  req.on('error', cb);
}

const server = http.createServer((req,res)=>{
  const url = req.url || '/';

  if (url.startsWith('/api/cart')) {
    const method = req.method || 'GET';
    if (method === 'GET') {
      const total = cart.items.reduce((s,i)=>s+i.qty,0);
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end(JSON.stringify({ total, items: cart.items }));
      return;
    }
    if (method === 'POST') {
      return readJson(req, (err, body)=>{
        if (err) { res.writeHead(400,{'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'invalid json' })); return }
        const { id, name, price=0 } = body || {};
        if(!id||!name){ res.writeHead(400,{'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'missing id or name' })); return }
        const existing = cart.items.find(i=>i.id===id);
        if(existing) existing.qty += 1; else cart.items.push({ id, name, price:Number(price), qty:1 });
        // persist (best-effort)
        try{
          if (typeof db !== 'undefined' && db) {
            try {
              if (existing) db.prepare('UPDATE cart_items SET qty = ? WHERE id = ?').run(existing.qty, id)
              else db.prepare('INSERT OR REPLACE INTO cart_items (id, name, price, qty) VALUES (?, ?, ?, ?)').run(id, name, Number(price), 1)
            } catch (err) { console.error('sqlite persistence failed', err) }
          } else {
            fs.mkdirSync(DATA_DIR, { recursive: true })
            fs.writeFileSync(CART_FILE + '.tmp', JSON.stringify({ items: cart.items }), 'utf8')
            fs.renameSync(CART_FILE + '.tmp', CART_FILE)
          }
        }catch(e){ console.error('cart persistence failed', e) }
        const total = cart.items.reduce((s,i)=>s+i.qty,0);
        res.writeHead(201,{'Content-Type':'application/json'});
        res.end(JSON.stringify({ total, items: cart.items }));
      });
    }

    if (method === 'DELETE') {
      // clear cart (testing/dev helper)
      cart.items.length = 0;
      try {
        if (typeof db !== 'undefined' && db) {
          db.prepare('DELETE FROM cart_items').run()
        } else {
          try { fs.unlinkSync(CART_FILE) } catch (e) { }
        }
      } catch (err) { console.error('failed to clear cart', err) }
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end(JSON.stringify({ total: 0, items: [] }));
      return;
    }

    res.writeHead(405,{'Content-Type':'application/json'}); res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }

  if(url === '/health'){res.writeHead(200,{'Content-Type':'text/plain'});res.end('ok');return}
  let pathname = decodeURIComponent(url.split('?')[0]);
  if(pathname === '/') pathname = '/index.html';
  const filePath = path.join(PUBLIC_DIR, pathname);
  if(!filePath.startsWith(PUBLIC_DIR)){res.writeHead(400,{'Content-Type':'text/plain'});res.end('Bad request');return}
  fs.stat(filePath,(err,stat)=>{
    if(!err && stat.isFile()) return serveFile(filePath,res);
    serveFile(path.join(PUBLIC_DIR,'index.html'),res);
  });
});
server.listen(PORT, '127.0.0.1', ()=>{ const a = server.address(); const p = (a && typeof a === 'object' && 'port' in a) ? a.port : PORT; console.log(`listening on http://127.0.0.1:${p}`) });
