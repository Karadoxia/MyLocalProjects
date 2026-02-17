"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_1 = __importDefault(require("http"));
const PORT = Number(process.env.PORT) || 3000;
const http = require('http');
const fs = require('fs');
const path = require('path');
const PUBLIC_DIR = path.resolve(process.cwd(), 'public');
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
const server = http.createServer((req,res)=>{
  const url = req.url || '/';
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
server.listen(PORT, '127.0.0.1', ()=>{console.log(`listening on http://127.0.0.1:${PORT}`)});
