import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import multer from 'multer';
import Stripe from 'stripe';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=Number(process.env.PORT||3000);
const BASE=(process.env.BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');
const JWT=process.env.JWT_SECRET;
if(!JWT||JWT.length<32) throw Error('Set JWT_SECRET to a random string of 32+ characters in .env');
for(const d of ['uploads','private']) fs.mkdirSync(path.join(root,d),{recursive:true});
const db=new Database(path.join(root,'private','litspace.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS books(id INTEGER PRIMARY KEY,title TEXT NOT NULL,author TEXT NOT NULL,description TEXT DEFAULT '',category TEXT NOT NULL,genre TEXT DEFAULT '',price_ngn INTEGER NOT NULL DEFAULT 0,price_usd INTEGER NOT NULL DEFAULT 0,free INTEGER NOT NULL DEFAULT 0,cover TEXT DEFAULT '',file TEXT DEFAULT '',published INTEGER NOT NULL DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,book_id INTEGER NOT NULL,provider TEXT NOT NULL,currency TEXT NOT NULL,amount INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',provider_ref TEXT UNIQUE,created_at TEXT DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id),FOREIGN KEY(book_id) REFERENCES books(id));
CREATE UNIQUE INDEX IF NOT EXISTS ux_purchase ON orders(user_id,book_id) WHERE status='paid';
`);
const adminEmail=process.env.ADMIN_EMAIL?.toLowerCase().trim();


    console.log("Admin accounts updated:", result.changes);
if(adminEmail&&!db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail)){
 if(!process.env.ADMIN_PASSWORD||process.env.ADMIN_PASSWORD.length<12) throw Error('Set ADMIN_PASSWORD to 12+ characters');
 db.prepare('INSERT INTO users(email,password,role) VALUES(?,?,?)').run(adminEmail,bcrypt.hashSync(process.env.ADMIN_PASSWORD,12),'admin');
 console.log('Created initial admin:',adminEmail);
}
if(db.prepare('SELECT COUNT(*) n FROM books').get().n===0){
 const add=db.prepare('INSERT INTO books(title,author,description,category,genre,price_ngn,price_usd,free,cover) VALUES(?,?,?,?,?,?,?,?,?)');
 [
 ['Faith and Purpose','LitSpace Editorial','A sample inspirational eBook listing. Upload your licensed PDF before publishing.','Christian','Devotional',250000,199,0,''],
 ['Understanding the Cosmos','LitSpace Editorial','An introductory sample listing for science readers.','Science','Physics',420000,299,0,''],
 ['The Last Lantern','LitSpace Editorial','A fictional sample novel listing.','Novels','Mystery',320000,249,0,''],
 ['Introduction to Python','LitSpace Editorial','A free sample catalog listing. Attach a permitted PDF before distributing.','Technology','Programming',0,0,1,''],
 ['Beyond the Horizon','LitSpace Editorial','A sample fantasy novel listing.','Novels','Fantasy',350000,249,0,''],
 ['Growing a Business','LitSpace Editorial','A sample entrepreneurship title.','Business','Entrepreneurship',390000,299,0,'']
 ].forEach(b=>add.run(...b));
}
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(cookieParser());
app.use('/api',rateLimit({windowMs:15*60*1000,limit:200,standardHeaders:'draft-7',legacyHeaders:false}));
// Stripe needs the raw webhook body to validate its signature.
app.post('/api/webhooks/stripe',express.raw({type:'application/json'}),(req,res)=>{
 if(!process.env.STRIPE_WEBHOOK_SECRET||!process.env.STRIPE_SECRET_KEY)return res.sendStatus(503);
 try{
  const event=new Stripe(process.env.STRIPE_SECRET_KEY).webhooks.constructEvent(req.body,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET);
  if(event.type==='checkout.session.completed'&&event.data.object.payment_status==='paid'){
   const s=event.data.object; markPaid(s.metadata?.orderId,'stripe',s.id,s.amount_total,s.currency?.toUpperCase());
  }
  res.json({received:true});
 }catch(e){console.error('Stripe webhook:',e.message);res.status(400).send('Invalid signature');}
});
app.post('/api/webhooks/paystack',express.raw({type:'application/json'}),(req,res)=>{
 if(!process.env.PAYSTACK_SECRET_KEY)return res.sendStatus(503);
 const signature=crypto.createHmac('sha512',process.env.PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
 const supplied=String(req.headers['x-paystack-signature']||'');
 if(signature.length!==supplied.length||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(supplied)))return res.sendStatus(401);
 try{const event=JSON.parse(req.body.toString());if(event.event==='charge.success'){
  const d=event.data;markPaid(d.metadata?.orderId,'paystack',String(d.reference),d.amount,d.currency);
 }res.sendStatus(200);}catch{res.sendStatus(400);}
});
app.use(express.json({limit:'200kb'}));
app.use(express.static(path.join(root,'public')));
const sign=u=>jwt.sign({id:u.id,role:u.role},JWT,{expiresIn:'7d'});
const user=(req,res,next)=>{try{const t=req.cookies.litspace_session;if(!t)throw Error();const v=jwt.verify(t,JWT);req.user=db.prepare('SELECT id,email,role FROM users WHERE id=?').get(v.id);if(!req.user)throw Error();next();}catch{res.status(401).json({error:'Please log in first.'});}};
const admin=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({error:'Admin access required'});
const cookieOpts={httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*86400*1000,path:'/'};
const safeUser=u=>({id:u.id,email:u.email,role:u.role});
app.post('/api/register',(req,res)=>{const email=String(req.body.email||'').toLowerCase().trim(),p=String(req.body.password||'');if(!/^\S+@\S+\.\S+$/.test(email)||p.length<8)return res.status(400).json({error:'Valid email and password of 8+ characters required'});try{const r=db.prepare('INSERT INTO users(email,password) VALUES(?,?)').run(email,bcrypt.hashSync(p,12));const u={id:r.lastInsertRowid,email,role:'customer'};res.cookie('litspace_session',sign(u),cookieOpts).json({user:safeUser(u)});}catch{res.status(409).json({error:'Email already registered'});}});
app.post('/api/login',(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email||'').toLowerCase().trim());if(!u||!bcrypt.compareSync(String(req.body.password||''),u.password))return res.status(401).json({error:'Incorrect email or password'});res.cookie('litspace_session',sign(u),cookieOpts).json({user:safeUser(u)});});
app.post('/api/logout',(req,res)=>res.clearCookie('litspace_session',{path:'/'}).json({ok:true}));
app.get('/api/me',(req,res)=>{try{const v=jwt.verify(req.cookies.litspace_session,JWT);const u=db.prepare('SELECT id,email,role FROM users WHERE id=?').get(v.id);res.json({user:u||null});}catch{res.json({user:null});}});
const publicBooks=()=>db.prepare('SELECT id,title,author,description,category,genre,price_ngn,price_usd,free,cover,published FROM books WHERE published=1 ORDER BY id DESC').all();
app.get('/api/books',(req,res)=>res.json(publicBooks()));
app.get('/api/admin/books',user,admin,(req,res)=>res.json(db.prepare('SELECT id,title,author,description,category,genre,price_ngn,price_usd,free,cover,file,published FROM books ORDER BY id DESC').all().map(b=>({...b,file:!!b.file}))));
const upload=multer({storage:multer.diskStorage({destination:(req,file,cb)=>cb(null,path.join(root,'uploads')),filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())}),limits:{fileSize:30*1024*1024},fileFilter:(req,file,cb)=>{const ext=path.extname(file.originalname).toLowerCase();if(file.fieldname==='cover'&&['.jpg','.jpeg','.png','.webp'].includes(ext))cb(null,true);else if(file.fieldname==='ebook'&&ext==='.pdf')cb(null,true);else cb(new Error('Only JPG/PNG/WebP covers and PDF ebooks are supported'));}});
const fields=upload.fields([{name:'cover',maxCount:1},{name:'ebook',maxCount:1}]);
const parseBook=(req,old={})=>{const b={};for(const k of ['title','author','description','category','genre'])b[k]=String(req.body[k]??old[k]??'').trim().slice(0,k==='description'?3000:150);for(const k of ['price_ngn','price_usd']){b[k]=Number(req.body[k]??old[k]??0);if(!Number.isSafeInteger(b[k])||b[k]<0||b[k]>1000000000)throw Error('Invalid price');}b.free=String(req.body.free??old.free??'0')==='1'?1:0;b.published=String(req.body.published??old.published??'1')==='1'?1:0;if(!b.title||!b.author||!b.category)throw Error('Title, author and category are required');if(b.free){b.price_ngn=0;b.price_usd=0;}b.cover=req.files?.cover?.[0]?.filename||old.cover||'';b.file=req.files?.ebook?.[0]?.filename||old.file||'';return b;};
const bookCols=['title','author','description','category','genre','price_ngn','price_usd','free','cover','file','published'];
app.post('/api/admin/books',user,admin,fields,(req,res)=>{try{const b=parseBook(req);const r=db.prepare(`INSERT INTO books(${bookCols.join(',')}) VALUES(${bookCols.map(()=>'?').join(',')})`).run(...bookCols.map(k=>b[k]));res.json({id:r.lastInsertRowid});}catch(e){res.status(400).json({error:e.message});}});
app.put('/api/admin/books/:id',user,admin,fields,(req,res)=>{try{const old=db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);if(!old)return res.sendStatus(404);const b=parseBook(req,old);db.prepare(`UPDATE books SET ${bookCols.map(k=>k+'=?').join(',')} WHERE id=?`).run(...bookCols.map(k=>b[k]),old.id);res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.delete('/api/admin/books/:id',user,admin,(req,res)=>{const b=db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);if(!b)return res.sendStatus(404);db.prepare('UPDATE books SET published=0 WHERE id=?').run(b.id);res.json({ok:true,message:'Unpublished. Existing buyers retain access.'});});
app.get('/api/covers/:id',(req,res)=>{const b=db.prepare('SELECT cover FROM books WHERE id=?').get(req.params.id);if(!b?.cover)return res.sendStatus(404);res.sendFile(path.join(root,'uploads',path.basename(b.cover)));});
app.get('/api/library',user,(req,res)=>res.json(db.prepare(`SELECT b.id,b.title,b.author,b.cover,b.category FROM books b WHERE b.free=1 OR EXISTS(SELECT 1 FROM orders o WHERE o.book_id=b.id AND o.user_id=? AND o.status='paid') ORDER BY b.id DESC`).all(req.user.id)));
app.get('/api/read/:id',user,(req,res)=>{const b=db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);if(!b?.file)return res.status(404).json({error:'Digital file not uploaded yet'});const owned=b.free||req.user.role==='admin'||db.prepare("SELECT id FROM orders WHERE user_id=? AND book_id=? AND status='paid'").get(req.user.id,b.id);if(!owned)return res.status(403).json({error:'Purchase this book to access it'});res.setHeader('Cache-Control','private, no-store');res.download(path.join(root,'uploads',path.basename(b.file)),b.title.replace(/[^a-z0-9 _-]/gi,'').slice(0,60)+'.pdf');});
const orderById=id=>db.prepare('SELECT * FROM orders WHERE id=?').get(id);
function markPaid(orderId,provider,ref,amount,currency){const o=orderById(orderId);if(!o||o.provider!==provider||o.amount!==Number(amount)||o.currency!==String(currency).toUpperCase())return false;if(o.status==='paid')return true;db.prepare("UPDATE orders SET status='paid',provider_ref=? WHERE id=? AND status='pending'").run(ref,orderId);return true;}
const createOrder=(u,b,provider,currency)=>{if(!['NGN','USD'].includes(currency))throw Error('Invalid currency');const amount=currency==='NGN'?b.price_ngn:b.price_usd;if(!Number.isInteger(amount)||amount<1)throw Error('Price not configured for this currency');const id=crypto.randomUUID();db.prepare('INSERT INTO orders(id,user_id,book_id,provider,currency,amount) VALUES(?,?,?,?,?,?)').run(id,u.id,b.id,provider,currency,amount);return {id,amount};};
app.post('/api/checkout',user,async(req,res)=>{const b=db.prepare('SELECT * FROM books WHERE id=? AND published=1').get(req.body.bookId);if(!b)return res.status(404).json({error:'Book not found'});if(!b.file)return res.status(400).json({error:'This book is not ready for sale: no PDF uploaded'});if(b.free)return res.json({url:null,free:true});if(db.prepare("SELECT id FROM orders WHERE user_id=? AND book_id=? AND status='paid'").get(req.user.id,b.id))return res.json({owned:true});const provider=String(req.body.provider||''),currency=String(req.body.currency||'NGN').toUpperCase();if(!['stripe','paystack','paypal','flutterwave'].includes(provider))return res.status(400).json({error:'Unsupported payment method'});if(provider==='paypal'&&currency!=='USD')return res.status(400).json({error:'PayPal checkout uses USD'});if(provider==='paystack'&&currency!=='NGN')return res.status(400).json({error:'Paystack checkout uses NGN'});let o;try{o=createOrder(req.user,b,provider,currency);let url;
 if(provider==='stripe'){
  if(!process.env.STRIPE_SECRET_KEY)throw Error('Stripe is not configured');
  const s=await new Stripe(process.env.STRIPE_SECRET_KEY).checkout.sessions.create({mode:'payment',customer_email:req.user.email,line_items:[{price_data:{currency:currency.toLowerCase(),unit_amount:o.amount,product_data:{name:b.title}},quantity:1}],metadata:{orderId:o.id},success_url:`${BASE}/?payment=return`,cancel_url:`${BASE}/?payment=cancel`});url=s.url;
 }else if(provider==='paystack'){
  if(!process.env.PAYSTACK_SECRET_KEY)throw Error('Paystack is not configured');
  const r=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({email:req.user.email,amount:o.amount,currency:'NGN',reference:o.id,metadata:{orderId:o.id},callback_url:`${BASE}/?payment=return&provider=paystack&reference=${o.id}`})});const d=await r.json();if(!r.ok||!d.status)throw Error(d.message||'Paystack checkout failed');url=d.data.authorization_url;
 }else if(provider==='flutterwave'){
  if(!process.env.FLW_SECRET_KEY)throw Error('Flutterwave is not configured');
  const r=await fetch('https://api.flutterwave.com/v3/payments',{method:'POST',headers:{Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({tx_ref:o.id,amount:o.amount/100,currency,redirect_url:`${BASE}/?payment=return&provider=flutterwave`,customer:{email:req.user.email},customizations:{title:'LitSpace',description:b.title}})});const d=await r.json();if(!r.ok||d.status!=='success')throw Error(d.message||'Flutterwave checkout failed');url=d.data.link;
 }else{
  const token=await paypalToken();const host=paypalHost();const r=await fetch(host+'/v2/checkout/orders',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json','PayPal-Request-Id':o.id},body:JSON.stringify({intent:'CAPTURE',purchase_units:[{reference_id:o.id,custom_id:o.id,amount:{currency_code:'USD',value:(o.amount/100).toFixed(2)}}],application_context:{return_url:`${BASE}/?payment=return&provider=paypal&order=${o.id}`,cancel_url:`${BASE}/?payment=cancel`}})});const d=await r.json();if(!r.ok)throw Error(d.message||'PayPal checkout failed');db.prepare('UPDATE orders SET provider_ref=? WHERE id=?').run(d.id,o.id);url=d.links?.find(l=>l.rel==='approve')?.href;if(!url)throw Error('PayPal approval link unavailable');
 }
 res.json({url,orderId:o.id});
 }catch(e){if(o)db.prepare("UPDATE orders SET status='failed' WHERE id=?").run(o.id);res.status(400).json({error:e.message});}
});
function paypalHost(){return process.env.PAYPAL_ENV==='live'?'https://api-m.paypal.com':'https://api-m.sandbox.paypal.com';}
async function paypalToken(){if(!process.env.PAYPAL_CLIENT_ID||!process.env.PAYPAL_CLIENT_SECRET)throw Error('PayPal is not configured');const auth=Buffer.from(process.env.PAYPAL_CLIENT_ID+':'+process.env.PAYPAL_CLIENT_SECRET).toString('base64');const r=await fetch(paypalHost()+'/v1/oauth2/token',{method:'POST',headers:{Authorization:'Basic '+auth,'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type=client_credentials'});const d=await r.json();if(!r.ok)throw Error('PayPal authentication failed');return d.access_token;}
app.post('/api/payments/verify',user,async(req,res)=>{const o=orderById(String(req.body.orderId||''));if(!o||o.user_id!==req.user.id)return res.sendStatus(404);if(o.status==='paid')return res.json({paid:true});try{if(o.provider==='paystack'){
  const r=await fetch('https://api.paystack.co/transaction/verify/'+encodeURIComponent(o.id),{headers:{Authorization:`Bearer ${process.env.PAYSTACK_SECRET_KEY}`}});const d=await r.json();if(d.data?.status==='success')markPaid(o.id,'paystack',String(d.data.reference),d.data.amount,d.data.currency);
 }else if(o.provider==='flutterwave'){
  const tx=String(req.body.transactionId||'');if(!/^\d+$/.test(tx))throw Error('Missing transaction ID');const r=await fetch('https://api.flutterwave.com/v3/transactions/'+tx+'/verify',{headers:{Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`}});const d=await r.json();if(d.data?.status==='successful'&&d.data.tx_ref===o.id&&d.data.currency===o.currency&&Number(d.data.amount)*100>=o.amount)markPaid(o.id,'flutterwave',tx,o.amount,o.currency);
 }else if(o.provider==='paypal'){
  const token=await paypalToken();const r=await fetch(paypalHost()+'/v2/checkout/orders/'+encodeURIComponent(o.provider_ref)+'/capture',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json','PayPal-Request-Id':o.id}});const d=await r.json();const pu=d.purchase_units?.[0],cap=pu?.payments?.captures?.[0];if(d.status==='COMPLETED'&&cap?.status==='COMPLETED'&&pu.custom_id===o.id&&cap.amount.currency_code===o.currency&&Math.round(Number(cap.amount.value)*100)===o.amount)markPaid(o.id,'paypal',cap.id,o.amount,o.currency);
 }res.json({paid:orderById(o.id).status==='paid'});}catch(e){res.status(400).json({error:e.message});}});
app.get('/api/orders',user,(req,res)=>res.json(db.prepare('SELECT o.id,o.status,o.provider,o.currency,o.amount,b.title FROM orders o JOIN books b ON b.id=o.book_id WHERE o.user_id=? ORDER BY o.created_at DESC LIMIT 50').all(req.user.id)));
app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:err.message||'Request failed'});});
app.listen(PORT,()=>console.log(`LitSpace running at ${BASE}`));
