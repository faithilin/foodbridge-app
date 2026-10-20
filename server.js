'use strict';
// FoodBridge server: zero npm dependencies. Needs Node 22.13+ (built-in SQLite).
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const db=new DatabaseSync(process.env.DB_PATH||path.join(__dirname,'foodbridge.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,hash TEXT,role TEXT,type TEXT,org TEXT,city TEXT,phone TEXT,verified INT,created INT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INT,created INT);
CREATE TABLE IF NOT EXISTS donations(id INTEGER PRIMARY KEY,donor_id INT,org TEXT,name TEXT,cat TEXT,qty INT,person TEXT,prep TEXT,deadline TEXT,loc TEXT,addr TEXT,al TEXT,status TEXT,demo INT DEFAULT 0,created INT);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,donation_id INT,recipient_id INT,status TEXT,demo INT DEFAULT 0,created INT);`);
const A=(s,...p)=>db.prepare(s).all(...p),G=(s,...p)=>db.prepare(s).get(...p),X=(s,...p)=>db.prepare(s).run(...p);
const CATS=['Cooked meals','Bakery','Fruit & vegetables','Packaged food','Dairy','Other'];
const TYPES={donor:['Restaurant','Hotel','Bakery','Hostel','Household'],recipient:['Charity','Community kitchen','Authorised recipient']};
class E extends Error{constructor(m,s=400){super(m);this.s=s}}
const need=(c,m,s)=>{if(!c)throw new E(m,s)};
const hash=p=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.scryptSync(p,s,32).toString('hex')};
const check=(p,h)=>{const[s,k]=h.split(':');return crypto.timingSafeEqual(Buffer.from(k,'hex'),crypto.scryptSync(p,s,32))};
const tries=new Map();
const live=d=>d.status==='available'&&d.deadline>new Date().toISOString();
const str=(v,min,max,m)=>{v=String(v??'').trim();need(v.length>=min&&v.length<=max,m);return v};

function userOf(req){const m=/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(!m)return null;
 return G('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created>?',m[1],Date.now()-30*864e5)||null}
function login(req,res,uid){const t=crypto.randomBytes(32).toString('hex');X('INSERT INTO sessions VALUES(?,?,?)',t,uid,Date.now());
 res.setHeader('Set-Cookie',`sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000${req.headers['x-forwarded-proto']==='https'?'; Secure':''}`)}

function stats(demo){const w=demo?'':' AND demo=0',p=G(`SELECT COALESCE(SUM(qty),0) p,COUNT(*) n FROM donations WHERE 1=1${w}`),
 done=G(`SELECT COALESCE(SUM(qty),0) p FROM donations WHERE status='completed'${w}`).p,c=G(`SELECT COUNT(*) c FROM requests WHERE status='completed'${w}`).c;
 return{n:p.n,p:done,c,kg:Math.round(done*0.4)}}  // ESTIMATE: 1 portion = 0.4 kg (assumption)

function state(u){const admin=u?.role==='admin',U=new Map(A('SELECT * FROM users').map(x=>[x.id,x])),org=id=>id?U.get(id)?.org||'Removed user':'Demo Charity';
 const D=A('SELECT * FROM donations ORDER BY created DESC').filter(d=>admin||live(d)||(u&&d.donor_id===u.id)).map(d=>({id:d.id,name:d.name,cat:d.cat,qty:d.qty,deadline:d.deadline,loc:d.loc,al:d.al,donorOrg:d.org,donorId:d.donor_id,status:d.status,demo:!!d.demo}));
 const R=A('SELECT r.*,d.name dn,d.donor_id,d.person,d.addr FROM requests r JOIN donations d ON d.id=r.donation_id').filter(r=>admin||(u&&(r.recipient_id===u.id||r.donor_id===u.id))).map(r=>{
  const ok=['accepted','completed'].includes(r.status),mineD=u&&r.donor_id===u.id,mineR=u&&r.recipient_id===u.id;
  return{id:r.id,donationId:r.donation_id,donationName:r.dn,donorId:r.donor_id,recipientId:r.recipient_id,recipientOrg:org(r.recipient_id),status:r.status,created:r.created,demo:!!r.demo,
   recipientPhone:ok&&mineD?U.get(r.recipient_id)?.phone:undefined,donorPhone:ok&&mineR?U.get(r.donor_id)?.phone:undefined,donorPerson:ok&&mineR?r.person:undefined,pickup:ok&&mineR?r.addr:undefined}});
 const pub=x=>({id:x.id,email:x.email,role:x.role,type:x.type,org:x.org,city:x.city,verified:!!x.verified});
 return{me:u?pub(u):null,donations:D,requests:R,users:admin?[...U.values()].map(pub):undefined,stats:{all:stats(true),real:stats(false)}}}

const demoRows=()=>{const h=36e5,n=Date.now(),x=(name,cat,qty,al,loc,org,hrs,status='available')=>[org,name,cat,qty,'Demo contact',new Date(n-2*h).toISOString(),new Date(n+hrs*h).toISOString(),loc,loc+' (demo address)',al,status];
 return[x('Vegetable biryani','Cooked meals',40,'None known','Demo Hotel, MG Road','Demo Grand Hotel',8),x('Fresh bread loaves','Bakery',25,'Gluten, may contain milk','Demo Main Street','Demo Sunrise Bakery',20),x('Mixed fruit crates','Fruit & vegetables',60,'None known','Demo Market Lane','Demo Fresh Mart',48),x('Packaged biscuits','Packaged food',100,'Gluten, nuts','Demo Hostel Gate','Demo Student Hostel',72),x('Milk packets','Dairy',30,'Milk','Demo Dairy Road','Demo Household',10),x('Old chapati (expired)','Cooked meals',50,'Gluten','Demo Kitchen','Demo Restaurant',-1),x('Sandwich boxes','Cooked meals',70,'Gluten, egg','Demo Cafe','Demo Cafe',5,'completed'),x('Rice meals','Cooked meals',90,'None known','Demo Canteen','Demo Hotel',5,'completed')]};

const routes={
'POST /register':(b,u,req,res)=>{const email=str(b.email,5,120,'Enter a valid email.').toLowerCase();need(/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email),'Enter a valid email.');
 need(String(b.password||'').length>=8,'Password must be at least 8 characters.');need(!G('SELECT 1 FROM users WHERE email=?',email),'This email is already registered.',409);
 const org=str(b.org,2,80,'Enter your organisation or household name (at least 2 letters).'),city=str(b.city,2,60,'Enter your city or area.'),phone=String(b.phone||'').trim();
 need(/^[+0-9 ()-]{7,16}$/.test(phone),'Enter a valid phone number (7–16 digits).');
 const adm=process.env.ADMIN_EMAIL?email===process.env.ADMIN_EMAIL.toLowerCase():!G('SELECT 1 FROM users');let role='admin',type='Admin';
 if(!adm){[role,type]=String(b.t||'').split('|');need(TYPES[role]?.includes(type),'Choose who you are.')}
 const id=Number(X('INSERT INTO users(email,hash,role,type,org,city,phone,verified,created) VALUES(?,?,?,?,?,?,?,?,?)',email,hash(b.password),role,type,org,city,phone,role==='recipient'?0:1,Date.now()).lastInsertRowid);login(req,res,id);return{ok:1}},
'POST /login':(b,u,req,res)=>{const ip=req.socket.remoteAddress,t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}need(t.n<10,'Too many attempts. Try again in 15 minutes.',429);
 const x=G('SELECT * FROM users WHERE email=?',String(b.email||'').trim().toLowerCase());if(!x||!check(String(b.password||''),x.hash)){t.n++;tries.set(ip,t);throw new E('Wrong email or password.',401)}login(req,res,x.id);return{ok:1}},
'POST /logout':(b,u,req,res)=>{const m=/sid=([a-f0-9]{64})/.exec(req.headers.cookie||'');if(m)X('DELETE FROM sessions WHERE token=?',m[1]);return{ok:1}},
'GET /state':(b,u)=>state(u),
'POST /donations':(b,u)=>{need(u?.role==='donor','Only donor accounts can add food.',403);const now=Date.now(),pr=Date.parse(b.prep),dl=Date.parse(b.dl);
 const name=str(b.name,2,80,'Enter the food name.');need(CATS.includes(b.cat),'Choose a category.');need(Number.isInteger(+b.qty)&&b.qty>=1&&b.qty<=10000,'Quantity must be 1 to 10000 portions.');
 const person=str(b.person,2,60,'Enter a contact person.');need(!isNaN(pr),'Enter the preparation time.');need(pr<=now+6e4,'Preparation time cannot be in the future.');need(!isNaN(dl),'Enter the safe collection deadline.');
 need(dl>now,'The deadline must be in the future. Past-deadline food cannot be listed.');need(dl>pr,'The deadline must be after the preparation time.');
 const loc=str(b.loc,2,60,'Enter the public area (for example “Kowdiar, Trivandrum”).'),addr=str(b.addr,5,160,'Enter the full pickup address.'),al=str(b.al,2,120,'Enter allergen information (or “none known”).');need(b.ok,'Please confirm the food is safe and not expired.');
 X('INSERT INTO donations(donor_id,org,name,cat,qty,person,prep,deadline,loc,addr,al,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',u.id,u.org,name,b.cat,+b.qty,person,new Date(pr).toISOString(),new Date(dl).toISOString(),loc,addr,al,'available',now);return{ok:1}},
'POST /requests':(b,u)=>{need(u?.role==='recipient','Only recipient accounts can request food.',403);need(u.verified,'Your recipient account is waiting for admin approval.',403);
 const d=G('SELECT * FROM donations WHERE id=?',+b.donationId);need(d&&live(d),'Sorry, this food is no longer available.',409);need(!d.demo,'Demo food cannot be requested.');
 need(!G("SELECT 1 FROM requests WHERE donation_id=? AND recipient_id=? AND status IN('pending','accepted')",d.id,u.id),'You already requested this food.',409);
 X("INSERT INTO requests(donation_id,recipient_id,status,created) VALUES(?,?,'pending',?)",d.id,u.id,Date.now());return{ok:1}},
'POST /admin/seed':(b,u)=>{need(u?.role==='admin','Admin only.',403);X('DELETE FROM requests WHERE demo=1');X('DELETE FROM donations WHERE demo=1');
 for(const r of demoRows()){const i=Number(X('INSERT INTO donations(donor_id,org,name,cat,qty,person,prep,deadline,loc,addr,al,status,demo,created) VALUES(0,?,?,?,?,?,?,?,?,?,?,?,1,?)',...r,Date.now()).lastInsertRowid);
  if(r[10]==='completed')X("INSERT INTO requests(donation_id,recipient_id,status,demo,created) VALUES(?,0,'completed',1,?)",i,Date.now())}return{ok:1}},
'POST /admin/unseed':(b,u)=>{need(u?.role==='admin','Admin only.',403);X('DELETE FROM requests WHERE demo=1');X('DELETE FROM donations WHERE demo=1');return{ok:1}}};

function dyn(m,p,b,u){const id=+m[1];
 if(p==='requests'){const r=G('SELECT r.*,d.donor_id,d.status ds,d.deadline FROM requests r JOIN donations d ON d.id=r.donation_id WHERE r.id=?',id);need(r,'Not found.',404);const act=m[2],donor=u?.id===r.donor_id,rec=u?.id===r.recipient_id;
  db.exec('BEGIN');try{
  if(act==='accept'){need(donor&&r.status==='pending','Not allowed.',403);need(r.ds==='available'&&r.deadline>new Date().toISOString(),'This donation is no longer available (deadline passed or already reserved).',409);
   X("UPDATE requests SET status='accepted' WHERE id=?",id);X("UPDATE donations SET status='reserved' WHERE id=?",r.donation_id);X("UPDATE requests SET status='rejected' WHERE donation_id=? AND id<>? AND status='pending'",r.donation_id,id)}
  else if(act==='reject'){need(donor&&r.status==='pending','Not allowed.',403);X("UPDATE requests SET status='rejected' WHERE id=?",id)}
  else if(act==='complete'){need(donor&&r.status==='accepted','Not allowed.',403);X("UPDATE requests SET status='completed' WHERE id=?",id);X("UPDATE donations SET status='completed' WHERE id=?",r.donation_id)}
  else if(act==='cancel'){need(rec&&['pending','accepted'].includes(r.status),'Not allowed.',403);X("UPDATE requests SET status='cancelled' WHERE id=?",id);if(r.status==='accepted')X("UPDATE donations SET status='available' WHERE id=?",r.donation_id)}
  else throw new E('Not found.',404);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e}return{ok:1}}
 if(p==='donations'){const d=G('SELECT * FROM donations WHERE id=?',id);need(d&&u&&d.donor_id===u.id&&d.status==='available','Not allowed.',403);X("UPDATE donations SET status='cancelled' WHERE id=?",id);X("UPDATE requests SET status='rejected' WHERE donation_id=? AND status='pending'",id);return{ok:1}}
 need(u?.role==='admin','Admin only.',403);
 if(p==='approve'){X('UPDATE users SET verified=1 WHERE id=?',id)}
 else if(p==='rmuser'){need(id!==u.id,'You cannot remove yourself.');X('DELETE FROM sessions WHERE user_id=?',id);X('DELETE FROM users WHERE id=?',id);X("UPDATE donations SET status='cancelled' WHERE donor_id=? AND status='available'",id)}
 else if(p==='rmdon'){X('DELETE FROM requests WHERE donation_id=?',id);X('DELETE FROM donations WHERE id=?',id)}
 else throw new E('Not found.',404);return{ok:1}}

const page=fs.readFileSync(path.join(__dirname,'public','index.html'));
http.createServer((req,res)=>{const p=new URL(req.url,'http://x').pathname,H={'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY'};
 if(req.method==='GET'&&p==='/'){res.writeHead(200,{'content-type':'text/html; charset=utf-8','x-content-type-options':'nosniff','x-frame-options':'DENY'});return res.end(page)}
 if(req.method==='GET'&&p==='/healthz'){res.writeHead(200);return res.end('ok')}
 let raw='';req.on('data',c=>{raw+=c;if(raw.length>2e4)req.destroy()});req.on('end',()=>{
  try{const k=req.method+' '+p.replace(/^\/api/,''),u=userOf(req);let b={};
   if(req.method==='POST'){need((req.headers['content-type']||'').includes('application/json'),'Bad request.');try{b=JSON.parse(raw||'{}')}catch{throw new E('Bad JSON.')}}
   let out,m;if(routes[k])out=routes[k](b,u,req,res);
   else if(req.method==='POST'&&(m=/^\/api\/requests\/(\d+)\/(\w+)$/.exec(p)))out=dyn(m,'requests',b,u);
   else if(req.method==='POST'&&(m=/^\/api\/donations\/(\d+)\/cancel$/.exec(p)))out=dyn(m,'donations',b,u);
   else if(req.method==='POST'&&(m=/^\/api\/admin\/(approve|rmuser|rmdon)\/(\d+)$/.exec(p)))out=dyn([0,m[2]],m[1],b,u);
   else throw new E('Not found.',404);
   res.writeHead(200,H);res.end(JSON.stringify(out))}
  catch(e){const s=e instanceof E?e.s:500;if(s===500)console.error(e);res.setHeader('content-type','application/json');res.writeHead(s,H);res.end(JSON.stringify({error:s===500?'Server error. Please try again.':e.message}))}})
}).listen(process.env.PORT||3000,()=>console.log('FoodBridge running on port '+(process.env.PORT||3000)));