require('dotenv').config();
const express=require('express'),helmet=require('helmet'),cookie=require('cookie-parser'),rate=require('express-rate-limit');
const {Pool,types}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),mail=require('nodemailer');
types.setTypeParser(1082,v=>v); // keep DATE columns as plain 'YYYY-MM-DD'
const SECRET=process.env.JWT_SECRET;if(!SECRET)throw new Error('Set JWT_SECRET in .env');
const prod=process.env.NODE_ENV==='production';
const db=new Pool({connectionString:process.env.DATABASE_URL,ssl:prod?{rejectUnauthorized:false}:false});
const app=express();app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}),express.json({limit:'20kb'}),cookie(),express.static('public'));

const SERVICES=['Regular Cleaning','Deep Cleaning','Move-in / Move-out Clean','Laundry & Ironing','Outdoor & Lawn Care','Pest Control','Multiple Services'];
const STATUSES=['Pending','Confirmed','Completed','Cancelled'];
const limiter=rate({windowMs:15*60*1000,max:20,message:{error:'Too many attempts. Try again in 15 minutes.'}});
const wrap=f=>(req,res)=>f(req,res).catch(e=>{console.error(e);res.status(500).json({error:'Server error. Please try again.'})});
const startSession=(res,payload)=>res.cookie('gb',jwt.sign(payload,SECRET,{expiresIn:'1d'}),{httpOnly:true,sameSite:'strict',secure:prod,maxAge:864e5});
const need=role=>(req,res,next)=>{try{const u=jwt.verify(req.cookies.gb,SECRET);if(u.role!==role)throw 0;req.user=u;next()}catch{res.status(401).json({error:'Please log in.'})}};

const tx=process.env.SMTP_HOST&&mail.createTransport({host:process.env.SMTP_HOST,port:+process.env.SMTP_PORT||587,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}});
const notify=(name,b)=>tx&&tx.sendMail({from:process.env.SMTP_USER,to:process.env.ADMIN_EMAIL,subject:`New booking: ${b.service} - ${name}`,
 text:`Customer: ${name}\nService: ${b.service}\nLocation: ${b.location}\nDate: ${b.date}\nNotes: ${b.message||'-'}`});

// ---- auth
app.post('/api/register',limiter,wrap(async(req,res)=>{
  const {full_name,phone,email,password}=req.body,e=[];
  if(!full_name||full_name.trim().length<2)e.push('Enter your full name.');
  if(!/^0\d{9}$/.test(phone||''))e.push('Enter a valid 10-digit phone number.');
  if(!/^\S+@\S+\.\S+$/.test(email||''))e.push('Enter a valid email address.');
  if(!password||password.length<8)e.push('Password must be at least 8 characters.');
  if(e.length)return res.status(400).json({error:e.join(' ')});
  try{await db.query('INSERT INTO users(full_name,phone,email,password) VALUES($1,$2,$3,$4)',[full_name.trim(),phone,email.toLowerCase(),await bcrypt.hash(password,12)]);res.json({ok:true})}
  catch(x){if(x.code==='23505')return res.status(409).json({error:'That email is already registered.'});throw x}}));
app.post('/api/login',limiter,wrap(async(req,res)=>{
  const {rows:[u]}=await db.query('SELECT * FROM users WHERE email=$1',[String(req.body.email||'').toLowerCase()]);
  if(!u||!await bcrypt.compare(String(req.body.password||''),u.password))return res.status(401).json({error:'Incorrect email or password.'});
  startSession(res,{id:u.id,role:'user',name:u.full_name});res.json({name:u.full_name})}));
app.post('/api/admin/login',limiter,wrap(async(req,res)=>{
  const {rows:[a]}=await db.query('SELECT * FROM admins WHERE username=$1',[String(req.body.username||'')]);
  if(!a||!await bcrypt.compare(String(req.body.password||''),a.password))return res.status(401).json({error:'Incorrect username or password.'});
  startSession(res,{id:a.id,role:'admin',name:a.username});res.json({ok:true})}));
app.post('/api/logout',(req,res)=>res.clearCookie('gb').json({ok:true}));
app.get('/api/me',(req,res)=>{try{const {role,name}=jwt.verify(req.cookies.gb,SECRET);res.json({role,name})}catch{res.json({role:null})}});

// ---- customer bookings
app.get('/api/bookings',need('user'),wrap(async(req,res)=>res.json((await db.query('SELECT * FROM bookings WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id])).rows)));
app.post('/api/bookings',need('user'),wrap(async(req,res)=>{
  const b=req.body;
  if(!SERVICES.includes(b.service)||!String(b.location||'').trim()||!/^\d{4}-\d{2}-\d{2}$/.test(b.date||'')||b.date<new Date().toISOString().slice(0,10))
    return res.status(400).json({error:'Choose a service, enter your location and pick a future date.'});
  await db.query('INSERT INTO bookings(user_id,service,location,bedrooms,frequency,date,message) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [req.user.id,b.service,b.location.trim().slice(0,200),b.bedrooms||null,b.frequency||null,b.date,String(b.message||'').slice(0,1000)]);
  Promise.resolve(notify(req.user.name,b)).catch(console.error);res.json({ok:true})}));

// ---- admin
app.get('/api/admin/bookings',need('admin'),wrap(async(req,res)=>res.json((await db.query('SELECT b.*,u.full_name,u.phone,u.email FROM bookings b JOIN users u ON u.id=b.user_id ORDER BY b.created_at DESC')).rows)));
app.patch('/api/admin/bookings/:id',need('admin'),wrap(async(req,res)=>{
  if(!STATUSES.includes(req.body.status))return res.status(400).json({error:'Invalid status.'});
  await db.query('UPDATE bookings SET status=$1 WHERE id=$2',[req.body.status,+req.params.id||0]);res.json({ok:true})}));
app.get('/api/admin/customers',need('admin'),wrap(async(req,res)=>res.json((await db.query('SELECT u.id,u.full_name,u.phone,u.email,u.created_at,COUNT(b.id)::int AS bookings FROM users u LEFT JOIN bookings b ON b.user_id=u.id GROUP BY u.id ORDER BY u.created_at DESC')).rows)));

// ---- cancel / reschedule (customer can only touch their own bookings)
const mine=async(req,res)=>{const {rows:[b]}=await db.query('SELECT * FROM bookings WHERE id=$1 AND user_id=$2',[+req.params.id||0,req.user.id]);
  if(!b)res.status(404).json({error:'Booking not found.'});else if(!['Pending','Confirmed'].includes(b.status)){res.status(400).json({error:'This booking can no longer be changed.'});return null}return b};
app.patch('/api/bookings/:id/cancel',need('user'),wrap(async(req,res)=>{const b=await mine(req,res);if(!b)return;
  await db.query("UPDATE bookings SET status='Cancelled' WHERE id=$1",[b.id]);
  Promise.resolve(notify(req.user.name,{...b,service:'CANCELLED: '+b.service})).catch(console.error);res.json({ok:true})}));
app.patch('/api/bookings/:id/reschedule',need('user'),wrap(async(req,res)=>{const b=await mine(req,res);if(!b)return;const d=String(req.body.date||'');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(d)||d<new Date().toISOString().slice(0,10))return res.status(400).json({error:'Pick a future date.'});
  await db.query("UPDATE bookings SET date=$1,status='Pending' WHERE id=$2",[d,b.id]);
  Promise.resolve(notify(req.user.name,{...b,date:d,service:'RESCHEDULED: '+b.service})).catch(console.error);res.json({ok:true})}));

app.listen(process.env.PORT||3000,()=>console.log('Golden Broom running on port',process.env.PORT||3000));
