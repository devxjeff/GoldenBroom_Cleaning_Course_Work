require('dotenv').config();const {Pool}=require('pg'),bcrypt=require('bcryptjs');
(async()=>{const {ADMIN_USER:u,ADMIN_PASS:p}=process.env;if(!u||!p||p.length<10)throw new Error('Set ADMIN_USER and an ADMIN_PASS of 10+ characters in .env');
const db=new Pool({connectionString:process.env.DATABASE_URL});
await db.query('INSERT INTO admins(username,password) VALUES($1,$2) ON CONFLICT(username) DO UPDATE SET password=$2',[u,await bcrypt.hash(p,12)]);
console.log('Admin ready:',u);await db.end()})().catch(e=>{console.error(e.message);process.exit(1)});
