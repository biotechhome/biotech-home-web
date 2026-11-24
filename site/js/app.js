// Public config only (publishable key is safe to expose; security is enforced by RLS).
const SUPABASE_URL='https://sxwqmghmpineouxhjwdw.supabase.co';
const SUPABASE_KEY='sb_publishable_7I-iPhzPnTEW2y2GtEA3oQ_xPcbNjuR';
const sb=window.supabase.createClient(SUPABASE_URL,SUPABASE_KEY,{auth:{persistSession:true,autoRefreshToken:true}});
const $=(s,r=document)=>r.querySelector(s);
function say(el,text,ok){el.className='msg '+(ok?'ok':'err');el.textContent=text}
function bnErr(e){const m=(e&&e.message||'').toLowerCase();
 if(m.includes('invalid login'))return 'তথ্য ঠিক নেই। আবার চেষ্টা করুন।';
 if(m.includes('already'))return 'এই মোবাইল নম্বর দিয়ে আগেই নিবন্ধন করা আছে।';
 if(m.includes('rate')||m.includes('too many'))return 'অনেকবার চেষ্টা হয়েছে, কিছুক্ষণ পরে আবার চেষ্টা করুন।';
 return 'কিছু একটা সমস্যা হয়েছে। আবার চেষ্টা করুন।'}
const MOBILE=/^01[3-9][0-9]{8}$/;
const mEmail=m=>m+'@m.biotechhome.invalid', sEmail=c=>c.toLowerCase()+'@s.biotechhome.invalid';
async function getProfile(){const {data:{session}}=await sb.auth.getSession();if(!session)return null;
 const {data}=await sb.from('profiles').select('id,full_name,role,status,student_type,student_code,mobile').eq('id',session.user.id).maybeSingle();return data}
async function requireLogin(){const p=await getProfile();if(!p){location.href='login.html';return null}return p}
async function logout(){await sb.auth.signOut();location.href='login.html'}
// light deterrents only (real protection is server-side)
document.addEventListener('contextmenu',e=>{if(e.target.closest('.wm'))e.preventDefault()});

// theme toggle (saved per browser)
(function(){const r=document.documentElement;function ap(t){r.dataset.theme=t;const b=document.getElementById('theme');if(b)b.textContent=t==='dark'?'☀️':'🌙'}
 let t='light';try{t=localStorage.getItem('bh-theme')||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}catch(_){}
 ap(t);document.addEventListener('DOMContentLoaded',()=>{ap(r.dataset.theme);const b=document.getElementById('theme');if(b)b.onclick=()=>{const n=r.dataset.theme==='dark'?'light':'dark';ap(n);try{localStorage.setItem('bh-theme',n)}catch(_){}}})})();
