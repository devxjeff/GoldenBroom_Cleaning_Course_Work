(()=>{const r=document.documentElement,k='gb-theme';let t;try{t=localStorage.getItem(k)}catch{}t=t==='light'?'light':'dark';r.dataset.theme=t;
const paint=()=>document.querySelectorAll('.theme-toggle').forEach(b=>{const d=r.dataset.theme==='dark';b.textContent=d?'☀️':'🌙';b.setAttribute('aria-label',d?'Switch to light mode':'Switch to dark mode')});
addEventListener('DOMContentLoaded',()=>{paint();document.querySelectorAll('.theme-toggle').forEach(b=>b.onclick=()=>{r.dataset.theme=r.dataset.theme==='dark'?'light':'dark';try{localStorage.setItem(k,r.dataset.theme)}catch{}paint()})})})();
