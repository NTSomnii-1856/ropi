'use strict';
const GateCrypto=(()=>{
  const normalize=code=>code.normalize('NFKC').trim().toUpperCase().replace(/[\s\-–—]/g,'');
  const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  async function unlock(payload,code){
    if(payload.version!==1||payload.algorithm!=='AES-GCM'||payload.kdf!=='PBKDF2'||payload.hash!=='SHA-256'||payload.iterations!==600000)throw Error('Unsupported payload');
    const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(normalize(code)),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode(payload.salt),iterations:payload.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
    const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(payload.iv),tagLength:128,additionalData:new TextEncoder().encode('ropi|v1|lessons')},key,decode(payload.ciphertext));
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  }
  return {normalize,unlock};
})();
if(typeof module!=='undefined')module.exports=GateCrypto;
if(typeof document!=='undefined')(()=>{
  const form=document.querySelector('#entry-form'),input=document.querySelector('#class-code'),message=document.querySelector('#entry-message'),button=document.querySelector('#enter');
  let busy=false;
  document.querySelector('#show-code').onclick=()=>{const show=input.type==='password';input.type=show?'text':'password';document.querySelector('#show-code').textContent=show?'Απόκρυψη':'Εμφάνιση';document.querySelector('#show-code').setAttribute('aria-pressed',String(show));document.querySelector('#show-code').setAttribute('aria-label',show?'Απόκρυψη κωδικού':'Εμφάνιση κωδικού');};
  form.addEventListener('submit',async e=>{e.preventDefault();if(busy)return;busy=true;button.disabled=true;message.textContent='Άνοιγμα μαθημάτων…';let code=input.value;input.value='';
    try{
      if(!crypto?.subtle)throw Error('crypto-unavailable');
      const response=await fetch('lessons.enc.json',{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});if(!response.ok)throw Error('load-failed');
      const payload=await response.json();let html=await GateCrypto.unlock(payload,code);code='';
      const bar='<div id="gate-access-bar"><span>Φυσική Γ΄ Λυκείου · Μέρος Α΄</span><button id="gate-lock" type="button">Κλείδωμα</button></div>';
      const styles='<style>body{padding-top:34px!important}#gate-access-bar{position:fixed;top:0;left:0;right:0;z-index:90;height:34px;display:flex;justify-content:space-between;align-items:center;padding:0 15px;background:#edf5ef;border-bottom:1px solid #dce5dc;font:11px Arial;color:#203f47}#gate-lock{min-height:28px;border:0;background:none;padding:3px 8px;font:12px Arial;color:#255f6b;cursor:pointer}.quiet-layout aside.open,.quiet-layout.focus-mode aside.open{top:112px!important;max-height:calc(100vh - 112px)!important}</style>';
      const hooks='<script>document.querySelector("#gate-lock").addEventListener("click",()=>location.reload());window.addEventListener("pageshow",event=>{if(event.persisted)location.reload();});<\/script>';
      html=html.replace('</head>',styles+'</head>').replace(/<body([^>]*)>/i,(_,attrs)=>'<body'+attrs+'>'+bar).replace('</body>',hooks+'</body>');
      document.open();document.write(html);document.close();html='';
    }catch(error){code='';message.textContent=error.message==='crypto-unavailable'?'Άνοιξε τη σελίδα σε σύγχρονο φυλλομετρητή με HTTPS.':error.message==='load-failed'||error instanceof TypeError?'Δεν φορτώθηκαν τα μαθήματα. Έλεγξε τη σύνδεση και δοκίμασε ξανά.':'Ο κωδικός δεν είναι σωστός. Δοκίμασε ξανά.';input.focus();}
    finally{code='';busy=false;button.disabled=false;}
  });
})();
