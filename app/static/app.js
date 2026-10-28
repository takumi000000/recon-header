const form=document.querySelector('#scan-form');
const loading=document.querySelector('#loading');
const errorBox=document.querySelector('#error');
const results=document.querySelector('#results');
const esc=value=>String(value??'—').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const row=(key,value)=>`<div><dt>${esc(key)}</dt><dd>${esc(value)}</dd></div>`;

form.addEventListener('submit',async event=>{
  event.preventDefault();
  const domain=document.querySelector('#domain').value.trim();
  const button=form.querySelector('button');
  errorBox.classList.add('hidden');results.classList.add('hidden');loading.classList.remove('hidden');button.disabled=true;
  try{
    const response=await fetch('/v1/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({domain})});
    const data=await response.json();
    if(!response.ok){const detail=Array.isArray(data.detail)?data.detail.map(x=>x.msg).join(' / '):data.detail;throw new Error(detail||'診断に失敗しました');}
    render(data);results.classList.remove('hidden');results.scrollIntoView({behavior:'smooth',block:'start'});
  }catch(error){errorBox.textContent=`診断できませんでした: ${error.message}`;errorBox.classList.remove('hidden');}
  finally{loading.classList.add('hidden');button.disabled=false;}
});

function render(data){
  document.querySelector('#result-domain').textContent=data.domain;
  document.querySelector('#score strong').textContent=data.findings.length;
  document.querySelector('#summary').innerHTML=[`HTTP ${data.status_code??'—'}`,data.tls.version||'TLS —',data.cms.detected||'CMS unknown',...(data.resolved_ips||[])].map(x=>`<span class="pill">${esc(x)}</span>`).join('');
  document.querySelector('#tls-data').innerHTML=row('TLS version',data.tls.version)+row('Cipher',data.tls.cipher)+row('Expires',data.tls.expires_at)+row('Days remaining',data.tls.days_until_expiry)+row('Issuer',data.tls.issuer?.organizationName||data.tls.error);
  document.querySelector('#cms-data').innerHTML=row('Detected',data.cms.detected)+row('Confidence',data.cms.confidence)+row('Signals',(data.cms.signals||[]).join(', '))+row('X-Powered-By',data.cms.x_powered_by);
  document.querySelector('#findings').innerHTML=data.findings.length?data.findings.map(f=>`<div class="finding"><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><div><strong>${esc(f.title)}</strong><p>${esc(f.detail)}</p></div></div>`).join(''):'<p class="info">現在の検査範囲で指摘はありません。</p>';
  document.querySelector('#headers').textContent=Object.entries(data.headers||{}).map(([k,v])=>`${k}: ${v}`).join('\n');
}
