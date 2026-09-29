'use strict';
// Private historic hardware evidence, never a live command or live poll.
(async function () {
  const output=document.getElementById('c320-real-inventory');
  const status=document.getElementById('c320-real-inventory-status');
  if(!output||!status)return;
  try {
    const reply=await fetch('/lab/c320-first-real-inventory',{
      cache:'no-store',credentials:'omit'
    });
    if(!reply.ok)throw new Error('no private historical evidence');
    const r=await reply.json();
    if(r.target!=='DEV-01'||r.mode!=='ACTUAL_HISTORICAL_OWNER_LAB_PHYSICAL_READ_NO_WORKER'
      ||r.recorded_date!=='2026-09-29'||r.observation_is_live!==false
      ||r.owner_restic_isolated_byte_identical_restore_verified!==true
      ||r.device_native_restore_rehearsed!==false
      ||r.real_saas_device_adopted!==false||r.production_worker_enabled!==false
      ||r.dedicated_verified_limited_role_account_exists!==false
      ||!Array.isArray(r.cards)||r.cards.length!==3
      ||!r.cards.every(c=>c.card_reported_status==='INSERVICE'))
      throw new Error('unverifiable server physical evidence');
    const expected=[['1/1/1','GTGHK','GTXK'],['1/1/3','PRAM',null],['1/1/4','SMXA','SMXA']];
    if(r.cards.some((c,i)=>c.slot!==expected[i][0]
      ||c.physical!==expected[i][1]
      ||c.reported_mvr_filetype!==expected[i][2]))throw new Error('unreviewed vendor layout');
    output.replaceChildren();
    for(const c of r.cards){
      const row=document.createElement('div');row.className='physical-gate';
      const version=c.reported_mvr_version===null?'MVR belum terlapor':
        (c.mvr_card_alias_verified?'MVR '+c.reported_mvr_version:'MVR tipe berbeda: BELUM TERKONFIRMASI');
      for(const value of [c.slot,c.physical+' · '+c.card_reported_status,version]){
        const span=document.createElement('span');span.textContent=value;row.append(span);
      }
      output.append(row);
    }
    status.textContent='BUKTI HISTORIS 29 Sep 2026 · 3 kartu terbaca nyata. Backup terenkripsi Restic telah pulih identik; impor konfigurasi vendor, identitas akun terbatas dan worker otomatis BELUM teruji.';
  }catch{
    output.replaceChildren();status.textContent='Bukti historis gagal divalidasi; tidak ada klaim inventaris atau adopsi otomatis.';
  }
})();
