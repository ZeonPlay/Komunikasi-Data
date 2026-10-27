import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.0';
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './config.js';

const $ = (id) => document.getElementById(id);
// Antrean lock ini mencegah auth gagal hanya karena tab lain masih memegang lock.
 // Browser modern memakai Web Locks API; jika tidak tersedia, gunakan lock bawaan library.
const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: {
    lock: async (name, _acquireTimeout, fn) => {
      if (typeof navigator !== 'undefined' && navigator.locks?.request) {
        return navigator.locks.request(name, { mode: 'exclusive' }, () => fn());
      }
      // Fallback untuk browser tanpa Web Locks API.
      return fn();
    }
  }
});
const state = { user: null, profile: null, chats: [], peer: null, messages: [], channel: null, mode: 'signup', encodingOpen: false, encodingText: '', privateKey: null, publicKey: null, loginPassword: null };

// E2EE: ECDH P-256 + HKDF-SHA-256 + AES-256-GCM.
// Private key runtime non-extractable disimpan lokal. Cadangan private key dikirim ke Supabase hanya dalam bentuk terenkripsi dengan password akun.
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KEY_DB = 'ruang-e2ee-key-store';
function toBase64(bytes) { let binary=''; for(const byte of bytes) binary+=String.fromCharCode(byte); return btoa(binary); }
function fromBase64(value) { return Uint8Array.from(atob(value), c=>c.charCodeAt(0)); }
function openKeyDb() {
  return new Promise((resolve,reject)=>{
    const request=indexedDB.open(KEY_DB,1);
    request.onupgradeneeded=()=>request.result.createObjectStore('identities',{keyPath:'userId'});
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
}
async function readIdentity(userId) {
  const db=await openKeyDb();
  return new Promise((resolve,reject)=>{
    const request=db.transaction('identities','readonly').objectStore('identities').get(userId);
    request.onsuccess=()=>resolve(request.result||null);
    request.onerror=()=>reject(request.error);
  });
}
async function saveIdentity(identity) {
  const db=await openKeyDb();
  return new Promise((resolve,reject)=>{
    const request=db.transaction('identities','readwrite').objectStore('identities').put(identity);
    request.onsuccess=()=>resolve();
    request.onerror=()=>reject(request.error);
  });
}
async function deriveBackupKey(password, salt) {
  if (!password) throw new Error('Masukkan password akun untuk membuka kunci E2EE di perangkat ini.');
  const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', hash:'SHA-256', salt, iterations:600000},
    material,
    {name:'AES-GCM', length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function encryptPrivateKeyBackup(pkcs8, password) {
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await deriveBackupKey(password,salt);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,pkcs8);
  return JSON.stringify({v:1,salt:toBase64(salt),iv:toBase64(iv),data:toBase64(new Uint8Array(ciphertext))});
}
async function decryptPrivateKeyBackup(backup,password) {
  const envelope=typeof backup==='string'?JSON.parse(backup):backup;
  if(envelope?.v!==1||!envelope.salt||!envelope.iv||!envelope.data) throw new Error('Cadangan kunci tidak valid.');
  const key=await deriveBackupKey(password,fromBase64(envelope.salt));
  try {
    return await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(envelope.iv)},key,fromBase64(envelope.data));
  } catch {
    throw new Error('Password tidak cocok untuk membuka cadangan kunci E2EE. Coba password akun yang benar.');
  }
}
async function writeProfileKeys(userId, publicKey, keyBackup) {
  const {error:profileError}=await supabase.from('profiles').update({public_key:publicKey}).eq('id',userId);
  if(profileError) throw profileError;
  const {error:backupError}=await supabase.from('private_key_backups').upsert({user_id:userId,key_backup:keyBackup,updated_at:new Date().toISOString()},{onConflict:'user_id'});
  if(backupError) throw backupError;
}
async function loadPrivateKeyBackup(userId) {
  const {data,error}=await supabase.from('private_key_backups').select('key_backup').eq('user_id',userId).maybeSingle();
  if(error) throw error;
  return data?.key_backup||null;
}
async function createIdentity(profile,password) {
  if(!password) {
    password=window.prompt('Masukkan password akun untuk membuat cadangan kunci E2EE terenkripsi. Password dipakai lokal dan tidak disimpan oleh aplikasi.');
    if(!password) throw new Error('Penyiapan kunci dibatalkan. Masuk kembali dan masukkan password akun untuk melanjutkan.');
  }
  // Private key sementara dibuat extractable hanya agar bisa dienkripsi sebagai cadangan.
  // Kunci yang dipakai runtime diimpor ulang sebagai non-extractable.
  const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const publicKey=toBase64(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)));
  const pkcs8=await crypto.subtle.exportKey('pkcs8',pair.privateKey);
  const keyBackup=await encryptPrivateKeyBackup(pkcs8,password);
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const identity={userId:profile.id,privateKey,publicKey};
  await writeProfileKeys(profile.id,publicKey,keyBackup);
  await saveIdentity(identity);
  return {...identity,keyBackup};
}
async function restoreIdentity(profile,password) {
  if(!profile.key_backup||!profile.public_key) throw new Error('Cadangan kunci akun belum tersedia. Gunakan perangkat lama yang masih memiliki kunci, atau buat kunci baru dengan sadar bahwa pesan lama mungkin tidak bisa dibuka.');
  if(!password) password=window.prompt('Masukkan password akun untuk membuka kunci E2EE di perangkat ini.');
  if(!password) throw new Error('Pembukaan kunci dibatalkan.');
  const pkcs8=await decryptPrivateKeyBackup(profile.key_backup,password);
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const identity={userId:profile.id,privateKey,publicKey:profile.public_key};
  await saveIdentity(identity);
  return identity;
}
async function ensureIdentity(profile,password) {
  let identity=await readIdentity(profile.id);
  const keyBackup=await loadPrivateKeyBackup(profile.id);
  profile={...profile,key_backup:keyBackup};
  const backupExists=Boolean(profile.key_backup&&profile.public_key);
  if(identity && identity.publicKey===profile.public_key && profile.key_backup) {
    state.privateKey=identity.privateKey;
    state.publicKey=identity.publicKey;
    state.profile={...profile};
    return;
  }
  if(backupExists) {
    identity=await restoreIdentity(profile,password);
  } else {
    if(profile.public_key && !window.confirm('Akun ini masih memakai kunci E2EE versi lama yang tidak memiliki cadangan lintas perangkat. Membuat kunci baru membuat pesan lama yang memakai kunci lama tidak dapat dibuka. Lanjutkan migrasi kunci?')) {
      throw new Error('Migrasi kunci dibatalkan. Perangkat ini tetap perlu kunci cadangan agar bisa dipakai lintas perangkat.');
    }
    identity=await createIdentity(profile,password);
  }
  state.privateKey=identity.privateKey;
  state.publicKey=identity.publicKey;
  state.profile={...profile,public_key:identity.publicKey,key_backup:identity.keyBackup||profile.key_backup};
}
async function importPeerPublicKey(encoded) {
  if(!encoded) throw new Error('Teman belum memiliki kunci publik. Minta teman login ulang setelah migrasi E2EE diterapkan.');
  return crypto.subtle.importKey('raw',fromBase64(encoded),{name:'ECDH',namedCurve:'P-256'},false,[]);
}
async function deriveMessageKey(privateKey, peerPublicKey, userA, userB) {
  const shared=await crypto.subtle.deriveBits({name:'ECDH',public:peerPublicKey},privateKey,256);
  const material=await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveKey']);
  const salt=encoder.encode(['ruang-e2ee-v2',...([userA,userB].sort())].join(':'));
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:encoder.encode('ruang-message-encryption')},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptMessage(plain) {
  if(!state.privateKey||!state.publicKey||!state.peer?.public_key) throw new Error('Kunci E2EE belum siap. Pastikan teman sudah membuat kunci publik.');
  const peerKey=await importPeerPublicKey(state.peer.public_key);
  const key=await deriveMessageKey(state.privateKey,peerKey,state.user.id,state.peer.id);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const aad=encoder.encode(state.user.id+':'+state.peer.id);
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},key,encoder.encode(plain));
  return 'E2EE2:'+toBase64(encoder.encode(JSON.stringify({v:2,senderPublicKey:state.publicKey,iv:toBase64(iv),data:toBase64(new Uint8Array(data))})));
}
async function decryptMessage(message) {
  if(!message.body?.startsWith('E2EE2:')) {
    if(message.body?.startsWith('E2EE1:')) return {...message,plaintext:'🔒 Pesan lama memakai format passphrase; tidak dapat dibuka dengan kunci E2EE baru.',encrypted:true,undecryptable:true};
    return {...message,plaintext:message.body,encrypted:false};
  }
  try {
    if(!state.privateKey||!state.peer?.public_key) throw new Error('Kunci belum tersedia');
    const envelope=JSON.parse(decoder.decode(fromBase64(message.body.slice(6))));
    if(envelope.v!==2||!envelope.senderPublicKey||!envelope.iv||!envelope.data) throw new Error('Format tidak dikenal');
    let peerKey;
    if(message.sender_id===state.user.id) {
      peerKey=await importPeerPublicKey(state.peer.public_key);
    } else {
      if(envelope.senderPublicKey!==state.peer.public_key) throw new Error('Kunci pengirim tidak cocok dengan kunci publik profil');
      peerKey=await importPeerPublicKey(envelope.senderPublicKey);
    }
    const key=await deriveMessageKey(state.privateKey,peerKey,state.user.id,state.peer.id);
    const aad=encoder.encode(message.sender_id+':'+message.recipient_id);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(envelope.iv),additionalData:aad},key,fromBase64(envelope.data));
    return {...message,plaintext:decoder.decode(plain),encrypted:true};
  } catch {
    return {...message,plaintext:'🔒 Pesan terkunci — kunci tidak cocok atau pesan tidak valid.',encrypted:true,undecryptable:true};
  }
}
const COLORS = ['#354b60','#4a3c61','#31574f','#634a40','#3c4e70','#5c4654'];
let toastTimer;
const normalizeId = (value) => value.trim().replace(/^@/, '').toLowerCase();
const escapeText = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const initials = (name) => (name || '?').trim().split(/\s+/).slice(0,2).map(part => part[0] || '').join('').toUpperCase();
function isPlaceholderProfile(profile) { return /^u_[0-9a-f]{16}$/.test(profile?.username || ''); }
function showToast(message) { const el=$('toast'); el.textContent=message; el.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.classList.remove('show'),3000); }
function setConnection(online, message) { $('statusDot').classList.toggle('online', online); $('connectionText').textContent=message; }
function openModal(id) { $(id).classList.remove('hidden'); }
function closeModal(id) { $(id).classList.add('hidden'); }
function feedback(id, message, success=false) { const el=$(id); el.textContent=message; el.classList.toggle('success',success); }
function setAuthMode(mode) {
  state.mode=mode;
  document.querySelectorAll('.auth-tab').forEach(tab=>tab.classList.toggle('active',tab.dataset.mode===mode));
  $('authTitle').textContent=mode==='signup'?'Gabung ke percakapan.':'Senang bertemu lagi.';
  $('authDescription').textContent=mode==='signup'?'Buat akun untuk mendapatkan ID unik dan chat temanmu.':'Masuk dengan email dan kata sandi akunmu.';
  $('nameLabel').classList.toggle('hidden',mode==='login'); $('displayName').classList.toggle('hidden',mode==='login');
  $('customId').closest('label')?.classList.toggle('hidden',mode==='login');
  $('customId').parentElement.classList.toggle('hidden',mode==='login');
  $('customId').required=mode==='signup'; $('displayName').required=mode==='signup';
  $('authSubmit').innerHTML=mode==='signup'?'Buat akun <span>↗</span>':'Masuk <span>↗</span>';
  feedback('authFeedback','');
}
function renderProfile() {
  if(!state.profile) return;
  $('myAvatar').textContent=initials(state.profile.display_name);
  $('myAvatar').style.background=COLORS[state.profile.username.charCodeAt(0)%COLORS.length];
  $('myName').textContent=state.profile.display_name;
  $('myId').textContent='@'+state.profile.username;
}
function renderChats() {
  const list=$('chatList');
  if(!state.chats.length){list.innerHTML='<div class="empty-list">Belum ada percakapan.<br>Tekan + untuk mencari teman.</div>';return;}
  list.innerHTML=state.chats.map(chat=>`<button class="chat-item ${state.peer?.id===chat.id?'active':''}" data-peer="${chat.id}"><span class="avatar" style="background:${COLORS[chat.username.charCodeAt(0)%COLORS.length]}">${escapeText(initials(chat.display_name))}</span><span class="chat-item-copy"><strong>${escapeText(chat.display_name)}</strong><small>@${escapeText(chat.username)}</small></span></button>`).join('');
  list.querySelectorAll('[data-peer]').forEach(button=>button.addEventListener('click',()=>openConversation(button.dataset.peer)));
}
async function loadProfile(user) {
  const {data,error}=await supabase.from('profiles').select('id,username,display_name,public_key').eq('id',user.id).maybeSingle();
  if(error) throw error;
  if(!data) { showToast('Profil belum ditemukan. Periksa trigger handle_new_user di database.'); return; }
  try { await ensureIdentity(data,state.loginPassword); state.loginPassword=null; }
  catch(keyError) { state.loginPassword=null; showToast('Gagal menyiapkan E2EE: '+keyError.message); throw keyError; }
  renderProfile();
  if(isPlaceholderProfile(data)) {
    state.chats=[]; renderChats();
    openProfileEditor();
    return;
  }
  closeModal('profileModal');
  await loadChats();
}
function openProfileEditor() {
  if(!state.user) { openModal('authModal'); return; }
  const pending=isPlaceholderProfile(state.profile);
  $('profileModalTitle').textContent=pending?'Lengkapi profil':'Pengaturan akun';
  $('profileModalDescription').textContent=pending
    ?'Akunmu sudah aktif. Pilih nama tampilan dan ID chat supaya temanmu bisa menemukanmu.'
    :'Ubah nama tampilan dan ID chat yang digunakan temanmu untuk menghubungimu.';
  $('profileCloseBtn').classList.toggle('hidden',pending);
  $('profileDisplayName').value=pending?'':(state.profile?.display_name||'');
  $('profileUsername').value=pending?'':(state.profile?.username||'');
  feedback('profileFeedback','');
  openModal('profileModal');
  $('profileDisplayName').focus();
}
async function loadChats() {
  const {data:sent,error:sentError}=await supabase.from('messages').select('recipient_id').eq('sender_id',state.user.id).limit(500);
  const {data:received,error:receivedError}=await supabase.from('messages').select('sender_id').eq('recipient_id',state.user.id).limit(500);
  if(sentError||receivedError) { showToast('Gagal memuat daftar chat. Periksa setup database.'); return; }
  const ids=[...new Set([...(sent||[]).map(x=>x.recipient_id),...(received||[]).map(x=>x.sender_id)])].filter(id=>id!==state.user.id);
  if(!ids.length){state.chats=[];renderChats();return;}
  const {data:profiles,error}=await supabase.from('profiles').select('id,username,display_name,public_key').in('id',ids);
  if(error){showToast('Tidak bisa memuat profil teman.');return;}
  state.chats=profiles||[]; state.chats.sort((a,b)=>a.display_name.localeCompare(b.display_name)); renderChats();
}
async function findFriend(id) {
  const {data,error}=await supabase.from('profiles').select('id,username,display_name,public_key').eq('username',normalizeId(id)).maybeSingle();
  if(error) throw error;
  return data;
}
async function startChatById(rawId) {
  const id=normalizeId(rawId);
  if(!/^[a-z0-9_]{3,20}$/.test(id)){feedback('newChatFeedback','ID harus 3–20 karakter: huruf, angka, atau garis bawah.');return;}
  if(id===state.profile.username){feedback('newChatFeedback','Itu ID akunmu sendiri. Masukkan ID teman.');return;}
  feedback('newChatFeedback','Mencari akun…');
  try {
    const friend=await findFriend(id);
    if(!friend){feedback('newChatFeedback','ID tidak ditemukan. Minta teman mengecek ID-nya.');return;}
    if(!state.chats.some(chat=>chat.id===friend.id)){state.chats.push(friend);state.chats.sort((a,b)=>a.display_name.localeCompare(b.display_name));}
    renderChats(); closeModal('newChatModal'); feedback('newChatFeedback','');
    await openConversation(friend.id); $('sidebar').classList.remove('open');
  } catch(error){feedback('newChatFeedback',error.message||'Pencarian gagal. Periksa koneksi dan database.');}
}
async function showPeerFingerprint() {
  if(!state.peer?.public_key) { showToast('Teman belum memiliki kunci publik.'); return; }
  const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',fromBase64(state.peer.public_key)));
  const hex=Array.from(digest,byte=>byte.toString(16).padStart(2,'0').toUpperCase()).join('');
  const fingerprint=hex.match(/.{1,4}/g).join(' ');
  window.alert('Fingerprint kunci publik @'+state.peer.username+'\n\n'+fingerprint+'\n\nBandingkan fingerprint ini dengan teman melalui kanal lain (misalnya bertemu langsung atau panggilan yang kamu yakini aman). Jika tidak cocok, jangan kirim pesan sensitif.');
}
async function openConversation(peerId) {
  const peer=state.chats.find(chat=>chat.id===peerId);
  if(!peer) return;
  state.peer=peer; state.messages=[]; state.peer.public_key=peer.public_key; state.encodingOpen=false; state.encodingText='';
  if(!state.privateKey) { showToast('Kunci privat perangkat tidak tersedia. Keluar dan masuk kembali.'); return; }
  if(!peer.public_key) { showToast('Teman belum punya kunci publik. Minta teman login ulang setelah migrasi E2EE.'); return; }
  $('encodingPanel').classList.add('hidden');
  $('encodingToggle').classList.remove('active');
  $('encodingToggle').setAttribute('aria-expanded','false');
  $('encodingTitle').textContent='NRZ-I · @'+peer.username;
  $('encodingSource').value='message';
  $('welcomeView').classList.add('hidden'); $('chatView').classList.remove('hidden');
  $('headerTitle').textContent=peer.display_name;
  $('peerAvatar').textContent=initials(peer.display_name); $('peerAvatar').style.background=COLORS[peer.username.charCodeAt(0)%COLORS.length];
  $('peerName').textContent=peer.display_name; $('peerId').textContent='@'+peer.username;
  $('messageInput').disabled=false; $('sendBtn').disabled=false; $('messageInput').focus();
  renderChats(); renderMessages();
  if(state.channel){await supabase.removeChannel(state.channel);state.channel=null;}
  const {data,error}=await supabase.from('messages').select('id,sender_id,recipient_id,body,created_at').or(`and(sender_id.eq.${state.user.id},recipient_id.eq.${peer.id}),and(sender_id.eq.${peer.id},recipient_id.eq.${state.user.id})`).order('created_at',{ascending:true}).limit(300);
  if(error){showToast('Gagal memuat pesan. Periksa kebijakan RLS database.');return;}
  state.messages=await Promise.all((data||[]).map(decryptMessage)); renderMessages();
  state.channel=supabase.channel('chat:'+ [state.user.id,peer.id].sort().join(':'))
    .on('postgres_changes',{event:'INSERT',schema:'public',table:'messages',filter:`recipient_id=eq.${state.user.id}`},payload=>handleIncoming(payload.new))
    .on('postgres_changes',{event:'INSERT',schema:'public',table:'messages',filter:`sender_id=eq.${state.user.id}`},payload=>handleIncoming(payload.new))
    .subscribe(status=>{if(status==='CHANNEL_ERROR')setConnection(false,'Realtime bermasalah');});
}
function handleIncoming(message) {
  if(!state.peer||![state.user.id,state.peer.id].includes(message.sender_id)||![state.user.id,state.peer.id].includes(message.recipient_id)) return;
  if(state.messages.some(item=>item.id===message.id)) return;
  decryptMessage(message).then(decoded=>{ if(state.messages.some(item=>item.id===decoded.id)) return; state.messages.push(decoded);state.messages.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));renderMessages(); });
  if(message.sender_id!==state.user.id) renderChats();
}
function renderMessages() {
  const box=$('messages');
  if(!state.messages.length){
    box.innerHTML='<div class="message-empty">Ini awal percakapan kalian.<br>Kirim pesan pertama 👋</div>';
  } else {
    box.innerHTML=state.messages.map((message,index)=>{
      const mine=message.sender_id===state.user.id;
      const time=new Date(message.created_at).toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'});
      return `<article class="message-row ${mine?'mine':''}">
        <div class="message-author">${mine?'Kamu':escapeText(state.peer?.display_name||'Teman')}</div>
        <div class="message-bubble">${escapeText(message.plaintext ?? message.body)}</div>
        <div class="message-meta-row">
          <div class="message-time">${time}</div>
          <button type="button" class="message-encoding-toggle" data-encode-index="${index}" aria-label="Lihat visualisasi NRZ-I untuk pesan ${index+1}">NRZ-I</button>
        </div>
      </article>`;
    }).join('');
    box.querySelectorAll('[data-encode-index]').forEach(button=>button.addEventListener('click',()=>{
      const message=state.messages[Number(button.dataset.encodeIndex)];
      if(message) toggleEncoding(true,message.body);
    }));
  }
  box.scrollTop=box.scrollHeight;
  if(state.encodingOpen) renderEncoding(state.encodingText || '10110010');
}
async function sendMessage(event) {
  event.preventDefault();
  const body=$('messageInput').value.trim();
  if(!body||!state.peer||!state.user) return;
  $('sendBtn').disabled=true;
  if(!state.privateKey||!state.peer?.public_key) { showToast('Kunci E2EE belum siap. Pastikan kunci publik teman tersedia.'); $('sendBtn').disabled=false; return; }
  let encryptedBody; try { encryptedBody=await encryptMessage(body); } catch(error) { showToast(error.message); $('sendBtn').disabled=false; return; }
  const {data,error}=await supabase.from('messages').insert({sender_id:state.user.id,recipient_id:state.peer.id,body:encryptedBody}).select('id,sender_id,recipient_id,body,created_at').single();
  $('sendBtn').disabled=false;
  if(error){showToast(error.message.includes('row-level security')?'Pesan ditolak oleh aturan keamanan database. Periksa schema.sql.':'Pesan gagal dikirim. Periksa koneksi.');return;}
  state.messages.push({...data,plaintext:body,encrypted:true}); state.messages.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at)); renderMessages(); $('messageInput').value='';resizeComposer();updateCharCount();
}
function resizeComposer(){const input=$('messageInput');input.style.height='auto';input.style.height=Math.min(input.scrollHeight,130)+'px';}
function updateCharCount(){$('charCount').textContent=$('messageInput').value.length+' / 2000';}
function bytesToBits(text){return Array.from(new TextEncoder().encode(text)).map(byte=>byte.toString(2).padStart(8,'0')).join('');}
function renderEncoding(text) {
  const isSample=$('encodingSource').value==='sample';
  const source=isSample?'10110010':bytesToBits(text||'');
  const bits=source.slice(0,64);
  // Konvensi: bit 1 membalik level di AWAL interval; bit 0 mempertahankan level.
  // Level awal adalah level sebelum bit pertama diproses.
  let level=$('initialLevel').value==='high'?1:0;
  $('bitStrip').innerHTML=bits.split('').map((bit,index)=>`<span class="bit-cell ${bit==='1'?'transition':''}" title="Bit ${index+1}: ${bit}">${bit}</span>`).join('');
  const width=Math.max(360,bits.length*20), left=28, top=15, bottom=116;
  const cell=(width-left*2)/Math.max(bits.length,1);
  let path='', labels='', grid='';
  const yFor=(value)=>value?38:92;
  // Level sebelum bit pertama. Untuk setiap bit, gambar transisi vertikal bila bit=1,
  // lalu gambar level horizontal sepanjang satu interval bit.
  path=`M${left} ${yFor(level)}`;
  for(let i=0;i<bits.length;i++) {
    const x=left+i*cell;
    grid+=`<path d="M${x} ${top}V${bottom}"/>`;
    if(bits[i]==='1') {
      level=1-level;
      path+=`V${yFor(level)}`;
    }
    path+=`H${x+cell}`;
    labels+=`<text x="${x+cell/2}" y="137" text-anchor="middle">${bits[i]}</text>`;
  }
  grid+=`<path d="M${left+bits.length*cell} ${top}V${bottom}"/>`;
  $('nrzWave').setAttribute('viewBox',`0 0 ${width} 150`);
  $('nrzWave').innerHTML=`<path class="grid" d="M${left} 38H${width-left} M${left} 92H${width-left}"/>${grid}<path class="signal" d="${path}"/>${labels}<text x="3" y="41">H</text><text x="3" y="95">L</text>`;
  $('encodingSummary').textContent=isSample
    ? 'Contoh bit 10110010. Bit 1 membalik level pada awal interval, sedangkan bit 0 mempertahankan level. Level yang dipilih adalah level sebelum bit pertama.'
    : `Menampilkan ${bits.length} bit pertama dari UTF-8 pesan (${new TextEncoder().encode(text||'').length} byte). Bit 1 membalik level pada awal interval, sedangkan bit 0 mempertahankan level. Ini simulasi line coding, bukan enkripsi.`;
}
function toggleEncoding(open, text) {
  state.encodingOpen=open;
  $('encodingPanel').classList.toggle('hidden',!open);
  $('encodingToggle').classList.toggle('active',open);
  $('encodingToggle').setAttribute('aria-expanded',String(open));
  if(open) {
    const latest=[...state.messages].reverse().find(message=>message.body);
    if(typeof text==='string') {
      state.encodingText=text;
      $('encodingSource').value='message';
    } else if(latest) {
      state.encodingText=latest.body;
      $('encodingSource').value='message';
    } else {
      state.encodingText='10110010';
      $('encodingSource').value='sample';
    }
    renderEncoding(state.encodingText);
    $('encodingPanel').scrollTop=0;
  }
}
async function handleAuthSubmit(event) {
  event.preventDefault();feedback('authFeedback','Memproses…');
  const email=$('authEmail').value.trim(),password=$('authPassword').value;
  try {
    if(state.mode==='signup') {
      const username=normalizeId($('customId').value),display_name=$('displayName').value.trim();
      if(!/^[a-z0-9_]{3,20}$/.test(username)){feedback('authFeedback','ID harus 3–20 karakter: huruf, angka, atau garis bawah.');return;}
      if(/^u_[0-9a-f]{16}$/.test(username)){feedback('authFeedback','ID ini termasuk format internal. Pilih ID lain.');return;}
      if(display_name.length<1||display_name.length>32){feedback('authFeedback','Nama tampilan harus 1–32 karakter.');return;}
      state.loginPassword=password; const {data,error}=await supabase.auth.signUp({email,password,options:{data:{username,display_name}}});
      if(error)throw error;
      if(data.user && !data.session){feedback('authFeedback','Akun dibuat. Cek email untuk verifikasi, lalu masuk. Jika verifikasi email dimatikan, kamu akan langsung masuk.',true);setAuthMode('login');$('authEmail').value=email;return;}
      if(data.session){await ensureProfile(data.user,username,display_name);closeModal('authModal');showToast('Akun berhasil dibuat!');}
    } else {
      state.loginPassword=password; const {error}=await supabase.auth.signInWithPassword({email,password});if(error)throw error;closeModal('authModal');showToast('Berhasil masuk.');
    }
  } catch(error) {
    state.loginPassword=null;
    const message=error.message||'Terjadi kesalahan.';
    feedback('authFeedback',message.includes('duplicate key')||message.includes('profiles_username_key')?'ID itu sudah dipakai. Coba ID lain.':message);
  }
}
async function handleProfileSubmit(event) {
  event.preventDefault();
  if(!state.user) { feedback('profileFeedback','Sesi login tidak ditemukan. Silakan masuk kembali.'); return; }
  const username=normalizeId($('profileUsername').value);
  const display_name=$('profileDisplayName').value.trim();
  if(!/^[a-z0-9_]{3,20}$/.test(username)) {
    feedback('profileFeedback','ID harus 3–20 karakter: huruf kecil, angka, atau garis bawah.'); return;
  }
  if(/^u_[0-9a-f]{16}$/.test(username)) {
    feedback('profileFeedback','ID ini termasuk format internal. Pilih ID lain.'); return;
  }
  if(display_name.length<1||display_name.length>32) {
    feedback('profileFeedback','Nama tampilan harus 1–32 karakter.'); return;
  }
  const button=$('profileSubmit'); button.disabled=true; feedback('profileFeedback','Menyimpan profil…');
  try {
    const {data,error}=await supabase.from('profiles')
      .update({username,display_name}).eq('id',state.user.id)
      .select('id,username,display_name').single();
    if(error) throw error;
    state.profile={...data,public_key:state.publicKey}; renderProfile();
    closeModal('profileModal');
    await loadChats();
    showToast('Profil berhasil disimpan.');
  } catch(error) {
    const message=error.message||'Profil gagal disimpan.';
    feedback('profileFeedback',message.includes('duplicate key')||message.includes('profiles_username_key')
      ?'ID itu sudah dipakai. Coba ID lain.'
      :message);
  } finally { button.disabled=false; }
}
async function ensureProfile(user,username,display_name) {
  const {error}=await supabase.from('profiles').upsert({id:user.id,username,display_name},{onConflict:'id'});
  if(error)throw error;
}
async function signOut() {await supabase.auth.signOut();closeModal('profileModal');state.user=null;state.profile=null;state.chats=[];state.peer=null;if(state.channel)await supabase.removeChannel(state.channel);state.channel=null;renderChats();$('chatView').classList.add('hidden');$('welcomeView').classList.remove('hidden');$('headerTitle').textContent='Selamat datang';$('myName').textContent='Belum login';$('myId').textContent='@—';$('myAvatar').textContent='?';setConnection(false,'Belum terhubung');openModal('authModal');setAuthMode('login');}
async function init() {
  if(!SUPABASE_URL||!SUPABASE_PUBLISHABLE_KEY||SUPABASE_URL.includes('YOUR_PROJECT')) {
    setConnection(false,'Setup diperlukan');
    feedback('authFeedback','Sebelum login, salin config.js.example menjadi config.js dan isi URL serta publishable key Supabase.');
    openModal('authModal');return;
  }
  const {data:{session}}=await supabase.auth.getSession();
  if(session){state.user=session.user;try{await loadProfile(session.user);setConnection(true,'Terhubung');}catch(error){showToast('Profil gagal dimuat: '+error.message);openModal('authModal');}}
  else {openModal('authModal');setAuthMode('signup');}
  supabase.auth.onAuthStateChange(async(_event,session)=>{
    if(session&&!state.user){state.user=session.user;try{await loadProfile(session.user);setConnection(true,'Terhubung');closeModal('authModal');}catch(error){showToast(error.message);}}
    if(!session&&state.user){state.user=null;state.profile=null;setConnection(false,'Belum terhubung');}
  });
}
$('authForm').addEventListener('submit',handleAuthSubmit);
$('profileForm').addEventListener('submit',handleProfileSubmit);
$('messageForm').addEventListener('submit',sendMessage);
$('messageInput').addEventListener('input',()=>{resizeComposer();updateCharCount();});
$('messageInput').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();$('messageForm').requestSubmit();}});
$('addChatBtn').addEventListener('click',()=>{if(!state.user){openModal('authModal');return;}feedback('newChatFeedback','');$('friendId').value='';openModal('newChatModal');$('friendId').focus();});
$('welcomeStart').addEventListener('click',()=>state.user?$('addChatBtn').click():openModal('authModal'));
$('newChatForm').addEventListener('submit',async event=>{event.preventDefault();await startChatById($('friendId').value);});
$('logoutBtn').addEventListener('click',()=>{if(state.user)signOut();else openModal('authModal');});
$('profileBtn').addEventListener('click',openProfileEditor);
$('peerInfoBtn').addEventListener('click',()=>state.peer&&showPeerFingerprint().catch(error=>showToast(error.message||'Fingerprint gagal dibuat.')));
$('encodingToggle').addEventListener('click',()=>toggleEncoding(!state.encodingOpen));
$('closeEncoding').addEventListener('click',()=>toggleEncoding(false));
$('learnNrz').addEventListener('click',()=>showToast('Buka percakapan anggota dulu, lalu tekan NRZ-I pada pesan yang ingin dilihat.'));
$('encodingSource').addEventListener('change',()=>renderEncoding(state.encodingText||'10110010'));
$('initialLevel').addEventListener('change',()=>renderEncoding(state.encodingText||'10110010'));
$('mobileMenu').addEventListener('click',()=>$('sidebar').classList.toggle('open'));
document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>closeModal(button.dataset.close)));
document.querySelectorAll('.modal-backdrop').forEach(backdrop=>backdrop.addEventListener('click',event=>{if(event.target===backdrop&&!(backdrop.id==='profileModal'&&isPlaceholderProfile(state.profile)))closeModal(backdrop.id);}));
document.querySelectorAll('.auth-tab').forEach(button=>button.addEventListener('click',()=>setAuthMode(button.dataset.mode)));
init();