import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.0';
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from './config.js';

const $ = (id) => document.getElementById(id);
const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);
const state = { user: null, profile: null, chats: [], peer: null, messages: [], channel: null, mode: 'signup', encodingOpen: false };
const COLORS = ['#354b60','#4a3c61','#31574f','#634a40','#3c4e70','#5c4654'];
let toastTimer;
const normalizeId = (value) => value.trim().replace(/^@/, '').toLowerCase();
const escapeText = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const initials = (name) => (name || '?').trim().split(/\s+/).slice(0,2).map(part => part[0] || '').join('').toUpperCase();
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
  const {data,error}=await supabase.from('profiles').select('id,username,display_name').eq('id',user.id).maybeSingle();
  if(error) throw error;
  state.profile=data;
  if(!data) { showToast('Profil belum ditemukan. Coba keluar lalu daftar kembali.'); return; }
  renderProfile(); await loadChats();
}
async function loadChats() {
  const {data:sent,error:sentError}=await supabase.from('messages').select('recipient_id').eq('sender_id',state.user.id).limit(500);
  const {data:received,error:receivedError}=await supabase.from('messages').select('sender_id').eq('recipient_id',state.user.id).limit(500);
  if(sentError||receivedError) { showToast('Gagal memuat daftar chat. Periksa setup database.'); return; }
  const ids=[...new Set([...(sent||[]).map(x=>x.recipient_id),...(received||[]).map(x=>x.sender_id)])].filter(id=>id!==state.user.id);
  if(!ids.length){state.chats=[];renderChats();return;}
  const {data:profiles,error}=await supabase.from('profiles').select('id,username,display_name').in('id',ids);
  if(error){showToast('Tidak bisa memuat profil teman.');return;}
  state.chats=profiles||[]; state.chats.sort((a,b)=>a.display_name.localeCompare(b.display_name)); renderChats();
}
async function findFriend(id) {
  const {data,error}=await supabase.from('profiles').select('id,username,display_name').eq('username',normalizeId(id)).maybeSingle();
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
async function openConversation(peerId) {
  const peer=state.chats.find(chat=>chat.id===peerId);
  if(!peer) return;
  state.peer=peer; state.messages=[];
  $('welcomeView').classList.add('hidden'); $('chatView').classList.remove('hidden');
  $('headerTitle').textContent=peer.display_name;
  $('peerAvatar').textContent=initials(peer.display_name); $('peerAvatar').style.background=COLORS[peer.username.charCodeAt(0)%COLORS.length];
  $('peerName').textContent=peer.display_name; $('peerId').textContent='@'+peer.username;
  $('messageInput').disabled=false; $('sendBtn').disabled=false; $('messageInput').focus();
  renderChats(); renderMessages();
  if(state.channel){await supabase.removeChannel(state.channel);state.channel=null;}
  const {data,error}=await supabase.from('messages').select('id,sender_id,recipient_id,body,created_at').or(`and(sender_id.eq.${state.user.id},recipient_id.eq.${peer.id}),and(sender_id.eq.${peer.id},recipient_id.eq.${state.user.id})`).order('created_at',{ascending:true}).limit(300);
  if(error){showToast('Gagal memuat pesan. Periksa kebijakan RLS database.');return;}
  state.messages=data||[]; renderMessages();
  state.channel=supabase.channel('chat:'+ [state.user.id,peer.id].sort().join(':'))
    .on('postgres_changes',{event:'INSERT',schema:'public',table:'messages',filter:`recipient_id=eq.${state.user.id}`},payload=>handleIncoming(payload.new))
    .on('postgres_changes',{event:'INSERT',schema:'public',table:'messages',filter:`sender_id=eq.${state.user.id}`},payload=>handleIncoming(payload.new))
    .subscribe(status=>{if(status==='CHANNEL_ERROR')setConnection(false,'Realtime bermasalah');});
}
function handleIncoming(message) {
  if(!state.peer||![state.user.id,state.peer.id].includes(message.sender_id)||![state.user.id,state.peer.id].includes(message.recipient_id)) return;
  if(state.messages.some(item=>item.id===message.id)) return;
  state.messages.push(message);state.messages.sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));renderMessages();
  if(message.sender_id!==state.user.id) renderChats();
}
function renderMessages() {
  const box=$('messages');
  if(!state.messages.length){box.innerHTML='<div class="message-empty">Ini awal percakapan kalian.<br>Kirim pesan pertama 👋</div>';}
  else {
    box.innerHTML=state.messages.map(message=>{
      const mine=message.sender_id===state.user.id;
      const time=new Date(message.created_at).toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'});
      return `<article class="message-row ${mine?'mine':''}"><div class="message-author">${mine?'Kamu':escapeText(state.peer?.display_name||'Teman')}</div><div class="message-bubble">${escapeText(message.body)}</div><div class="message-time">${time}</div></article>`;
    }).join('');
  }
  box.scrollTop=box.scrollHeight;
  const latest=[...state.messages].reverse().find(message=>message.body);
  if(latest && state.encodingOpen) renderEncoding(latest.body);
}
async function sendMessage(event) {
  event.preventDefault();
  const body=$('messageInput').value.trim();
  if(!body||!state.peer||!state.user) return;
  $('sendBtn').disabled=true;
  const {data,error}=await supabase.from('messages').insert({sender_id:state.user.id,recipient_id:state.peer.id,body}).select('id,sender_id,recipient_id,body,created_at').single();
  $('sendBtn').disabled=false;
  if(error){showToast(error.message.includes('row-level security')?'Pesan ditolak oleh aturan keamanan database. Periksa schema.sql.':'Pesan gagal dikirim. Periksa koneksi.');return;}
  handleIncoming(data);$('messageInput').value='';resizeComposer();updateCharCount();
}
function resizeComposer(){const input=$('messageInput');input.style.height='auto';input.style.height=Math.min(input.scrollHeight,130)+'px';}
function updateCharCount(){$('charCount').textContent=$('messageInput').value.length+' / 2000';}
function bytesToBits(text){return Array.from(new TextEncoder().encode(text)).map(byte=>byte.toString(2).padStart(8,'0')).join('');}
function renderEncoding(text) {
  const source=$('encodingSource').value==='sample'?'10110010':bytesToBits(text||'');
  const bits=source.slice(0,64);
  const start=$('initialLevel').value==='high'?1:0;
  $('bitStrip').innerHTML=bits.split('').map((bit,index)=>`<span class="bit-cell ${bit==='1'?'transition':''}" title="Bit ${index+1}: ${bit}">${bit}</span>`).join('');
  const width= Math.max(360,bits.length*20), left=18, top=15, bottom=116, cell=(width-left*2)/Math.max(bits.length,1);
  let level=start, path='', labels='', grid='';
  for(let i=0;i<=bits.length;i++){const x=left+i*cell;grid+=`<path d="M${x} ${top}V${bottom}"/>`;if(i<bits.length){if(bits[i]==='1')level=1-level;const y=level?38:92;if(i===0)path+=`M${x} ${y}`;path+=`H${x+cell}`;labels+=`<text x="${x+cell/2}" y="137" text-anchor="middle">${bits[i]}</text>`;}}
  $('nrzWave').setAttribute('viewBox',`0 0 ${width} 150`);
  $('nrzWave').innerHTML=`<path class="grid" d="M${left} 38H${width-left} M${left} 92H${width-left}"/>${grid}<path class="signal" d="${path}"/>${labels}<text x="3" y="41">H</text><text x="3" y="95">L</text>`;
  $('encodingSummary').textContent=`Menampilkan ${bits.length} bit pertama dari UTF-8 pesan (${new TextEncoder().encode(text||'').length} byte). Setiap bit 1 membalik level sinyal; bit 0 mempertahankan level. Grafik ini simulasi line coding, bukan enkripsi.`;
}
function toggleEncoding(open) {
  state.encodingOpen=open;
  $('encodingPanel').classList.toggle('hidden',!open);
  if(open){const latest=[...state.messages].reverse().find(message=>message.body);renderEncoding(latest?.body||'10110010');$('encodingPanel').scrollIntoView({behavior:'smooth',block:'nearest'});}
}
async function handleAuthSubmit(event) {
  event.preventDefault();feedback('authFeedback','Memproses…');
  const email=$('authEmail').value.trim(),password=$('authPassword').value;
  try {
    if(state.mode==='signup') {
      const username=normalizeId($('customId').value),display_name=$('displayName').value.trim();
      if(!/^[a-z0-9_]{3,20}$/.test(username)){feedback('authFeedback','ID harus 3–20 karakter: huruf, angka, atau garis bawah.');return;}
      if(display_name.length<1){feedback('authFeedback','Isi nama tampilan.');return;}
      const {data,error}=await supabase.auth.signUp({email,password,options:{data:{username,display_name}}});
      if(error)throw error;
      if(data.user && !data.session){feedback('authFeedback','Akun dibuat. Cek email untuk verifikasi, lalu masuk. Jika verifikasi email dimatikan, kamu akan langsung masuk.',true);setAuthMode('login');$('authEmail').value=email;return;}
      if(data.session){await ensureProfile(data.user,username,display_name);closeModal('authModal');showToast('Akun berhasil dibuat!');}
    } else {
      const {error}=await supabase.auth.signInWithPassword({email,password});if(error)throw error;closeModal('authModal');showToast('Berhasil masuk.');
    }
  } catch(error) {
    const message=error.message||'Terjadi kesalahan.';
    feedback('authFeedback',message.includes('duplicate key')||message.includes('profiles_username_key')?'ID itu sudah dipakai. Coba ID lain.':message);
  }
}
async function ensureProfile(user,username,display_name) {
  const {error}=await supabase.from('profiles').upsert({id:user.id,username,display_name},{onConflict:'id'});
  if(error)throw error;
}
async function signOut() {await supabase.auth.signOut();state.user=null;state.profile=null;state.chats=[];state.peer=null;if(state.channel)await supabase.removeChannel(state.channel);state.channel=null;renderChats();$('chatView').classList.add('hidden');$('welcomeView').classList.remove('hidden');$('headerTitle').textContent='Selamat datang';$('myName').textContent='Belum login';$('myId').textContent='@—';$('myAvatar').textContent='?';setConnection(false,'Belum terhubung');openModal('authModal');setAuthMode('login');}
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
$('messageForm').addEventListener('submit',sendMessage);
$('messageInput').addEventListener('input',()=>{resizeComposer();updateCharCount();});
$('messageInput').addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();$('messageForm').requestSubmit();}});
$('addChatBtn').addEventListener('click',()=>{if(!state.user){openModal('authModal');return;}feedback('newChatFeedback','');$('friendId').value='';openModal('newChatModal');$('friendId').focus();});
$('welcomeStart').addEventListener('click',()=>state.user?$('addChatBtn').click():openModal('authModal'));
$('newChatForm').addEventListener('submit',async event=>{event.preventDefault();await startChatById($('friendId').value);});
$('logoutBtn').addEventListener('click',()=>{if(state.user)signOut();else openModal('authModal');});
$('profileBtn').addEventListener('click',()=>state.profile?showToast('ID kamu: @'+state.profile.username):openModal('authModal'));
$('peerInfoBtn').addEventListener('click',()=>state.peer&&showToast('ID teman: @'+state.peer.username));
$('encodingToggle').addEventListener('click',()=>toggleEncoding(!state.encodingOpen));
$('closeEncoding').addEventListener('click',()=>toggleEncoding(false));
$('learnNrz').addEventListener('click',()=>toggleEncoding(true));
$('encodingSource').addEventListener('change',()=>{const latest=[...state.messages].reverse().find(message=>message.body);renderEncoding(latest?.body||'10110010');});
$('initialLevel').addEventListener('change',()=>{const latest=[...state.messages].reverse().find(message=>message.body);renderEncoding(latest?.body||'10110010');});
$('mobileMenu').addEventListener('click',()=>$('sidebar').classList.toggle('open'));
document.querySelectorAll('[data-close]').forEach(button=>button.addEventListener('click',()=>closeModal(button.dataset.close)));
document.querySelectorAll('.modal-backdrop').forEach(backdrop=>backdrop.addEventListener('click',event=>{if(event.target===backdrop)closeModal(backdrop.id);}));
document.querySelectorAll('.auth-tab').forEach(button=>button.addEventListener('click',()=>setAuthMode(button.dataset.mode)));
init();