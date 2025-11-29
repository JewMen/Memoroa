/* app.js — 可靠版：強制 modal、清楚提示、支援 fallback */
const noteList = document.getElementById('note-list');
const noteEditor = document.getElementById('note-editor');
const newNoteBtn = document.getElementById('new-note-btn');
const backupBtn = document.getElementById('backupBtn');
const restoreBtn = document.getElementById('restoreBtn');

const pwdModal = document.getElementById('pwd-modal');
const pwdInput = document.getElementById('pwd-input');
const pwdOk = document.getElementById('pwd-ok');
const pwdCancel = document.getElementById('pwd-cancel');
const pwdError = document.getElementById('pwd-error');

let currentNoteId = null;
let saveTimer = null;

/* ---------- notes basic ---------- */
function getNotesFromStorage(){ try{ const j = localStorage.getItem('notes'); return j ? JSON.parse(j) : []; }catch(e){ console.error(e); return []; } }
function persistNotes(notes){ localStorage.setItem('notes', JSON.stringify(notes)); }

function addNoteToSidebar(note, isActive=false){
  const li = document.createElement('li'); li.className='note-item';
  if(isActive) li.classList.add('active');
  li.setAttribute('data-id', note.id);
  const wrapper = document.createElement('div');
  const title = document.createElement('div'); title.className='note-title';
  const preview = document.createElement('div'); preview.className='note-preview';
  wrapper.appendChild(title); wrapper.appendChild(preview);
  const del = document.createElement('button'); del.className='delete-btn'; del.type='button'; del.textContent='×';
  del.onclick = (e)=>{ e.stopPropagation(); deleteNote(note.id); };
  li.appendChild(wrapper); li.appendChild(del);
  li.addEventListener('mousedown', (e)=>{ if(e.target.closest('.delete-btn')) return; selectNote(note.id); });
  updateNoteItemContent(li, note.content);
  noteList.prepend(li);
  return li;
}
function updateNoteItemContent(item, content){
  const t = item.querySelector('.note-title'); const p = item.querySelector('.note-preview');
  if(!t||!p) return;
  const plain = content.replace(/<br\s*\/?>/gi,"\n").replace(/<\/div>|<\/p>/gi,"\n").replace(/<[^>]*>?/gm,'').trim();
  const lines = plain.split('\n').filter(l=>l.trim()!=='');
  t.textContent = lines[0] ? lines[0].substring(0,30) : '新筆記';
  p.textContent = lines[1] ? lines[1] : '無預覽';
}
function loadNotes(){ noteList.innerHTML=''; const notes = getNotesFromStorage(); notes.forEach(n=>addNoteToSidebar(n)); if(notes.length>0) selectNote(notes[0].id); else newNote(); }
function saveNote(){ const content = noteEditor.innerHTML; let notes = getNotesFromStorage();
  if(!content.trim() && currentNoteId){ deleteNote(currentNoteId); return; }
  if(currentNoteId){
    const nm = notes.find(n=>n.id===currentNoteId);
    if(nm && nm.content !== content){ nm.content = content; const item = document.querySelector(`.note-item[data-id="${currentNoteId}"]`); if(item) updateNoteItemContent(item, content); }
  } else if(content.trim()){
    const newN = { id: Date.now().toString(), content }; notes.unshift(newN); currentNoteId = newN.id;
    document.querySelectorAll('.note-item.active').forEach(i=>i.classList.remove('active')); addNoteToSidebar(newN, true);
  }
  persistNotes(notes);
}
function selectNote(id){ const notes = getNotesFromStorage(); const sel = notes.find(n=>n.id===id); if(sel){ noteEditor.innerHTML = sel.content; currentNoteId = id; document.querySelectorAll('.note-item').forEach(i=>i.classList.toggle('active', i.getAttribute('data-id')===id)); noteEditor.focus(); } }
function newNote(){ noteEditor.innerHTML=''; currentNoteId=null; document.querySelectorAll('.note-item.active').forEach(i=>i.classList.remove('active')); noteEditor.focus(); }
function deleteNote(id){ let notes = getNotesFromStorage(); notes = notes.filter(n=>n.id!==id); persistNotes(notes); const it = document.querySelector(`.note-item[data-id="${id}"]`); if(it) it.remove(); if(currentNoteId===id){ if(notes.length>0) selectNote(notes[0].id); else newNote(); } }

window.onload = loadNotes;
newNoteBtn.onclick = newNote;
noteEditor.oninput = ()=>{ clearTimeout(saveTimer); saveTimer = setTimeout(saveNote, 500); };
function formatDoc(cmd){ document.execCommand(cmd,false,null); noteEditor.focus(); }
window.formatDoc = formatDoc;

/* ---------- encryption helpers ---------- */
const FILE_MAGIC='MEMO'; const SALT_LEN=16; const IV_LEN=12; const PBKDF2_ITER=150000;
function getRandomBytes(len){ const b=new Uint8Array(len); crypto.getRandomValues(b); return b; }
async function deriveKeyFromPassword(password, saltBuffer){
  const enc=new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name:'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name:'PBKDF2', salt: saltBuffer, iterations: PBKDF2_ITER, hash:'SHA-256' }, passKey, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}
async function encryptNotesToUint8(notesArray, password){
  const salt = getRandomBytes(SALT_LEN); const iv = getRandomBytes(IV_LEN);
  const key = await deriveKeyFromPassword(password, salt.buffer);
  const enc = new TextEncoder(); const plain = enc.encode(JSON.stringify(notesArray));
  const cipher = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);
  const magicBuf = new TextEncoder().encode(FILE_MAGIC);
  const cipherBuf = new Uint8Array(cipher);
  const out = new Uint8Array(magicBuf.length + salt.length + iv.length + cipherBuf.length);
  let off=0; out.set(magicBuf, off); off+=magicBuf.length; out.set(salt, off); off+=salt.length; out.set(iv, off); off+=iv.length; out.set(cipherBuf, off);
  return out.buffer;
}
async function decryptUint8ToNotes(arrayBuffer, password){
  const data = new Uint8Array(arrayBuffer); const magicLen = FILE_MAGIC.length;
  const magic = new TextDecoder().decode(data.slice(0, magicLen));
  if(magic !== FILE_MAGIC) throw new Error('檔案格式不正確');
  const salt = data.slice(magicLen, magicLen+SALT_LEN).buffer;
  const iv = data.slice(magicLen+SALT_LEN, magicLen+SALT_LEN+IV_LEN);
  const cipher = data.slice(magicLen+SALT_LEN+IV_LEN).buffer;
  const key = await deriveKeyFromPassword(password, salt);
  const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, cipher);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ---------- modal helper (promise) ---------- */
function askPasswordModal(){
  return new Promise((resolve, reject)=>{
    pwdError.style.display='none'; pwdError.textContent='';
    pwdInput.value=''; pwdModal.setAttribute('aria-hidden','false');
    // small timeout so focus works on some mobile browsers
    setTimeout(()=>pwdInput.focus(),50);

    function cleanup(){
      pwdModal.setAttribute('aria-hidden','true');
      pwdOk.removeEventListener('click', onOk);
      pwdCancel.removeEventListener('click', onCancel);
      pwdInput.removeEventListener('keydown', onKey);
    }
    const onOk = ()=>{
      const v = pwdInput.value || '';
      if(v.length < 1){ pwdError.style.display='block'; pwdError.textContent='密碼不可為空。'; pwdInput.focus(); return; }
      cleanup(); resolve(v);
    };
    const onCancel = ()=>{ cleanup(); reject(new Error('使用者取消')); };
    const onKey = (e)=>{ if(e.key === 'Enter'){ onOk(); } else if(e.key === 'Escape'){ onCancel(); } };

    pwdOk.addEventListener('click', onOk);
    pwdCancel.addEventListener('click', onCancel);
    pwdInput.addEventListener('keydown', onKey);
  });
}

/* ---------- file helpers ---------- */
async function saveByDownload(notesArray, password, suggestedName='memoroa.dat'){
  const arrayBuf = await encryptNotesToUint8(notesArray, password);
  const blob = new Blob([arrayBuf], { type:'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = suggestedName; document.body.appendChild(a);
  a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function openFileFromDevice(){
  if(window.showOpenFilePicker){
    const [handle] = await window.showOpenFilePicker({ types:[{ description:'Memoroa backup', accept:{ 'application/octet-stream':['.dat'] } }], multiple:false });
    const file = await handle.getFile();
    const arrayBuffer = await file.arrayBuffer();
    return { arrayBuffer, handle, name: file.name };
  } else {
    return await new Promise((resolve, reject)=>{
      const input = document.createElement('input'); input.type='file'; input.accept='.dat,application/octet-stream';
      input.onchange = async (e)=>{ const f = e.target.files[0]; if(!f){ reject(new Error('使用者取消')); return; } const ab = await f.arrayBuffer(); resolve({ arrayBuffer: ab, handle: null, name: f.name }); };
      input.click();
    });
  }
}

/* ---------- final backup & restore flows ---------- */
backupBtn.addEventListener('click', async ()=>{
  try{
    const notes = getNotesFromStorage();
    if(!notes || notes.length === 0){ alert('目前沒有任何筆記可備份。'); return; }

    // 優先使用 showSaveFilePicker（需在 user gesture 中呼叫）
    if(window.showSaveFilePicker){
      try{
        const opts = { types:[{ description:'Memoroa backup', accept:{ 'application/octet-stream':['.dat'] } }], suggestedName:'memoroa.dat' };
        const handle = await window.showSaveFilePicker(opts);
        // picker 回傳成功（使用者選位置），再用 modal 取得密碼（modal 在這階段不會被瀏覽器阻擋）
        const password = await askPasswordModal();
        // 加密並寫入
        const arrayBuf = await encryptNotesToUint8(notes, password);
        const writable = await handle.createWritable(); await writable.write(arrayBuf); await writable.close();
        alert('備份成功：已寫入選擇位置（檔名或路徑由系統決定），請妥善保存密碼以便還原。');
        return;
      } catch(err){
        // 如果使用者取消 file picker，err.name 可能是 AbortError 或 custom
        if(err && (err.name === 'AbortError' || err.message === '使用者取消')){ console.warn('使用者取消 file picker'); return; }
        console.warn('showSaveFilePicker 路徑失敗，改用下載 fallback：', err);
      }
    }

    // fallback（瀏覽器不支援 showSaveFilePicker）：先用 modal 取得密碼，然後下載加密檔案
    const pwd = await askPasswordModal();
    await saveByDownload(notes, pwd, 'memoroa.dat');
    alert('備份成功（下載）：已下載 memoroa.dat，請妥善保存密碼以便還原。');

  } catch(e){
    if(e.message === '使用者取消') return;
    console.error('備份失敗', e);
    alert('備份失敗：' + (e.message || e));
  }
});

restoreBtn.addEventListener('click', async ()=>{
  try{
    const { arrayBuffer, name } = await openFileFromDevice();
    if(!arrayBuffer) throw new Error('讀取檔案失敗或使用者取消');
    const pwd = await askPasswordModal();
    const notes = await decryptUint8ToNotes(arrayBuffer, pwd);
    persistNotes(notes); loadNotes();
    alert('還原成功：筆記已匯入（已覆蓋目前資料）。');
  } catch(e){
    if(e.message === '使用者取消') return;
    console.error('還原失敗', e);
    if(e.message && e.message.includes('檔案格式不正確')) alert('還原失敗：檔案不是 Memoroa 的備份檔，請確認來源。');
    else if(e.name === 'OperationError' || (e.message && (e.message.includes('authentication tag') || e.message.includes('tag')))) alert('還原失敗：密碼錯誤或備份檔已損壞。');
    else alert('還原失敗：' + (e.message || e));
  }
});
