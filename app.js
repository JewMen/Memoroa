/* app.js — 最終穩定版（含 password modal） */
/* ------------ DOM 元件 -------------- */
const noteList = document.getElementById('note-list');
const noteEditor = document.getElementById('note-editor');
const newNoteBtn = document.getElementById('new-note-btn');
const backupBtn = document.getElementById('backupBtn');
const restoreBtn = document.getElementById('restoreBtn');

/* modal 元件 */
const pwdModal = document.getElementById('pwd-modal');
const pwdInput = document.getElementById('pwd-input');
const pwdOk = document.getElementById('pwd-ok');
const pwdCancel = document.getElementById('pwd-cancel');
const pwdError = document.getElementById('pwd-error');

/* ------------ 筆記邏輯（同上，不再贅述） ------------- */
let currentNoteId = null;
let saveTimer = null;

function getNotesFromStorage() {
  try { const notesJSON = localStorage.getItem('notes'); return notesJSON ? JSON.parse(notesJSON) : []; }
  catch(e){ console.error('parse notes error', e); return []; }
}
function persistNotes(notes){ localStorage.setItem('notes', JSON.stringify(notes)); }

function addNoteToSidebar(note, isActive=false){
  const li = document.createElement('li');
  li.className='note-item';
  if(isActive) li.classList.add('active');
  li.setAttribute('data-id', note.id);
  const contentWrapper = document.createElement('div');
  const title = document.createElement('div'); title.className='note-title';
  const preview = document.createElement('div'); preview.className='note-preview';
  contentWrapper.appendChild(title); contentWrapper.appendChild(preview);
  const deleteBtn = document.createElement('button'); deleteBtn.className='delete-btn'; deleteBtn.type='button'; deleteBtn.textContent='×';
  deleteBtn.onclick = (e)=>{ e.stopPropagation(); deleteNote(note.id); };
  li.appendChild(contentWrapper); li.appendChild(deleteBtn);
  li.addEventListener('mousedown', (e)=>{ if(e.target.closest('.delete-btn')) return; selectNote(note.id); });
  updateNoteItemContent(li, note.content);
  noteList.prepend(li);
  return li;
}
function updateNoteItemContent(item, content){
  const titleElement = item.querySelector('.note-title');
  const previewElement = item.querySelector('.note-preview');
  if(!titleElement || !previewElement) return;
  const plainTextWithNewlines = content.replace(/<br\s*\/?>/gi,"\n").replace(/<\/div>|<\/p>/gi,"\n");
  const plainText = plainTextWithNewlines.replace(/<[^>]*>?/gm,'').trim();
  const lines = plainText.split('\n').filter(l=>l.trim()!=='');
  titleElement.textContent = lines[0]? lines[0].substring(0,30) : '新筆記';
  previewElement.textContent = lines[1] ? lines[1] : '無預覽';
}
function loadNotes(){ noteList.innerHTML=''; const notes = getNotesFromStorage(); notes.forEach(n=>addNoteToSidebar(n)); if(notes.length>0) selectNote(notes[0].id); else newNote(); }
function saveNote(){ const content = noteEditor.innerHTML; let notes = getNotesFromStorage(); if(!content.trim() && currentNoteId){ deleteNote(currentNoteId); return; } if(currentNoteId){ const noteToUpdate = notes.find(n=>n.id===currentNoteId); if(noteToUpdate && noteToUpdate.content !== content){ noteToUpdate.content = content; const item = document.querySelector(`.note-item[data-id="${currentNoteId}"]`); if(item) updateNoteItemContent(item, content); } } else if(content.trim()){ const newNote = { id: Date.now().toString(), content }; notes.unshift(newNote); currentNoteId = newNote.id; document.querySelectorAll('.note-item.active').forEach(i=>i.classList.remove('active')); addNoteToSidebar(newNote,true); } persistNotes(notes); }
function selectNote(id){ const notes = getNotesFromStorage(); const sel = notes.find(n=>n.id===id); if(sel){ noteEditor.innerHTML = sel.content; currentNoteId = id; document.querySelectorAll('.note-item').forEach(item=> item.classList.toggle('active', item.getAttribute('data-id')===id)); noteEditor.focus(); } }
function newNote(){ noteEditor.innerHTML=''; currentNoteId=null; document.querySelectorAll('.note-item.active').forEach(i=>i.classList.remove('active')); noteEditor.focus(); }
function deleteNote(id){ let notes = getNotesFromStorage(); notes = notes.filter(n=>n.id!==id); persistNotes(notes); const item = document.querySelector(`.note-item[data-id="${id}"]`); if(item) item.remove(); if(currentNoteId===id){ if(notes.length>0) selectNote(notes[0].id); else newNote(); } }

window.onload = loadNotes;
newNoteBtn.onclick = newNote;
noteEditor.oninput = ()=>{ clearTimeout(saveTimer); saveTimer = setTimeout(saveNote, 500); };
function formatDoc(cmd){ document.execCommand(cmd,false,null); noteEditor.focus(); }
window.formatDoc = formatDoc;

/* ------------- 加密格式與 helpers --------------- */
const FILE_MAGIC = 'MEMO'; const SALT_LEN = 16; const IV_LEN = 12; const PBKDF2_ITER = 150000;
function getRandomBytes(len){ const b = new Uint8Array(len); crypto.getRandomValues(b); return b; }
async function deriveKeyFromPassword(password, saltBuffer){
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: saltBuffer, iterations: PBKDF2_ITER, hash: 'SHA-256' }, passKey, { name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}
async function encryptNotesToUint8(notesArray, password){
  const salt = getRandomBytes(SALT_LEN); const iv = getRandomBytes(IV_LEN);
  const key = await deriveKeyFromPassword(password, salt.buffer);
  const encoder = new TextEncoder(); const plaintext = encoder.encode(JSON.stringify(notesArray));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
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

/* ---------- Modal password helper (可靠於所有平台) ---------- */
/* 回傳 Promise，resolve => 密碼字串，reject => 使用者取消 */
function askPasswordModal(promptText='請輸入密碼'){
  return new Promise((resolve, reject) => {
    pwdError.style.display='none'; pwdError.textContent='';
    pwdInput.value=''; pwdModal.setAttribute('aria-hidden', 'false'); pwdInput.focus();

    const cleanup = () => {
      pwdModal.setAttribute('aria-hidden','true');
      pwdOk.removeEventListener('click', onOk);
      pwdCancel.removeEventListener('click', onCancel);
      pwdInput.removeEventListener('keydown', onKeyDown);
    };

    const onOk = () => {
      const v = pwdInput.value || '';
      if(v.length < 1){ pwdError.style.display='block'; pwdError.textContent = '密碼不可為空。'; pwdInput.focus(); return; }
      cleanup(); resolve(v);
    };
    const onCancel = () => { cleanup(); reject(new Error('使用者取消')); };

    const onKeyDown = (e) => { if(e.key === 'Enter'){ onOk(); } else if(e.key === 'Escape'){ onCancel(); } };

    pwdOk.addEventListener('click', onOk);
    pwdCancel.addEventListener('click', onCancel);
    pwdInput.addEventListener('keydown', onKeyDown);
  });
}

/* ---------- File helpers ---------- */
async function saveByDownload(notesArray, password, suggestedName='memoroa.dat'){
  const arrayBuf = await encryptNotesToUint8(notesArray, password);
  const blob = new Blob([arrayBuf], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = suggestedName; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function openFileFromDevice(){
  if(window.showOpenFilePicker){
    const [handle] = await window.showOpenFilePicker({ types:[{ description:'Memoroa backup', accept:{ 'application/octet-stream': ['.dat'] } }], multiple:false });
    const file = await handle.getFile();
    const arrayBuffer = await file.arrayBuffer();
    return { arrayBuffer, handle, name: file.name };
  } else {
    return await new Promise((resolve, reject) => {
      const input = document.createElement('input'); input.type='file'; input.accept='.dat,application/octet-stream';
      input.onchange = async (e) => { const f = e.target.files[0]; if(!f){ reject(new Error('使用者取消')); return; } const ab = await f.arrayBuffer(); resolve({ arrayBuffer: ab, handle: null, name: f.name }); };
      input.click();
    });
  }
}

/* ---------- 最終修正：備份 & 還原流程（使用 modal） ---------- */
backupBtn.addEventListener('click', async (e) => {
  try{
    const notes = getNotesFromStorage();
    if(!notes || notes.length===0){ alert('目前沒有任何筆記可備份。'); return; }

    // 如果 showSaveFilePicker 支援，優先用 picker（必須在 user gesture 直接呼叫）
    if(window.showSaveFilePicker){
      try{
        const opts = { types:[{ description:'Memoroa backup', accept:{ 'application/octet-stream':['.dat'] } }], suggestedName:'memoroa.dat' };
        const handle = await window.showSaveFilePicker(opts); // 在 user gesture 內開啟 picker
        // picker 成功打開並完成選擇後，用 modal 要密碼（modal 不會被瀏覽器阻擋）
        const password = await askPasswordModal('備份：請輸入備份密碼（將用來加密）');
        const arrayBuf = await encryptNotesToUint8(notes, password);
        const writable = await handle.createWritable(); await writable.write(arrayBuf); await writable.close();
        alert('已將備份檔案寫入裝置（memoroa.dat）。請妥善保存密碼以便還原。');
        return;
      } catch(err){
        // user cancelled file picker or other error -> 若是取消就 return；其他錯誤 fallback 到下載
        if(err && (err.name === 'AbortError' || err.message === '使用者取消')){ console.warn('使用者取消 file picker'); return; }
        console.warn('picker path error, fallback to download:', err);
      }
    }

    // fallback: 直接用 modal 要密碼，然後下載加密檔案（可靠）
    const pwd = await askPasswordModal('備份（備援）：請輸入備份密碼（將用來加密）');
    await saveByDownload(notes, pwd, 'memoroa.dat');
    alert('已將備份檔案下載到裝置（memoroa.dat）。請妥善保存密碼以便還原。');

  } catch(e){
    if(e.message === '使用者取消') { /* 使用者按取消，不視為錯誤 */ return; }
    console.error('備份失敗', e); alert('備份失敗：' + (e.message || e));
  }
});

restoreBtn.addEventListener('click', async () => {
  try{
    // 先開啟 file picker（必須在 user gesture 裡呼叫），選完檔案後再用 modal 要密碼
    const { arrayBuffer, name } = await openFileFromDevice();
    if(!arrayBuffer) throw new Error('無法讀取檔案內容');
    const pwd = await askPasswordModal('還原：請輸入備份檔案的密碼');
    const notes = await decryptUint8ToNotes(arrayBuffer, pwd);
    persistNotes(notes); loadNotes();
    alert('還原成功（已覆蓋目前筆記資料）。');
  } catch(e){
    if(e.message === '使用者取消') return;
    console.error('還原失敗', e);
    if(e.message && e.message.includes('檔案格式不正確')) alert('還原失敗：檔案不是 Memoroa 的備份檔，請確認檔案來源。');
    else if(e.name==='OperationError' || (e.message && e.message.includes('authentication tag'))) alert('還原失敗：密碼錯誤或檔案已損壞。');
    else alert('還原失敗：' + (e.message || e));
  }
});
