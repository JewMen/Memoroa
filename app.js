/* app.js
   最終穩定版：整合筆記功能 + PBKDF2 + AES-GCM 備份/還原
   - showSaveFilePicker 用法已放在 user gesture 內取得 handle
   - fallback download path 仍會先加密（避免無密碼檔）
   - 還原使用 file.arrayBuffer() -> 驗證 magic -> 解密
*/

/* -------------------------
   UI 元件 (DOM)
   ------------------------- */
const noteList = document.getElementById('note-list');
const noteEditor = document.getElementById('note-editor');
const newNoteBtn = document.getElementById('new-note-btn');
const backupBtn = document.getElementById('backupBtn');
const restoreBtn = document.getElementById('restoreBtn');

let currentNoteId = null;
let saveTimer = null;

/* -------------------------
   笔记資料 (localStorage)
   ------------------------- */
function getNotesFromStorage() {
  try {
    const notesJSON = localStorage.getItem('notes');
    return notesJSON ? JSON.parse(notesJSON) : [];
  } catch (e) {
    console.error("無法解析 localStorage 中的筆記", e);
    return [];
  }
}

function persistNotes(notes) {
  localStorage.setItem('notes', JSON.stringify(notes));
}

function addNoteToSidebar(note, isActive = false) {
  const li = document.createElement('li');
  li.className = 'note-item';
  if (isActive) li.classList.add('active');
  li.setAttribute('data-id', note.id);

  const contentWrapper = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'note-title';
  const preview = document.createElement('div');
  preview.className = 'note-preview';
  contentWrapper.appendChild(title);
  contentWrapper.appendChild(preview);

  const deleteBtn = document.createElement('button');
  deleteBtn.className = 'delete-btn';
  deleteBtn.type = 'button';
  deleteBtn.textContent = '×';
  deleteBtn.onclick = (e) => {
    e.stopPropagation();
    deleteNote(note.id);
  };

  li.appendChild(contentWrapper);
  li.appendChild(deleteBtn);

  // 使用 mousedown 避免 selection 與 contentEditable 衝突
  li.addEventListener('mousedown', (e) => {
    if (e.target.closest('.delete-btn')) return;
    selectNote(note.id);
  });

  updateNoteItemContent(li, note.content);
  noteList.prepend(li);
  return li;
}

function updateNoteItemContent(item, content) {
  const titleElement = item.querySelector('.note-title');
  const previewElement = item.querySelector('.note-preview');
  if (!titleElement || !previewElement) return;
  const plainTextWithNewlines = content
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/div>|<\/p>/gi, "\n");
  const plainText = plainTextWithNewlines.replace(/<[^>]*>?/gm, '').trim();
  const lines = plainText.split('\n').filter(line => line.trim() !== '');
  titleElement.textContent = lines[0] ? lines[0].substring(0, 30) : "新筆記";
  previewElement.textContent = lines[1] ? lines[1] : "無預覽";
}

function loadNotes() {
  noteList.innerHTML = '';
  const notes = getNotesFromStorage();
  notes.forEach(note => addNoteToSidebar(note));
  if (notes.length > 0) selectNote(notes[0].id);
  else newNote();
}

function saveNote() {
  const content = noteEditor.innerHTML;
  let notes = getNotesFromStorage();
  if (!content.trim() && currentNoteId) {
    deleteNote(currentNoteId);
    return;
  }
  if (currentNoteId) {
    const noteToUpdate = notes.find(note => note.id === currentNoteId);
    if (noteToUpdate && noteToUpdate.content !== content) {
      noteToUpdate.content = content;
      const item = document.querySelector(`.note-item[data-id="${currentNoteId}"]`);
      if (item) updateNoteItemContent(item, content);
    }
  } else if (content.trim()) {
    const newNote = { id: Date.now().toString(), content: content };
    notes.unshift(newNote);
    currentNoteId = newNote.id;
    document.querySelectorAll('.note-item.active').forEach(item => item.classList.remove('active'));
    addNoteToSidebar(newNote, true);
  }
  persistNotes(notes);
}

function selectNote(id) {
  const notes = getNotesFromStorage();
  const selectedNote = notes.find(note => note.id === id);
  if (selectedNote) {
    noteEditor.innerHTML = selectedNote.content;
    currentNoteId = id;
    document.querySelectorAll('.note-item').forEach(item => {
      item.classList.toggle('active', item.getAttribute('data-id') === id);
    });
    noteEditor.focus();
  }
}

function newNote() {
  noteEditor.innerHTML = '';
  currentNoteId = null;
  document.querySelectorAll('.note-item.active').forEach(item => item.classList.remove('active'));
  noteEditor.focus();
}

function deleteNote(id) {
  let notes = getNotesFromStorage();
  notes = notes.filter(note => note.id !== id);
  persistNotes(notes);
  const itemToRemove = document.querySelector(`.note-item[data-id="${id}"]`);
  if (itemToRemove) itemToRemove.remove();
  if (currentNoteId === id) {
    if (notes.length > 0) selectNote(notes[0].id);
    else newNote();
  }
}

/* event wiring */
window.onload = loadNotes;
newNoteBtn.onclick = newNote;
noteEditor.oninput = () => {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveNote, 500);
};

/* formatting */
function formatDoc(command) {
  document.execCommand(command, false, null);
  noteEditor.focus();
}
window.formatDoc = formatDoc; // expose for inline onclicks

/* -------------------------
   Backup / Restore (加密格式規範)
   - header: "MEMO" (4 bytes) + salt(16) + iv(12) + ciphertext
   - PBKDF2 iterations = 150000, hash SHA-256
   - AES-GCM 256
   ------------------------- */

const FILE_MAGIC = 'MEMO';
const SALT_LEN = 16;
const IV_LEN = 12;
const PBKDF2_ITER = 150000;

function getRandomBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

async function deriveKeyFromPassword(password, saltBuffer) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBuffer, iterations: PBKDF2_ITER, hash: "SHA-256" },
    passKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt","decrypt"]
  );
  return key;
}

async function encryptNotesToUint8(notesArray, password) {
  const salt = getRandomBytes(SALT_LEN);
  const iv = getRandomBytes(IV_LEN);
  const key = await deriveKeyFromPassword(password, salt.buffer);
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(notesArray));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, plaintext);
  const magicBuf = new TextEncoder().encode(FILE_MAGIC);
  const saltBuf = salt;
  const ivBuf = iv;
  const cipherBuf = new Uint8Array(cipher);
  const out = new Uint8Array(magicBuf.length + saltBuf.length + ivBuf.length + cipherBuf.length);
  let offset = 0;
  out.set(magicBuf, offset); offset += magicBuf.length;
  out.set(saltBuf, offset); offset += saltBuf.length;
  out.set(ivBuf, offset); offset += ivBuf.length;
  out.set(cipherBuf, offset);
  return out.buffer;
}

async function decryptUint8ToNotes(arrayBuffer, password) {
  const data = new Uint8Array(arrayBuffer);
  const magicLen = FILE_MAGIC.length;
  const magic = new TextDecoder().decode(data.slice(0, magicLen));
  if (magic !== FILE_MAGIC) throw new Error('檔案格式不正確：找不到 MEMO 標頭');
  const salt = data.slice(magicLen, magicLen + SALT_LEN).buffer;
  const iv = data.slice(magicLen + SALT_LEN, magicLen + SALT_LEN + IV_LEN);
  const cipher = data.slice(magicLen + SALT_LEN + IV_LEN).buffer;
  const key = await deriveKeyFromPassword(password, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipher);
  const decoded = new TextDecoder().decode(plainBuf);
  return JSON.parse(decoded);
}

/* prompt 密碼（同步 prompt） */
function promptPassword(promptText = '請輸入備份密碼（會用來加密/解密）') {
  const p = prompt(promptText + '\n(請記住此密碼，忘記將無法還原檔案)');
  if (p === null) throw new Error('使用者取消');
  if (p.length < 4) {
    const ok = confirm('建議使用較長密碼 (至少 6 個字)，是否繼續？');
    if (!ok) throw new Error('密碼太短');
  }
  return p;
}

/* ---------- Helpers for file save/open ---------- */
async function saveWithPickerHandle(notesArray, password) {
  // MUST be called with showSaveFilePicker in user gesture (we call here from click handler)
  const opts = {
    types: [{
      description: 'Memoroa backup',
      accept: { 'application/octet-stream': ['.dat'] }
    }],
    suggestedName: 'memoroa.dat'
  };
  // open handle (this call must be in user gesture)
  const handle = await window.showSaveFilePicker(opts);
  // now we can do heavy async: encrypt and write
  const arrayBuf = await encryptNotesToUint8(notesArray, password);
  const writable = await handle.createWritable();
  await writable.write(arrayBuf);
  await writable.close();
  return handle;
}

async function saveByDownload(notesArray, password, suggestedName='memoroa.dat') {
  const arrayBuf = await encryptNotesToUint8(notesArray, password);
  const blob = new Blob([arrayBuf], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return true;
}

async function openFileFromDevice() {
  if (window.showOpenFilePicker) {
    const [handle] = await window.showOpenFilePicker({
      types: [{
        description: 'Memoroa backup',
        accept: { 'application/octet-stream': ['.dat'] }
      }],
      multiple: false
    });
    const file = await handle.getFile();
    const arrayBuffer = await file.arrayBuffer();
    return { arrayBuffer, handle, name: file.name };
  } else {
    return await new Promise((resolve, reject) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.dat,application/octet-stream';
      input.onchange = async (e) => {
        const f = e.target.files[0];
        if (!f) { reject(new Error('使用者取消')); return; }
        const arrayBuffer = await f.arrayBuffer();
        resolve({ arrayBuffer, handle: null, name: f.name });
      };
      input.click();
    });
  }
}

/* ---------- 備份 Click Handler（最重要的修正） ---------- */
backupBtn.addEventListener('click', async (e) => {
  try {
    const notes = getNotesFromStorage();
    if (!notes || notes.length === 0) {
      alert('目前沒有任何筆記可備份。');
      return;
    }

    // If showSaveFilePicker exists, call it FIRST within the click handler to keep user gesture
    if (window.showSaveFilePicker) {
      try {
        // open save dialog in user gesture - if user cancels it will throw / return
        const opts = {
          types: [{
            description: 'Memoroa backup',
            accept: { 'application/octet-stream': ['.dat'] }
          }],
          suggestedName: 'memoroa.dat'
        };
        const handle = await window.showSaveFilePicker(opts);
        // Prompt password AFTER we have handle (prompt is synchronous and OK)
        const password = promptPassword('備份：請輸入備份密碼（將用來加密）');
        // now encrypt and write
        const arrayBuf = await encryptNotesToUint8(notes, password);
        const writable = await handle.createWritable();
        await writable.write(arrayBuf);
        await writable.close();
        alert('已將備份檔案寫入裝置（memoroa.dat）。請妥善保存密碼以便還原。');
        return;
      } catch (err) {
        // If user canceled file picker, just return quietly
        if (err && (err.name === 'AbortError' || err.message === 'The user aborted a request.')) {
          console.warn('使用者取消檔案選擇');
          return;
        }
        // else fallback to download (after console warn)
        console.warn('showSaveFilePicker 路徑發生錯誤，嘗試 fallback 下載：', err);
      }
    }

    // Fallback (download) - prompt password first then download encrypted blob
    const password = promptPassword('備份（備援）：請輸入備份密碼（將用來加密）');
    await saveByDownload(notes, password, 'memoroa.dat');
    alert('已將備份檔案下載到裝置（memoroa.dat）。請妥善保存密碼以便還原。');

  } catch (e) {
    if (e.message === '使用者取消') return;
    console.error('備份失敗：', e);
    alert('備份失敗：' + (e.message || e));
  }
});

/* ---------- 還原 Click Handler ---------- */
restoreBtn.addEventListener('click', async () => {
  try {
    const { arrayBuffer, name } = await openFileFromDevice();
    if (!arrayBuffer) throw new Error('無法讀取檔案內容');
    const password = promptPassword('還原：請輸入備份檔案的密碼');
    const notes = await decryptUint8ToNotes(arrayBuffer, password);
    // overwrite localStorage
    persistNotes(notes);
    loadNotes();
    alert('還原成功（已覆蓋目前筆記資料）。');
  } catch (e) {
    if (e.message === '使用者取消') return;
    console.error('還原失敗：', e);
    // 給出更友善的錯誤訊息
    if (e.message && e.message.includes('檔案格式不正確')) {
      alert('還原失敗：檔案不是 Memoroa 的備份檔，請確認檔案來源。');
    } else if (e.name === 'OperationError' || e.message.includes('authentication tag')) {
      alert('還原失敗：密碼錯誤或檔案已損壞。');
    } else {
      alert('還原失敗：' + (e.message || e));
    }
  }
});

/* End of app.js */
