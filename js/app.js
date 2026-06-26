// BugHunter Tracker v5 — Copyright (c) 2026. MIT License.
// v5: Cloud-first auth — create account once, login from any device (phone/laptop/tablet)
// Architecture: master user-index bin (public lookup) + per-user encrypted data bin

const App = (() => {
  'use strict';

  const JSONBIN_BASE = 'https://api.jsonbin.io/v3';

  // ─── State ───────────────────────────────────────────────────────────────────
  let state = {
    currentUser: null,
    findings: [], writeups: [], workspaces: [], reconNotes: [],
    reminders: [], streak: { current:0, longest:0, lastActive:null, history:[] },
    activeWorkspace: null, activePanel: 'dashboard',
    filterPriority: 'all', searchQuery: '',
    editId: null, monthlyGoal: 300,
    charts: {}, syncStatus: 'local', binId: null, lastSync: null,
    settings: { twoFAEnabled:false, twoFASecret:null, displayName:'', theme:'dark' },
    timeLog: [], _currentReport: null,
  };

  // ─── LocalStorage keys ───────────────────────────────────────────────────────
  const LS = {
    // Local fallback only — NOT the source of truth for auth
    LOCAL_USERS: 'bht_local_users_v5',
    SESSION:     'bht_session_v5',
    CACHE:       uid => `bht_cache_v5_${uid}`,
    BIN:         uid => `bht_data_bin_v5_${uid}`,
    INDEX_BIN:   'bht_index_bin_v5',   // bin that holds username→uid→dataBinId map
    APIKEY:      'bht_jsonbin_key',
  };

  // ─── API key helpers ─────────────────────────────────────────────────────────
  function getApiKey(){ return localStorage.getItem(LS.APIKEY) || ''; }
  function hasApiKey(){ return getApiKey().length > 20; }

  // ─── Crypto ──────────────────────────────────────────────────────────────────
  async function deriveKey(pw, salt) {
    const enc = new TextEncoder();
    const km = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt:enc.encode(salt), iterations:100000, hash:'SHA-256' },
      km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
    );
  }
  async function encrypt(data, pw, salt) {
    const key = await deriveKey(pw, salt);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const buf = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, enc.encode(JSON.stringify(data))));
    const out = new Uint8Array(12 + buf.length);
    out.set(iv, 0); out.set(buf, 12);
    return btoa(String.fromCharCode(...out));
  }
  async function decrypt(ct, pw, salt) {
    const combined = Uint8Array.from(atob(ct), c => c.charCodeAt(0));
    const key = await deriveKey(pw, salt);
    const dec = await crypto.subtle.decrypt({name:'AES-GCM', iv:combined.slice(0,12)}, key, combined.slice(12));
    return JSON.parse(new TextDecoder().decode(dec));
  }
  async function hashPw(pw) {
    const enc = new TextEncoder();
    const h   = await crypto.subtle.digest('SHA-256', enc.encode('bht5_salt_' + pw));
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // ─── TOTP ────────────────────────────────────────────────────────────────────
  function genTOTPSecret(){const c='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',a=crypto.getRandomValues(new Uint8Array(20));return Array.from(a,b=>c[b%32]).join('');}
  function b32ToBytes(s){const a='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits=0,val=0;const out=[];for(const c of s.toUpperCase().replace(/=+$/,'')){val=(val<<5)|a.indexOf(c);bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8;}}return new Uint8Array(out);}
  async function genTOTP(secret,t){const T=Math.floor((t||Date.now()/1000)/30),msg=new ArrayBuffer(8);new DataView(msg).setUint32(4,T,false);const k=await crypto.subtle.importKey('raw',b32ToBytes(secret),{name:'HMAC',hash:'SHA-1'},false,['sign']),sig=new Uint8Array(await crypto.subtle.sign('HMAC',k,msg)),o=sig[19]&0xf;return(((sig[o]&0x7f)<<24|(sig[o+1]<<16)|(sig[o+2]<<8)|sig[o+3])%1000000).toString().padStart(6,'0');}
  async function verifyTOTP(secret,token){const now=Date.now()/1000;for(const off of[-30,0,30]){if(await genTOTP(secret,now+off)===token.trim())return true;}return false;}

  // ═══════════════════════════════════════════════════════════════════════════
  // CLOUD AUTH SYSTEM
  // How it works (same as Instagram/Facebook/Bugcrowd):
  //
  // 1. ONE master index bin per API key — stores a list of all users:
  //    [ { uid, username, email, hash, dataBinId, joined }, ... ]
  //    This is encrypted with a static app-level key (not user password)
  //    so any device can look up accounts without knowing the password.
  //
  // 2. ONE data bin per user — stores all findings/workspaces/etc.
  //    This is encrypted with the USER's password.
  //
  // 3. Registration: load index → check username/email unique → add user →
  //    save index → create data bin → done.
  //
  // 4. Login from any device: load index → find user by username/email →
  //    verify password hash → load data bin → done.
  //
  // 5. No device-specific storage needed for auth. Works on phone, laptop,
  //    tablet — anything with the API key set.
  // ═══════════════════════════════════════════════════════════════════════════

  // Index bin encryption uses a static app salt (not user password)
  // so any device with the API key can read the user list
  const INDEX_ENC_KEY = 'bughunter_tracker_index_v5';
  const INDEX_ENC_SALT = 'bht_index_salt_2026';

  async function loadIndex() {
    if (!hasApiKey()) return null;
    const binId = localStorage.getItem(LS.INDEX_BIN);
    if (!binId) return null;
    try {
      const res = await fetch(`${JSONBIN_BASE}/b/${binId}/latest`, {
        headers: { 'X-Master-Key': getApiKey(), 'X-Bin-Meta': 'false' }
      });
      if (!res.ok) return null;
      const json = await res.json();
      const record = json.record || json;
      if (record && record.enc) {
        return await decrypt(record.enc, INDEX_ENC_KEY, INDEX_ENC_SALT);
      }
      return record || null;
    } catch(e) { console.warn('loadIndex:', e.message); return null; }
  }

  async function saveIndex(users) {
    if (!hasApiKey()) return false;
    let binId = localStorage.getItem(LS.INDEX_BIN);
    const enc = await encrypt(users, INDEX_ENC_KEY, INDEX_ENC_SALT);
    try {
      if (!binId) {
        // Create the index bin for the first time
        const res = await fetch(`${JSONBIN_BASE}/b`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Master-Key': getApiKey(),
            'X-Bin-Name': 'bht_user_index_v5',
            'X-Bin-Private': 'true',
          },
          body: JSON.stringify({ enc })
        });
        if (!res.ok) throw new Error(res.status);
        const json = await res.json();
        binId = json.metadata?.id || json.id;
        localStorage.setItem(LS.INDEX_BIN, binId);
        return true;
      } else {
        const res = await fetch(`${JSONBIN_BASE}/b/${binId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'X-Master-Key': getApiKey(),
            'X-Bin-Versioning': 'false',
          },
          body: JSON.stringify({ enc })
        });
        return res.ok;
      }
    } catch(e) { console.warn('saveIndex:', e.message); return false; }
  }

  async function createDataBin(uid, pw, data) {
    if (!hasApiKey()) return null;
    try {
      const enc = await encrypt(data, pw, uid);
      const res = await fetch(`${JSONBIN_BASE}/b`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Master-Key': getApiKey(),
          'X-Bin-Name': `bht_data_${uid.slice(0,8)}`,
          'X-Bin-Private': 'true',
        },
        body: JSON.stringify({ enc })
      });
      if (!res.ok) throw new Error(res.status);
      const json = await res.json();
      return json.metadata?.id || json.id || null;
    } catch(e) { console.warn('createDataBin:', e.message); return null; }
  }

  async function loadDataBin(binId, pw, uid) {
    if (!hasApiKey() || !binId) return null;
    try {
      const res = await fetch(`${JSONBIN_BASE}/b/${binId}/latest`, {
        headers: { 'X-Master-Key': getApiKey(), 'X-Bin-Meta': 'false' }
      });
      if (!res.ok) throw new Error(res.status);
      const json = await res.json();
      const record = json.record || json;
      if (record && record.enc) return await decrypt(record.enc, pw, uid);
      return record || null;
    } catch(e) { console.warn('loadDataBin:', e.message); return null; }
  }

  async function saveDataBin(binId, pw, uid, data) {
    if (!hasApiKey() || !binId) {
      _saveCache(uid, data);
      setSyncStatus('local');
      return false;
    }
    setSyncStatus('syncing');
    try {
      const enc = await encrypt(data, pw, uid);
      const res = await fetch(`${JSONBIN_BASE}/b/${binId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Master-Key': getApiKey(),
          'X-Bin-Versioning': 'false',
        },
        body: JSON.stringify({ enc })
      });
      if (!res.ok) throw new Error(res.status);
      setSyncStatus('ok');
      state.lastSync = new Date().toISOString();
      _updateSyncUI();
      _saveCache(uid, data);
      return true;
    } catch(e) {
      console.warn('saveDataBin:', e.message);
      setSyncStatus('error');
      _saveCache(uid, data);
      return false;
    }
  }

  // ─── Local cache (offline fallback only) ─────────────────────────────────────
  function _saveCache(uid, data) { try { localStorage.setItem(LS.CACHE(uid), JSON.stringify({data, ts:Date.now()})); } catch(e){} }
  function _getCache(uid) { try { const r = localStorage.getItem(LS.CACHE(uid)); return r ? JSON.parse(r).data : null; } catch(e){ return null; } }

  // Local fallback user store (used when no API key set — single device mode)
  function getLocalUsers() { try { return JSON.parse(localStorage.getItem(LS.LOCAL_USERS)||'[]'); } catch(e){ return []; } }
  function saveLocalUsers(u) { localStorage.setItem(LS.LOCAL_USERS, JSON.stringify(u)); }

  function setSyncStatus(s){ state.syncStatus=s; _updateSyncUI(); }
  function _updateSyncUI(){
    ['sync-dot','sync-dot2'].forEach(id=>{const el=document.getElementById(id);if(!el)return;el.className='sync-dot'+(state.syncStatus==='syncing'?' syncing':state.syncStatus==='error'?' error':state.syncStatus==='local'?' local':'');});
    ['sync-label','sync-label2'].forEach(id=>{const el=document.getElementById(id);if(!el)return;if(state.syncStatus==='local'){el.textContent='Local only — set API key';return;}if(state.syncStatus==='syncing'){el.textContent='Syncing\u2026';return;}if(state.syncStatus==='error'){el.textContent='Sync error';return;}el.textContent=state.lastSync?`Synced ${new Date(state.lastSync).toLocaleTimeString()}`:'Synced';});
  }

  function genId(){ return Date.now().toString(36)+Math.random().toString(36).slice(2,7); }
  function genUid(){ return 'u_'+(crypto.randomUUID?crypto.randomUUID():genId()).replace(/-/g,'').slice(0,16); }
  function getSession(){ return localStorage.getItem(LS.SESSION)||''; }
  function saveSession(t){ localStorage.setItem(LS.SESSION, t); }
  function clearSession(){ localStorage.removeItem(LS.SESSION); }

  function buildPayload(){
    return { findings:state.findings, writeups:state.writeups, workspaces:state.workspaces,
      reconNotes:state.reconNotes, reminders:state.reminders, streak:state.streak,
      monthlyGoal:state.monthlyGoal, settings:state.settings, timeLog:state.timeLog,
      version:5, lastModified:new Date().toISOString() };
  }

  async function syncToCloud(){
    if (!state.currentUser || !state.binId) {
      if (state.currentUser) _saveCache(state.currentUser.id, buildPayload());
      return false;
    }
    return saveDataBin(state.binId, state.currentUser.password, state.currentUser.id, buildPayload());
  }

  // ─── REGISTRATION — works from any device ────────────────────────────────────
  async function doRegister() {
    const btn    = document.getElementById('reg-btn');
    const uname  = document.getElementById('au-user').value.trim();
    const email  = document.getElementById('au-email').value.trim().toLowerCase();
    const pass   = document.getElementById('au-pass').value;
    const pass2  = document.getElementById('au-pass2').value;
    const errEl  = document.getElementById('auth-err');
    errEl.textContent = '';

    if (!uname||!email||!pass||!pass2){ errEl.textContent='All fields required.'; return; }
    if (pass.length < 8){ errEl.textContent='Password must be at least 8 characters.'; return; }
    if (pass !== pass2){ errEl.textContent='Passwords do not match.'; return; }
    if (!/^[a-zA-Z0-9_.\-]+$/.test(uname)){ errEl.textContent='Username: letters, numbers, _ . - only.'; return; }
    if (!/\S+@\S+\.\S+/.test(email)){ errEl.textContent='Enter a valid email.'; return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Creating account\u2026';

    const hash = await hashPw(pass);

    if (hasApiKey()) {
      // ── CLOUD REGISTRATION ──────────────────────────────────────────────────
      // Load existing index to check for duplicates across all devices
      setAuthStatus('Checking username availability\u2026');
      let indexUsers = await loadIndex() || [];
      // Ensure it's an array
      if (!Array.isArray(indexUsers)) indexUsers = indexUsers.users || [];

      if (indexUsers.find(u => u.username.toLowerCase() === uname.toLowerCase())) {
        errEl.textContent = 'Username already taken.'; btn.disabled=false; btn.innerHTML='Create account'; setAuthStatus(''); return;
      }
      if (indexUsers.find(u => u.email === email)) {
        errEl.textContent = 'An account with this email already exists.'; btn.disabled=false; btn.innerHTML='Create account'; setAuthStatus(''); return;
      }

      const uid = genUid();
      const initData = emptyUserData(uname);

      setAuthStatus('Creating your data store\u2026');
      const dataBinId = await createDataBin(uid, pass, initData);
      if (!dataBinId) {
        errEl.textContent = 'Could not create cloud storage. Check your API key in Settings.';
        btn.disabled=false; btn.innerHTML='Create account'; setAuthStatus(''); return;
      }

      const newUser = { uid, username:uname, email, hash, dataBinId, joined:new Date().toISOString() };
      indexUsers.push(newUser);

      setAuthStatus('Saving account\u2026');
      const saved = await saveIndex(indexUsers);
      if (!saved) {
        errEl.textContent = 'Could not save account to cloud. Check your API key.';
        btn.disabled=false; btn.innerHTML='Create account'; setAuthStatus(''); return;
      }

      // Also save locally so this device can log in offline
      const localUsers = getLocalUsers();
      localUsers.push({ id:uid, username:uname, email, hash, dataBinId, joined:newUser.joined });
      saveLocalUsers(localUsers);
      localStorage.setItem(LS.BIN(uid), dataBinId);
      _saveCache(uid, initData);

      btn.disabled=false; btn.innerHTML='Create account'; setAuthStatus('');
      await startSession({ id:uid, username:uname, email, dataBinId, joined:newUser.joined }, pass, dataBinId, initData);
      toast('Account created! You can now log in from any device. \ud83c\udf89');

    } else {
      // ── LOCAL-ONLY REGISTRATION (no API key) ────────────────────────────────
      const localUsers = getLocalUsers();
      if (localUsers.find(u => u.username.toLowerCase() === uname.toLowerCase())) {
        errEl.textContent='Username already taken.'; btn.disabled=false; btn.innerHTML='Create account'; return;
      }
      if (localUsers.find(u => u.email === email)) {
        errEl.textContent='An account with this email already exists.'; btn.disabled=false; btn.innerHTML='Create account'; return;
      }
      const uid = genUid();
      const user = { id:uid, username:uname, email, hash, joined:new Date().toISOString() };
      localUsers.push(user); saveLocalUsers(localUsers);
      const initData = emptyUserData(uname);
      _saveCache(uid, initData);
      btn.disabled=false; btn.innerHTML='Create account';
      await startSession(user, pass, null, initData);
      toast('Account created! Set an API key in Settings to sync across devices.');
    }
  }

  // ─── LOGIN — works from any device ──────────────────────────────────────────
  async function doLogin() {
    const btn   = document.getElementById('login-btn');
    const val   = document.getElementById('au-login').value.trim();
    const pass  = document.getElementById('au-pass').value;
    const errEl = document.getElementById('auth-err');
    const tfaRow= document.getElementById('tfa-row');
    errEl.textContent = '';

    if (!val||!pass){ errEl.textContent='Enter your username/email and password.'; return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Signing in\u2026';

    const hash = await hashPw(pass);
    let user = null;
    let dataBinId = null;
    let data = null;

    if (hasApiKey()) {
      // ── CLOUD LOGIN — checks against cloud user index ────────────────────────
      setAuthStatus('Looking up your account\u2026');
      const indexUsers = await loadIndex();

      if (indexUsers && Array.isArray(indexUsers)) {
        const found = indexUsers.find(u =>
          (u.username.toLowerCase() === val.toLowerCase() || u.email === val.toLowerCase())
          && u.hash === hash
        );
        if (found) {
          user = { id:found.uid, username:found.username, email:found.email, joined:found.joined };
          dataBinId = found.dataBinId;
          // Update local cache of this user so offline works next time
          const localUsers = getLocalUsers();
          if (!localUsers.find(u => u.id === found.uid)) {
            localUsers.push({ id:found.uid, username:found.username, email:found.email, hash, dataBinId, joined:found.joined });
            saveLocalUsers(localUsers);
          }
          localStorage.setItem(LS.BIN(found.uid), dataBinId);
        }
      }

      if (!user) {
        // Cloud lookup failed or credentials wrong — try local cache as fallback
        const localUsers = getLocalUsers();
        const found = localUsers.find(u =>
          (u.username.toLowerCase() === val.toLowerCase() || u.email === val.toLowerCase())
          && u.hash === hash
        );
        if (found) { user={ id:found.id||found.uid, username:found.username, email:found.email, joined:found.joined }; dataBinId=found.dataBinId||localStorage.getItem(LS.BIN(found.id||found.uid)); }
      }
    } else {
      // ── LOCAL-ONLY LOGIN (no API key) ────────────────────────────────────────
      const localUsers = getLocalUsers();
      const found = localUsers.find(u =>
        (u.username.toLowerCase() === val.toLowerCase() || u.email === val.toLowerCase())
        && u.hash === hash
      );
      if (found) { user={ id:found.id||found.uid, username:found.username, email:found.email, joined:found.joined }; dataBinId=found.dataBinId||null; }
    }

    if (!user) {
      errEl.textContent = 'Invalid username/email or password.';
      btn.disabled=false; btn.innerHTML='Sign in'; setAuthStatus(''); return;
    }

    // Load data
    setAuthStatus('Loading your data\u2026');
    if (dataBinId && hasApiKey()) data = await loadDataBin(dataBinId, pass, user.id);
    if (!data) data = _getCache(user.id);
    if (!data) data = emptyUserData(user.username);

    // 2FA check
    if (data.settings?.twoFAEnabled && data.settings?.twoFASecret) {
      if (tfaRow.classList.contains('hidden')) {
        tfaRow.classList.remove('hidden');
        errEl.textContent = 'Enter your 6-digit authenticator code.';
        btn.disabled=false; btn.innerHTML='Sign in'; setAuthStatus('');
        document.getElementById('au-tfa').focus(); return;
      }
      const token = document.getElementById('au-tfa')?.value.trim()||'';
      if (!token){ errEl.textContent='Enter your authenticator code.'; btn.disabled=false; btn.innerHTML='Sign in'; setAuthStatus(''); return; }
      if (!await verifyTOTP(data.settings.twoFASecret, token)){ errEl.textContent='Invalid or expired code.'; btn.disabled=false; btn.innerHTML='Sign in'; setAuthStatus(''); return; }
    }

    _saveCache(user.id, data);
    btn.disabled=false; btn.innerHTML='Sign in'; setAuthStatus('');
    await startSession(user, pass, dataBinId, data);
  }

  function setAuthStatus(msg) {
    const el = document.getElementById('auth-status');
    if (el) el.textContent = msg;
  }

  function emptyUserData(username) {
    return { findings:[], writeups:[], workspaces:[], reconNotes:[], reminders:[],
      streak:{current:0,longest:0,lastActive:null,history:[]}, timeLog:[],
      monthlyGoal:300, settings:{twoFAEnabled:false,twoFASecret:null,displayName:username,theme:'dark'}, version:5 };
  }

  async function startSession(user, password, dataBinId, data) {
    state.currentUser = { ...user, password };
    state.findings    = data.findings   || [];
    state.writeups    = data.writeups   || [];
    state.workspaces  = data.workspaces || [];
    state.reconNotes  = data.reconNotes || [];
    state.reminders   = data.reminders  || [];
    state.streak      = data.streak     || {current:0,longest:0,lastActive:null,history:[]};
    state.timeLog     = data.timeLog    || [];
    state.monthlyGoal = data.monthlyGoal|| 300;
    state.settings    = Object.assign({twoFAEnabled:false,twoFASecret:null,displayName:user.username,theme:'dark'}, data.settings||{});
    state.binId       = dataBinId;
    applyTheme(state.settings.theme || 'dark');
    saveSession(btoa(user.id+':'+Date.now())+'|'+user.id);
    updateStreak();
    renderApp();
    if (!hasApiKey()) setSyncStatus('local');
    else if (!dataBinId) setSyncStatus('local');
    setTimeout(checkReminders, 2000);
    setInterval(checkReminders, 60000);
  }

  async function doLogout() {
    _saveCache(state.currentUser?.id, buildPayload());
    await syncToCloud().catch(()=>{});
    clearSession();
    if (_timerInterval) clearInterval(_timerInterval);
    Object.assign(state, { currentUser:null, findings:[], writeups:[], workspaces:[],
      reconNotes:[], reminders:[], activePanel:'dashboard', charts:{}, binId:null, lastSync:null });
    renderAuth();
  }

  // ─── Merge helpers (data is NEVER deleted on sync) ────────────────────────────
  function mergeById(existing, incoming) {
    const map = new Map(existing.map(x => [x.id, x]));
    incoming.forEach(item => {
      if (!map.has(item.id)) { map.set(item.id, item); }
      else {
        const ex = map.get(item.id);
        const exT = new Date(ex.updated||ex.created||0).getTime();
        const inT = new Date(item.updated||item.created||0).getTime();
        if (inT > exT) map.set(item.id, item);
      }
    });
    return Array.from(map.values());
  }
  function mergeWorkspaces(local, cloud) {
    const map = new Map(local.map(w => [w.id, {...w}]));
    cloud.forEach(cw => {
      if (!map.has(cw.id)) { map.set(cw.id, cw); }
      else {
        const lw = map.get(cw.id);
        lw.entries = mergeById(lw.entries||[], cw.entries||[]);
        const lT = new Date(lw.updated||lw.created||0).getTime();
        const cT = new Date(cw.updated||cw.created||0).getTime();
        map.set(cw.id, cT > lT ? {...cw, entries:lw.entries} : lw);
      }
    });
    return Array.from(map.values());
  }
  async function safeSyncToCloud() {
    if (!state.currentUser || !state.binId || !hasApiKey()) {
      if (state.currentUser) _saveCache(state.currentUser.id, buildPayload());
      return false;
    }
    setSyncStatus('syncing');
    const cloud = await loadDataBin(state.binId, state.currentUser.password, state.currentUser.id);
    if (cloud) {
      state.findings   = mergeById(state.findings,   cloud.findings||[]);
      state.writeups   = mergeById(state.writeups,   cloud.writeups||[]);
      state.workspaces = mergeWorkspaces(state.workspaces, cloud.workspaces||[]);
      state.reconNotes = mergeById(state.reconNotes, cloud.reconNotes||[]);
      state.reminders  = mergeById(state.reminders,  cloud.reminders||[]);
      state.timeLog    = mergeById(state.timeLog||[], cloud.timeLog||[]);
      const cs = cloud.streak||{};
      state.streak = {
        current: Math.max(state.streak.current||0, cs.current||0),
        longest: Math.max(state.streak.longest||0, cs.longest||0),
        lastActive: [state.streak.lastActive, cs.lastActive].filter(Boolean).sort().pop(),
        history: [...new Set([...(state.streak.history||[]), ...(cs.history||[])])].sort(),
      };
    }
    return saveDataBin(state.binId, state.currentUser.password, state.currentUser.id, buildPayload());
  }

  // ─── Streak ───────────────────────────────────────────────────────────────────
  function updateStreak(){
    const today=new Date().toISOString().split('T')[0],s=state.streak;
    if(s.lastActive===today)return;
    const yesterday=new Date(Date.now()-86400000).toISOString().split('T')[0];
    s.current=s.lastActive===yesterday?(s.current||0)+1:1;
    s.longest=Math.max(s.longest||0,s.current);s.lastActive=today;
    if(!s.history)s.history=[];if(!s.history.includes(today))s.history.push(today);
    syncToCloud();
  }

  // ─── Reminders ────────────────────────────────────────────────────────────────
  function checkReminders(){
    if(!('Notification' in window))return;const now=Date.now();
    (state.reminders||[]).forEach(r=>{if(r.fired)return;if(now>=new Date(r.dueDate).getTime()){r.fired=true;if(Notification.permission==='granted')new Notification('BugHunter Reminder',{body:r.text});else toast('\u23f0 Reminder: '+r.text,'info');syncToCloud();}});
    const seven=7*864e5;state.findings.filter(f=>f.status==='submitted').forEach(f=>{if(now-new Date(f.updated||f.created).getTime()>seven&&!f._reminderFired){f._reminderFired=true;toast(`\u23f0 No response in 7 days: "${f.title.slice(0,35)}" \u2014 follow up?`,'info');}});
  }
  async function requestNotificationPermission(){if(!('Notification' in window)){toast('Not supported','err');return;}const p=await Notification.requestPermission();toast(p==='granted'?'Notifications enabled! \u2705':'Enable in browser settings.',p==='granted'?'ok':'err');}

  // ─── CVE Lookup ───────────────────────────────────────────────────────────────
  async function lookupCVE(cveId){
    const el=document.getElementById('cve-result');if(!el)return;el.innerHTML='<span class="spinner"></span> Looking up\u2026';
    try{const res=await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId.trim())}`);if(!res.ok)throw new Error();const json=await res.json(),vuln=json.vulnerabilities?.[0]?.cve;if(!vuln)throw new Error();
    const desc=vuln.descriptions?.find(d=>d.lang==='en')?.value||'No description';const score=vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore||vuln.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore||'N/A';const sev=vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity||'';const cls=score>=9?'p1':score>=7?'p2':score>=4?'p3':'p4';
    el.innerHTML=`<div class="cve-result-box"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;"><strong style="font-family:var(--mono);color:var(--accent);">${esc(vuln.id)}</strong><span class="badge ${cls}">CVSS ${score} ${esc(sev)}</span></div><div style="font-size:13px;color:var(--text2);line-height:1.65;">${esc(desc)}</div><a href="https://nvd.nist.gov/vuln/detail/${esc(vuln.id)}" target="_blank" class="btn" style="margin-top:10px;font-size:12px;display:inline-flex;gap:4px;">${I.link} View on NVD</a></div>`;}
    catch(e){el.innerHTML=`<div style="color:var(--red);font-size:13px;">CVE not found or NVD unavailable. <a href="https://nvd.nist.gov/vuln/search" target="_blank">Search NVD</a></div>`;}
  }

  function checkDuplicate(title){if(!title||title.length<4)return[];const q=title.toLowerCase().slice(0,20);return state.findings.filter(f=>f.id!==state.editId&&(f.title||'').toLowerCase().includes(q));}

  // ─── Report Generator ─────────────────────────────────────────────────────────
  function generateReport(fid){
    const f=state.findings.find(x=>x.id===fid);if(!f)return;
    const pmap={p1:'Critical',p2:'High',p3:'Medium',p4:'Low',p5:'Informational',na:'N/A'};
    const imp={p1:'**Critical impact.** Full system compromise or mass data theft possible.',p2:'**High impact.** Significant data exposure or privilege escalation.',p3:'**Medium impact.** Exploitation requires specific conditions.',p4:'**Low impact.** Limited risk.',p5:'**Informational.** No direct exploitability.'};
    const report=`# Bug Report: ${f.title}\n\n**Severity:** ${pmap[f.priority]||'N/A'}\n**Type:** ${f.vulnType||'N/A'}\n**Program:** ${f.program||'N/A'}\n**Platform:** ${f.platform||'N/A'}\n**Affected URL:** ${f.url||'N/A'}\n**Date Found:** ${f.date||new Date().toISOString().split('T')[0]}\n\n---\n\n## Summary\n\n${f.desc||'[Describe the vulnerability]'}\n\n---\n\n## Steps to Reproduce\n\n${f.desc?f.desc.split('\n').filter(l=>l.trim()).map((l,i)=>`${i+1}. ${l}`).join('\n'):'1. [Step 1]\n2. [Step 2]\n3. [Step 3]'}\n\n---\n\n## Impact\n\n${imp[f.priority]||imp.p3}\n\n---\n\n## Proof of Concept\n\n\`\`\`\n${f.desc||'[PoC payload or steps]'}\n\`\`\`\n\n---\n\n## Recommended Fix\n\n${f.fix||'[Describe the fix]'}\n\n---\n*Reporter: ${state.settings.displayName||state.currentUser?.username||'Anonymous'}*\n*Generated: ${new Date().toLocaleDateString()}*`;
    state._currentReport=report;
    showDetail(`<div class="modal-header"><h3>Generated Report</h3><button class="icon-btn" onclick="App.closeDetail()">${I.close}</button></div><div class="modal-body"><div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;"><button class="btn accent" onclick="App._copyReport()">${I.copy} Copy report</button><button class="btn" onclick="App._downloadReport('${fid}')">${I.download} Download .md</button><span style="font-size:12px;color:var(--text3);align-self:center;">Paste into HackerOne / Bugcrowd</span></div><pre id="report-content" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:16px;font-family:var(--mono);font-size:12px;line-height:1.7;overflow-x:auto;white-space:pre-wrap;color:var(--text2);">${esc(report)}</pre></div><div class="modal-footer"><button class="btn" onclick="App.closeDetail()">Close</button></div>`);
  }
  function _copyReport(){navigator.clipboard.writeText(state._currentReport||'').then(()=>toast('Copied!','info')).catch(()=>{});}
  function _downloadReport(fid){const f=state.findings.find(x=>x.id===fid),blob=new Blob([state._currentReport||''],{type:'text/markdown'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`report_${(f?.title||'bug').replace(/\s+/g,'_').slice(0,40)}.md`;a.click();}

  // ─── Program directory ────────────────────────────────────────────────────────
  const KNOWN_PROGRAMS=[
    {name:'HackerOne',platform:'HackerOne',url:'https://hackerone.com/hackerone',bounty:true,scope:'Web, API',tags:['web','api']},
    {name:'Shopify',platform:'HackerOne',url:'https://hackerone.com/shopify',bounty:true,scope:'Web, Mobile, API',tags:['web','mobile','ecommerce']},
    {name:'GitHub',platform:'HackerOne',url:'https://hackerone.com/github',bounty:true,scope:'Web, API, Desktop',tags:['web','api','code']},
    {name:'Twitter / X',platform:'HackerOne',url:'https://hackerone.com/twitter',bounty:true,scope:'Web, Mobile, API',tags:['web','mobile','social']},
    {name:'Uber',platform:'HackerOne',url:'https://hackerone.com/uber',bounty:true,scope:'Web, Mobile, API',tags:['web','mobile']},
    {name:'Coinbase',platform:'HackerOne',url:'https://hackerone.com/coinbase',bounty:true,scope:'Web, Mobile, API',tags:['crypto','web']},
    {name:'Google',platform:'HackerOne',url:'https://bughunters.google.com',bounty:true,scope:'All Google products',tags:['web','mobile','api']},
    {name:'Meta / Facebook',platform:'HackerOne',url:'https://www.facebook.com/whitehat',bounty:true,scope:'Facebook, Instagram, WhatsApp',tags:['web','mobile','social']},
    {name:'Microsoft',platform:'HackerOne',url:'https://www.microsoft.com/en-us/msrc/bounty',bounty:true,scope:'Windows, Azure, Office, Edge',tags:['web','cloud','os']},
    {name:'Apple',platform:'HackerOne',url:'https://security.apple.com',bounty:true,scope:'iOS, macOS, iCloud, Safari',tags:['mobile','web','os']},
    {name:'Dropbox',platform:'Bugcrowd',url:'https://bugcrowd.com/dropbox',bounty:true,scope:'Web, Mobile, Desktop',tags:['web','mobile','storage']},
    {name:'Tesla',platform:'Bugcrowd',url:'https://bugcrowd.com/tesla',bounty:true,scope:'Web, API, Vehicles',tags:['iot','web']},
    {name:'PayPal',platform:'HackerOne',url:'https://hackerone.com/paypal',bounty:true,scope:'Web, Mobile, API',tags:['fintech','web']},
    {name:'Intigriti',platform:'Intigriti',url:'https://app.intigriti.com/programs',bounty:true,scope:'Various EU programs',tags:['web','api','eu']},
    {name:'YesWeHack',platform:'YesWeHack',url:'https://yeswehack.com',bounty:true,scope:'Various programs',tags:['web','api']},
    {name:'Immunefi',platform:'Immunefi',url:'https://immunefi.com',bounty:true,scope:'DeFi, Blockchain, Smart Contracts',tags:['crypto','web3']},
    {name:'OpenBugBounty',platform:'OpenBugBounty',url:'https://www.openbugbounty.org',bounty:false,scope:'Web (XSS, CSRF)',tags:['web','xss']},
    {name:'Synack',platform:'Synack',url:'https://www.synack.com',bounty:true,scope:'Invite only',tags:['web','api','invite']},
    {name:'HackenProof',platform:'HackenProof',url:'https://hackenproof.com',bounty:true,scope:'Crypto, Web, API',tags:['crypto','web']},
    {name:'Bugcrowd',platform:'Bugcrowd',url:'https://bugcrowd.com',bounty:true,scope:'Various programs',tags:['web','api']},
  ];
  function renderProgramDirectory(){
    const el=document.getElementById('panel-programs');if(!el)return;
    const query=(document.getElementById('prog-search')?.value||'').toLowerCase();
    const platFilter=document.getElementById('prog-plat')?.value||'all';
    let list=KNOWN_PROGRAMS;
    if(query)list=list.filter(p=>p.name.toLowerCase().includes(query)||p.tags.some(t=>t.includes(query))||p.scope.toLowerCase().includes(query));
    if(platFilter!=='all')list=list.filter(p=>p.platform===platFilter);
    el.innerHTML=`<div style="display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;">
      <div class="search-wrap" style="flex:1;min-width:200px;"><span class="search-icon">${I.search}</span><input id="prog-search" placeholder="Search programs…" oninput="App.renderProgramDirectory()" style="width:100%;"/></div>
      <select id="prog-plat" onchange="App.renderProgramDirectory()" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:7px 12px;color:var(--text);font-size:13px;">
        <option value="all">All platforms</option>${[...new Set(KNOWN_PROGRAMS.map(p=>p.platform))].map(p=>`<option value="${p}" ${platFilter===p?'selected':''}>${p}</option>`).join('')}
      </select></div>
    <div class="writeup-grid">${list.map(p=>`<div class="writeup-card" style="cursor:default;">
      <div style="margin-bottom:8px;"><div class="writeup-card-title" style="margin-bottom:6px;">${esc(p.name)}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;"><span class="badge ${p.platform==='HackerOne'?'p4':p.platform==='Bugcrowd'?'p3':p.platform==='Intigriti'?'p2':p.platform==='Immunefi'?'p1':'pna'}" style="font-family:var(--font);font-size:11px;">${esc(p.platform)}</span>${p.bounty?'<span class="badge status-resolved" style="font-family:var(--font);font-size:11px;">💰 Bounty</span>':'<span class="badge pna" style="font-family:var(--font);font-size:11px;">No bounty</span>'}</div></div>
      <div style="font-size:12px;color:var(--text3);margin-bottom:10px;"><strong>Scope:</strong> ${esc(p.scope)}</div>
      <div class="writeup-tags" style="margin-bottom:12px;">${p.tags.map(t=>`<span class="writeup-tag">${esc(t)}</span>`).join('')}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;"><a href="${esc(p.url)}" target="_blank" rel="noopener" class="btn" style="font-size:12px;padding:5px 10px;text-decoration:none;">${I.link} View</a>
      <button class="btn accent" style="font-size:12px;padding:5px 10px;" onclick='App.startWorkspaceFromProgram(${JSON.stringify(p).replace(/'/g,"\\x27")})'>+ Workspace</button></div>
    </div>`).join('')}</div>`;
  }
  async function startWorkspaceFromProgram(p){
    const ws={id:genId(),name:`${p.platform} — ${p.name}`,emoji:'🎯',description:`Scope: ${p.scope}`,color:'#f78166',created:new Date().toISOString(),updated:new Date().toISOString(),entries:[]};
    state.workspaces.push(ws);await safeSyncToCloud();updateBadges();state.activeWorkspace=ws.id;nav('workspaces');toast(`Workspace created for ${p.name}!`);
  }

  // ─── Recon Notes ──────────────────────────────────────────────────────────────
  function renderReconNotes(){
    const el=document.getElementById('panel-recon');if(!el)return;const notes=state.reconNotes||[];
    el.innerHTML=`<div class="section-header" style="margin-bottom:16px;"><span class="section-title">Recon Notes</span><button class="btn accent" onclick="App.openReconModal()">${I.plus} New note</button></div>
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 14px;font-size:12px;color:var(--text3);margin-bottom:16px;">💡 Dump subdomains, endpoints, JS files, tokens found during recon. Raw dump separate from workspaces.</div>
    ${!notes.length?`<div class="empty-state">${I.search}<p>No recon notes yet.</p></div>`:`<div style="display:flex;flex-direction:column;gap:12px;">${[...notes].sort((a,b)=>new Date(b.created)-new Date(a.created)).map(n=>`<div class="card"><div class="card-header" style="padding:10px 14px;"><div><span style="font-weight:600;font-size:14px;">${esc(n.title)}</span>${n.target?`<span style="margin-left:8px;font-size:11px;color:var(--text3);font-family:var(--mono);">${esc(n.target)}</span>`:''}</div><div style="display:flex;gap:6px;align-items:center;"><span class="badge ${n.type==='subdomain'?'p4':n.type==='endpoint'?'p3':n.type==='secret'?'p1':n.type==='js'?'p2':'pna'}" style="font-family:var(--font);">${esc(n.type||'misc')}</span><button class="icon-btn" onclick="App.openReconModal('${n.id}')">${I.edit}</button><button class="icon-btn" onclick="App.deleteRecon('${n.id}')">${I.trash}</button></div></div><div style="padding:12px 14px;"><pre style="font-family:var(--mono);font-size:12px;color:var(--green);background:#0d1117;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;margin:0;">${esc(n.content||'')}</pre>${n.notes?`<div style="margin-top:8px;font-size:13px;color:var(--text2);">${esc(n.notes)}</div>`:''}<div style="margin-top:6px;font-size:11px;color:var(--text3);font-family:var(--mono);">${fmtDate(n.created)}</div></div></div>`).join('')}</div>`}`;
  }
  function openReconModal(id){const n=id?state.reconNotes.find(x=>x.id===id):null,v=(k,d='')=>n?(n[k]!=null?n[k]:d):d;showModal(`<div class="modal-header"><h3>${id?'Edit':'New'} recon note</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div><div class="modal-body"><div class="form-row"><div class="form-field"><label>Title *</label><input id="rn-title" value="${esc(v('title'))}" placeholder="Subdomains found"/></div><div class="form-field"><label>Target</label><input id="rn-target" value="${esc(v('target'))}" placeholder="target.com"/></div></div><div class="form-field form-field-full"><label>Type</label><select id="rn-type">${['subdomain','endpoint','js','secret','header','token','misc'].map(t=>`<option value="${t}" ${v('type','misc')===t?'selected':''}>${t.charAt(0).toUpperCase()+t.slice(1)}</option>`).join('')}</select></div><div class="form-field form-field-full"><label>Content</label><textarea id="rn-content" class="writeup-editor" style="min-height:160px;" placeholder="api.target.com&#10;admin.target.com&#10;...">${esc(v('content'))}</textarea></div><div class="form-field form-field-full"><label>Notes</label><textarea id="rn-notes" style="min-height:60px;" placeholder="Tools used, context...">${esc(v('notes'))}</textarea></div></div><div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveRecon('${id||''}')">Save</button></div>`);setTimeout(()=>document.getElementById('rn-title')?.focus(),50);}
  async function saveRecon(id){const title=document.getElementById('rn-title').value.trim();if(!title){toast('Title required','err');return;}const n={id:id||genId(),title,target:document.getElementById('rn-target').value.trim(),type:document.getElementById('rn-type').value,content:document.getElementById('rn-content').value.trim(),notes:document.getElementById('rn-notes').value.trim(),updated:new Date().toISOString()};if(!state.reconNotes)state.reconNotes=[];if(id){const idx=state.reconNotes.findIndex(x=>x.id===id);n.created=state.reconNotes[idx]?.created||n.updated;state.reconNotes[idx]=n;toast('Updated!');}else{n.created=new Date().toISOString();state.reconNotes.unshift(n);toast('Recon note saved!');}closeModal();updateBadges();await safeSyncToCloud();renderPanel(state.activePanel);}
  async function deleteRecon(id){if(!confirm('Delete?'))return;state.reconNotes=state.reconNotes.filter(x=>x.id!==id);await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);toast('Deleted.');}

  // ─── Program stats ────────────────────────────────────────────────────────────
  function renderProgramStats(){
    const el=document.getElementById('panel-progstats');if(!el)return;
    const resolved=state.findings.filter(f=>f.status==='resolved');
    const byPlatform={};state.findings.forEach(f=>{const p=f.platform||'Unknown';if(!byPlatform[p])byPlatform[p]={total:0,resolved:0,earned:0,dupes:0};byPlatform[p].total++;if(f.status==='resolved'){byPlatform[p].resolved++;byPlatform[p].earned+=(f.bounty||0);}if(f.status==='duplicate')byPlatform[p].dupes++;});
    const byProgram={};state.findings.forEach(f=>{const p=f.program||'Unknown';if(!byProgram[p])byProgram[p]={total:0,resolved:0,earned:0,dupes:0};byProgram[p].total++;if(f.status==='resolved'){byProgram[p].resolved++;byProgram[p].earned+=(f.bounty||0);}if(f.status==='duplicate')byProgram[p].dupes++;});
    const topPlatforms=Object.entries(byPlatform).sort((a,b)=>b[1].earned-a[1].earned);
    const topPrograms=Object.entries(byProgram).sort((a,b)=>b[1].earned-a[1].earned).slice(0,10);
    const successRate=state.findings.length?((resolved.length/state.findings.length)*100).toFixed(0)+'%':'--';
    const avgBounty=resolved.length?fmtMoney(Math.round(resolved.reduce((s,f)=>s+(f.bounty||0),0)/resolved.length)):'--';
    el.innerHTML=`<div class="metrics-grid" style="margin-bottom:24px;"><div class="metric-card"><div class="metric-label">Success rate</div><div class="metric-value text-green">${successRate}</div><div class="metric-sub">Resolved / Total</div></div><div class="metric-card"><div class="metric-label">Avg bounty</div><div class="metric-value text-green">${avgBounty}</div></div><div class="metric-card"><div class="metric-label">Platforms</div><div class="metric-value">${Object.keys(byPlatform).length}</div></div><div class="metric-card"><div class="metric-label">Programs</div><div class="metric-value">${Object.keys(byProgram).length}</div></div></div>
    <div class="charts-grid" style="margin-bottom:20px;"><div class="card"><div class="card-header"><span class="card-header-title">Earnings by platform</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="chart-plat"></canvas></div></div></div><div class="card"><div class="card-header"><span class="card-header-title">Success rate by platform</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="chart-rate"></canvas></div></div></div></div>
    <div class="card"><div class="card-header"><span class="card-header-title">Top programs</span></div><div class="table-wrap"><table><thead><tr><th>Program</th><th>Findings</th><th>Resolved</th><th>Dupes</th><th>Earned</th><th>Rate</th></tr></thead><tbody>${topPrograms.map(([name,s])=>`<tr><td style="font-weight:500;">${esc(name)}</td><td class="td-mono">${s.total}</td><td class="td-mono text-green">${s.resolved}</td><td class="td-mono">${s.dupes}</td><td class="bounty-val">${fmtMoney(s.earned)}</td><td class="td-mono">${s.total?Math.round(s.resolved/s.total*100)+'%':'--'}</td></tr>`).join('')}</tbody></table></div></div>`;
    setTimeout(()=>{if(typeof Chart==='undefined')return;const pn=topPlatforms.map(([k])=>k),pe=topPlatforms.map(([,v])=>v.earned);const c1=document.getElementById('chart-plat');if(c1)new Chart(c1,{type:'bar',data:{labels:pn,datasets:[{data:pe,backgroundColor:'#f78166',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#656d76'}},y:{ticks:{color:'#656d76',callback:v=>'$'+v}}}}});const pr=topPlatforms.map(([,v])=>v.total?Math.round(v.resolved/v.total*100):0);const c2=document.getElementById('chart-rate');if(c2)new Chart(c2,{type:'bar',data:{labels:pn,datasets:[{data:pr,backgroundColor:'#3fb950',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#656d76'}},y:{ticks:{color:'#656d76',callback:v=>v+'%'},max:100}}}});},50);
  }

  // ─── Time Tracker ─────────────────────────────────────────────────────────────
  let _timerInterval=null,_timerStart=null,_timerFindingId=null;
  function startTimer(fid){if(_timerInterval){clearInterval(_timerInterval);_timerInterval=null;}_timerStart=Date.now();_timerFindingId=fid||null;_timerInterval=setInterval(()=>{const secs=Math.floor((Date.now()-_timerStart)/1000),h=Math.floor(secs/3600),m=Math.floor((secs%3600)/60),s=secs%60;const el=document.getElementById('timer-display');if(el)el.textContent=`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;},1000);toast('Timer started ⏱️','info');}
  async function stopTimer(){if(!_timerStart){toast('No timer running','err');return;}clearInterval(_timerInterval);_timerInterval=null;const mins=Math.max(1,Math.round((Date.now()-_timerStart)/60000));const log={id:genId(),findingId:_timerFindingId,date:new Date().toISOString().split('T')[0],minutes:mins,start:new Date(_timerStart).toISOString(),end:new Date().toISOString()};if(!state.timeLog)state.timeLog=[];state.timeLog.push(log);_timerStart=null;_timerFindingId=null;await safeSyncToCloud();toast(`Logged ${mins} min ✅`,'info');renderPanel(state.activePanel);}
  function renderTimeTracker(){
    const el=document.getElementById('panel-time');if(!el)return;const logs=state.timeLog||[];const total=logs.reduce((s,l)=>s+l.minutes,0);const byFinding={};logs.forEach(l=>{if(!byFinding[l.findingId])byFinding[l.findingId]=0;byFinding[l.findingId]+=l.minutes;});const topFindings=Object.entries(byFinding).sort((a,b)=>b[1]-a[1]).slice(0,5).map(([fid,mins])=>({finding:state.findings.find(f=>f.id===fid),mins})).filter(x=>x.finding);const te=totalEarned(),hourlyRate=total>0&&te>0?fmtMoney(Math.round(te/(total/60))):'--';
    el.innerHTML=`<div class="metrics-grid" style="margin-bottom:24px;"><div class="metric-card"><div class="metric-label">Total logged</div><div class="metric-value">${Math.floor(total/60)}<span style="font-size:14px;">h</span> ${total%60}<span style="font-size:14px;">m</span></div></div><div class="metric-card"><div class="metric-label">Sessions</div><div class="metric-value">${logs.length}</div></div><div class="metric-card"><div class="metric-label">Effective rate</div><div class="metric-value text-green">${hourlyRate}<span style="font-size:14px;">/hr</span></div></div></div>
    <div class="card" style="margin-bottom:20px;"><div class="card-header"><span class="card-header-title">⏱️ Active timer</span></div><div style="padding:20px;"><div style="font-size:40px;font-family:var(--mono);font-weight:700;color:var(--text);margin-bottom:16px;letter-spacing:3px;" id="timer-display">${_timerStart?'Running…':'00:00:00'}</div><div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end;"><div class="form-field" style="flex:1;max-width:300px;"><label>Link to finding (optional)</label><select id="timer-finding" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:8px 11px;color:var(--text);font-size:13px;width:100%;"><option value="">No finding</option>${state.findings.map(f=>`<option value="${f.id}">${esc(f.title.slice(0,45))}</option>`).join('')}</select></div><button class="btn accent" onclick="App.startTimer(document.getElementById('timer-finding').value||null)">▶ Start</button><button class="btn" onclick="App.stopTimer()">⏹ Stop & log</button></div></div></div>
    ${topFindings.length?`<div class="card" style="margin-bottom:20px;"><div class="card-header"><span class="card-header-title">Time by finding</span></div><div class="table-wrap"><table><thead><tr><th>Finding</th><th>Time</th></tr></thead><tbody>${topFindings.map(({finding:f,mins})=>`<tr><td><div class="td-title">${esc(f.title)}</div></td><td class="td-mono">${Math.floor(mins/60)}h ${mins%60}m</td></tr>`).join('')}</tbody></table></div></div>`:''}
    <div class="card"><div class="card-header"><span class="card-header-title">Recent sessions</span></div><div class="table-wrap"><table><thead><tr><th>Date</th><th>Finding</th><th>Duration</th></tr></thead><tbody>${[...logs].reverse().slice(0,15).map(l=>{const f=state.findings.find(x=>x.id===l.findingId);return`<tr><td class="td-mono">${fmtDate(l.date)}</td><td>${f?esc(f.title.slice(0,40)):'<span style="color:var(--text3)">—</span>'}</td><td class="td-mono">${Math.floor(l.minutes/60)}h ${l.minutes%60}m</td></tr>`;}).join('')}${!logs.length?'<tr><td colspan="3" style="text-align:center;color:var(--text3);padding:24px;">No sessions yet.</td></tr>':''}</tbody></table></div></div>`;
  }

  // ─── Theme ────────────────────────────────────────────────────────────────────
  function applyTheme(t){document.documentElement.setAttribute('data-theme',t||'dark');state.settings.theme=t||'dark';}
  function toggleTheme(){const next=state.settings.theme==='dark'?'light':'dark';applyTheme(next);safeSyncToCloud();const btn=document.getElementById('theme-btn');if(btn)btn.textContent=next==='dark'?'☀️ Light':'🌙 Dark';}

  // ─── Constants ────────────────────────────────────────────────────────────────
  const PRIOS={p1:{label:'P1 — Critical',short:'P1',cls:'p1',desc:'RCE, auth bypass, account takeover'},p2:{label:'P2 — High',short:'P2',cls:'p2',desc:'SSRF, privilege escalation, significant data exposure'},p3:{label:'P3 — Medium',short:'P3',cls:'p3',desc:'XSS, CSRF, IDOR with limited impact'},p4:{label:'P4 — Low',short:'P4',cls:'p4',desc:'Self-XSS, open redirect, minor info disclosure'},p5:{label:'P5 — Info',short:'P5',cls:'p5',desc:'Best-practice issues, UI bugs'},na:{label:'N/A',short:'N/A',cls:'pna',desc:'Out of scope / not applicable'}};
  const STATUSES={new:{label:'New',cls:'status-new'},submitted:{label:'Submitted',cls:'status-submitted'},triaged:{label:'Triaged',cls:'status-triaged'},resolved:{label:'Resolved',cls:'status-resolved'},duplicate:{label:'Duplicate',cls:'status-duplicate'},na:{label:'N/A',cls:'status-na'}};
  const PLATFORMS=['HackerOne','Bugcrowd','Intigriti','YesWeHack','Synack','HackenProof','OpenBugBounty','Immunefi','Private Program','Other'];
  const VULN_TYPES=['XSS','SQL Injection','SSRF','RCE','LFI/RFI','IDOR','CSRF','Open Redirect','Auth Bypass','Business Logic','Info Disclosure','Broken Access Control','XXE','SSTI','Prototype Pollution','Deserialization','Other'];
  const WS_COLORS=['#f78166','#58a6ff','#3fb950','#d29922','#bc8cff','#f0883e','#39d353','#ff6b6b'];

  // ─── Helpers ──────────────────────────────────────────────────────────────────
  function pbadge(p){const m=PRIOS[p]||PRIOS.na;return`<span class="badge ${m.cls}">${m.short}</span>`;}
  function sbadge(s){const m=STATUSES[s]||STATUSES.na;return`<span class="badge ${m.cls}">${m.label}</span>`;}
  function fmtDate(d){if(!d)return'—';return new Date(d).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'});}
  function fmtMoney(v){return'$'+Number(v||0).toLocaleString();}
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function toast(msg,type='ok'){const el=document.createElement('div');el.className='toast';el.style.borderLeft=`3px solid ${type==='ok'?'var(--green)':type==='info'?'var(--blue)':'var(--red)'}`;el.textContent=msg;document.body.appendChild(el);setTimeout(()=>el.remove(),3500);}
  function totalEarned(){return state.findings.filter(f=>f.status==='resolved').reduce((s,f)=>s+(f.bounty||0),0);}
  function monthEarned(){const m=new Date().toISOString().slice(0,7);return state.findings.filter(f=>f.status==='resolved'&&(f.date||'').startsWith(m)).reduce((s,f)=>s+(f.bounty||0),0);}
  function pendingCount(){return state.findings.filter(f=>['submitted','triaged','new'].includes(f.status)).length;}
  function resolvedCount(){return state.findings.filter(f=>f.status==='resolved').length;}

  // ─── Icons ────────────────────────────────────────────────────────────────────
  const I={
    dashboard:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`,
    findings:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>`,
    earnings:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>`,
    goal:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg>`,
    writeups:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
    workspace:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v2"/><line x1="12" y1="12" x2="12" y2="16"/><line x1="10" y1="14" x2="14" y2="14"/></svg>`,
    settings:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`,
    guide:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z"/><path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z"/></svg>`,
    logout:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>`,
    plus:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
    edit:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
    trash:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>`,
    close:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
    search:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>`,
    shield:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
    cloud:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/></svg>`,
    lock:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
    check:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
    copy:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`,
    download:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
    upload:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>`,
    user:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
    menu:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>`,
    link:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>`,
    folder:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>`,
    bug:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 9c0-1.66 1.34-3 3-3s3 1.34 3 3v5c0 1.66-1.34 3-3 3s-3-1.34-3-3V9z"/><path d="M6 13H2M22 13h-4M6 9l-2-2M18 9l2-2M6 17l-2 2M18 17l2 2"/></svg>`,
    day:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>`,
    bell:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>`,
    fire:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2c0 0-5 5-5 10a5 5 0 0010 0c0-2.5-1.5-4.5-3-6 0 2-1 3-2 4 0-3-1.5-5.5 0-8z"/></svg>`,
    clock:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
    stats:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>`,
    globe:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>`,
    image:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
  };
  const LOGO_SVG=`<svg width="34" height="34" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" rx="18" fill="#1a1f2e"/><path d="M50 8 L82 22 L82 54 C82 72 67 86 50 94 C33 86 18 72 18 54 L18 22 Z" fill="#f78166" opacity="0.95"/><text y=".68em" font-size="42" x="22" style="font-family:sans-serif">🐛</text></svg>`;

  // ─── Auth screen ─────────────────────────────────────────────────────────────
  function renderAuth(){
    document.getElementById('app-root').innerHTML=`
    <div class="auth-screen"><div class="auth-card">
      <div class="auth-logo">${LOGO_SVG}<div><div class="auth-logo-text">BugHunter Tracker</div><div class="auth-logo-sub">Create once · Login anywhere</div></div></div>
      <div class="sync-note">${I.cloud} <span><strong>Cross-device login:</strong> set your JSONBin API key in Settings after first login to unlock login from any device.</span></div>
      <div class="auth-tabs"><button class="auth-tab active" id="tab-login" onclick="App.switchAuthTab('login')">Sign in</button><button class="auth-tab" id="tab-register" onclick="App.switchAuthTab('register')">Create account</button></div>
      <div id="auth-form"></div>
      <div id="auth-status" style="font-size:12px;color:var(--text3);text-align:center;margin-top:10px;min-height:16px;font-family:var(--mono);"></div>
    </div></div>`;
    renderLoginForm();
  }
  function renderLoginForm(){
    document.getElementById('auth-form').innerHTML=`
      <div class="field-group"><label>Username or email</label><input id="au-login" placeholder="hunter or you@email.com" autocomplete="username"/></div>
      <div class="field-group"><label>Password</label><input id="au-pass" type="password" placeholder="••••••••" autocomplete="current-password"/></div>
      <div class="field-group hidden" id="tfa-row"><label>Authenticator code</label><input id="au-tfa" type="text" inputmode="numeric" placeholder="6-digit code" maxlength="6" autocomplete="one-time-code"/></div>
      <span class="auth-err" id="auth-err"></span>
      <button class="btn-primary" id="login-btn" onclick="App.doLogin()">Sign in</button>
      <p class="auth-msg">New here? <a href="#" onclick="App.switchAuthTab('register');return false;">Create account</a></p>`;
    document.getElementById('au-pass').addEventListener('keydown',e=>{if(e.key==='Enter')App.doLogin();});
    document.getElementById('au-login').focus();
  }
  function renderRegisterForm(){
    document.getElementById('auth-form').innerHTML=`
      <div class="field-group"><label>Username</label><input id="au-user" placeholder="hunter_dev" autocomplete="username"/></div>
      <div class="field-group"><label>Email</label><input id="au-email" type="email" placeholder="you@email.com" autocomplete="email"/></div>
      <div class="field-group"><label>Password</label><input id="au-pass" type="password" placeholder="Min 8 characters" autocomplete="new-password"/></div>
      <div class="field-group"><label>Confirm password</label><input id="au-pass2" type="password" placeholder="Repeat password" autocomplete="new-password"/></div>
      <span class="auth-err" id="auth-err"></span>
      <button class="btn-primary" id="reg-btn" onclick="App.doRegister()">Create account</button>
      <p class="auth-msg" style="font-size:11px;color:var(--text3);">💡 Set a JSONBin API key in Settings after signup to enable login from all devices.</p>
      <p class="auth-msg">Already have an account? <a href="#" onclick="App.switchAuthTab('login');return false;">Sign in</a></p>`;
    document.getElementById('au-user').focus();
  }
  function switchAuthTab(tab){document.getElementById('tab-login').classList.toggle('active',tab==='login');document.getElementById('tab-register').classList.toggle('active',tab==='register');tab==='login'?renderLoginForm():renderRegisterForm();}

  // ─── App shell ────────────────────────────────────────────────────────────────
  function renderApp(){
    const u=state.currentUser,initials=(state.settings.displayName||u.username).slice(0,2).toUpperCase();
    document.getElementById('app-root').innerHTML=`
    <div id="sidebar-overlay" class="sidebar-overlay" onclick="App.closeSidebar()"></div>
    <div class="app">
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-logo">${LOGO_SVG}<div><div class="sidebar-logo-text">BugHunter</div><div class="sidebar-logo-sub">Bug Bounty Tracker</div></div></div>
        <div class="sidebar-user">
          <div class="user-avatar">${initials}</div>
          <div style="flex:1;min-width:0;"><div class="user-name">${esc(state.settings.displayName||u.username)}</div><div class="user-handle">${esc(u.email)}</div></div>
          ${state.settings.twoFAEnabled?'<span class="user-2fa-badge">2FA</span>':''}
        </div>
        <nav class="sidebar-nav">
          <div class="nav-section-label">Overview</div>
          <button class="nav-item active" id="nav-dashboard" onclick="App.nav('dashboard')">${I.dashboard} Dashboard</button>
          <button class="nav-item" id="nav-streak" onclick="App.nav('streak')">${I.fire} Streak <span class="nav-badge" id="nb-streak">${state.streak?.current||0}🔥</span></button>
          <div class="nav-section-label">Hunting</div>
          <button class="nav-item" id="nav-findings" onclick="App.nav('findings')">${I.findings} Findings <span class="nav-badge" id="nb-all">0</span></button>
          <button class="nav-item" id="nav-pending" onclick="App.nav('pending')">${I.findings} Pending <span class="nav-badge" id="nb-pending">0</span></button>
          <button class="nav-item" id="nav-resolved" onclick="App.nav('resolved')">${I.findings} Resolved <span class="nav-badge" id="nb-resolved">0</span></button>
          <button class="nav-item" id="nav-programs" onclick="App.nav('programs')">${I.globe} Program directory</button>
          <div class="nav-section-label">Money</div>
          <button class="nav-item" id="nav-earnings" onclick="App.nav('earnings')">${I.earnings} Earnings</button>
          <button class="nav-item" id="nav-goal" onclick="App.nav('goal')">${I.goal} Monthly goal</button>
          <button class="nav-item" id="nav-progstats" onclick="App.nav('progstats')">${I.stats} Program stats</button>
          <div class="nav-section-label">Workspace</div>
          <button class="nav-item" id="nav-workspaces" onclick="App.nav('workspaces')">${I.workspace} Workspaces <span class="nav-badge" id="nb-ws">0</span></button>
          <button class="nav-item" id="nav-recon" onclick="App.nav('recon')">${I.search} Recon notes <span class="nav-badge" id="nb-recon">0</span></button>
          <button class="nav-item" id="nav-time" onclick="App.nav('time')">${I.clock} Time tracker</button>
          <div class="nav-section-label">Knowledge</div>
          <button class="nav-item" id="nav-writeups" onclick="App.nav('writeups')">${I.writeups} Blogs & Writeups <span class="nav-badge" id="nb-writeups">0</span></button>
          <button class="nav-item" id="nav-reminders" onclick="App.nav('reminders')">${I.bell} Reminders <span class="nav-badge" id="nb-remind"></span></button>
          <button class="nav-item" id="nav-guide" onclick="App.nav('guide')">${I.guide} Priority & CVE guide</button>
          <div class="nav-section-label">Account</div>
          <button class="nav-item" id="nav-settings" onclick="App.nav('settings')">${I.settings} Settings</button>
        </nav>
        <div class="sidebar-footer">
          <div style="padding:4px 8px 8px;display:flex;align-items:center;gap:6px;"><span class="sync-dot" id="sync-dot"></span><span style="font-size:11px;color:var(--text3);font-family:var(--mono);" id="sync-label">—</span></div>
          <button class="nav-item" onclick="App.doLogout()">${I.logout} Sign out</button>
        </div>
      </aside>
      <div class="main">
        <div class="topbar">
          <div style="display:flex;align-items:center;gap:12px;">
            <button class="icon-btn" id="menu-btn" onclick="App.toggleMenu()" style="display:none">${I.menu}</button>
            <span class="topbar-title" id="topbar-title">Dashboard</span>
          </div>
          <div class="topbar-actions" id="topbar-actions">
            <button class="btn" id="theme-btn" onclick="App.toggleTheme()" style="font-size:12px;">${state.settings.theme==='dark'?'☀️ Light':'🌙 Dark'}</button>
            <button class="btn accent" onclick="App.openFindingModal()">${I.plus} Add finding</button>
          </div>
        </div>
        <div class="page-content">
          <div id="panel-dashboard"  class="panel active"></div>
          <div id="panel-streak"     class="panel"></div>
          <div id="panel-findings"   class="panel"></div>
          <div id="panel-pending"    class="panel"></div>
          <div id="panel-resolved"   class="panel"></div>
          <div id="panel-programs"   class="panel"></div>
          <div id="panel-earnings"   class="panel"></div>
          <div id="panel-goal"       class="panel"></div>
          <div id="panel-progstats"  class="panel"></div>
          <div id="panel-workspaces" class="panel"></div>
          <div id="panel-recon"      class="panel"></div>
          <div id="panel-time"       class="panel"></div>
          <div id="panel-writeups"   class="panel"></div>
          <div id="panel-reminders"  class="panel"></div>
          <div id="panel-guide"      class="panel"></div>
          <div id="panel-settings"   class="panel"></div>
        </div>
      </div>
    </div>
    <div id="modal-overlay" class="modal-overlay hidden" onclick="App._modalBg(event)"></div>
    <div id="detail-overlay" class="modal-overlay hidden" onclick="App._detailBg(event)"></div>`;
    if(window.innerWidth<=768)document.getElementById('menu-btn').style.display='flex';
    updateBadges();renderPanel('dashboard');_updateSyncUI();
  }

  function toggleMenu(){document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('visible');}
  function closeSidebar(){document.getElementById('sidebar').classList.remove('open');document.getElementById('sidebar-overlay').classList.remove('visible');}

  const PANEL_TITLES={dashboard:'Dashboard',streak:'Streak tracker',findings:'All findings',pending:'Pending findings',resolved:'Resolved findings',programs:'Program directory',earnings:'Earnings',goal:'Monthly goal',progstats:'Program stats',workspaces:'Workspaces',recon:'Recon notes',time:'Time tracker',writeups:'Blogs & Writeups',reminders:'Reminders',guide:'Priority & CVE guide',settings:'Settings'};

  function nav(panel){
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
    document.getElementById('nav-'+panel)?.classList.add('active');
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    document.getElementById('panel-'+panel)?.classList.add('active');
    state.activePanel=panel;
    document.getElementById('topbar-title').textContent=PANEL_TITLES[panel]||'';
    const ta=document.getElementById('topbar-actions');
    if(ta){
      const tb=`<button class="btn" id="theme-btn" onclick="App.toggleTheme()" style="font-size:12px;">${state.settings.theme==='dark'?'☀️ Light':'🌙 Dark'}</button>`;
      if(panel==='workspaces')ta.innerHTML=tb+`<button class="btn accent" onclick="App.openWorkspaceModal()">${I.plus} New workspace</button>`;
      else if(panel==='writeups')ta.innerHTML=tb+`<button class="btn accent" onclick="App.openWriteupModal()">${I.plus} New writeup</button>`;
      else if(panel==='recon')ta.innerHTML=tb+`<button class="btn accent" onclick="App.openReconModal()">${I.plus} New note</button>`;
      else if(panel==='reminders')ta.innerHTML=tb+`<button class="btn accent" onclick="App.openReminderModal()">${I.plus} Add reminder</button>`;
      else if(['settings','guide','progstats','streak','time','programs','earnings','goal'].includes(panel))ta.innerHTML=tb;
      else ta.innerHTML=tb+`<button class="btn accent" onclick="App.openFindingModal()">${I.plus} Add finding</button>`;
    }
    renderPanel(panel);closeSidebar();
  }

  function updateBadges(){
    const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
    set('nb-all',state.findings.length);set('nb-pending',pendingCount());set('nb-resolved',resolvedCount());
    set('nb-ws',state.workspaces.length);set('nb-recon',(state.reconNotes||[]).length);
    set('nb-writeups',state.writeups.length);set('nb-streak',(state.streak?.current||0)+'🔥');
    const ar=(state.reminders||[]).filter(r=>!r.fired).length;set('nb-remind',ar||'');
  }

  function renderPanel(name){
    const map={dashboard:renderDashboard,streak:renderStreak,
      findings:()=>renderFindingsPanel('findings','all'),pending:()=>renderFindingsPanel('pending','pending'),resolved:()=>renderFindingsPanel('resolved','resolved'),
      programs:renderProgramDirectory,earnings:renderEarnings,goal:renderGoal,
      progstats:renderProgramStats,workspaces:renderWorkspaces,recon:renderReconNotes,
      time:renderTimeTracker,writeups:renderWriteups,reminders:renderReminders,
      guide:renderGuide,settings:renderSettings};
    map[name]?.();
  }

  // ─── Dashboard ────────────────────────────────────────────────────────────────
  function renderDashboard(){
    const el=document.getElementById('panel-dashboard'),me=monthEarned(),te=totalEarned(),pct=Math.min(100,(me/state.monthlyGoal*100)).toFixed(0),s=state.streak||{};
    el.innerHTML=`
    <div class="metrics-grid">
      <div class="metric-card"><div class="metric-label">Total findings</div><div class="metric-value">${state.findings.length}</div><div class="metric-sub">${resolvedCount()} resolved</div></div>
      <div class="metric-card"><div class="metric-label">Total earned</div><div class="metric-value text-green">${fmtMoney(te)}</div><div class="metric-sub">All time</div></div>
      <div class="metric-card"><div class="metric-label">Pending</div><div class="metric-value" style="color:var(--yellow)">${pendingCount()}</div><div class="metric-sub">Awaiting response</div></div>
      <div class="metric-card"><div class="metric-label">This month</div><div class="metric-value text-green">${fmtMoney(me)}</div><div class="metric-sub">${pct}% of goal</div></div>
      <div class="metric-card"><div class="metric-label">🔥 Streak</div><div class="metric-value" style="color:var(--orange)">${s.current||0}<span style="font-size:14px;"> days</span></div><div class="metric-sub">Best: ${s.longest||0} days</div></div>
      <div class="metric-card"><div class="metric-label">Workspaces</div><div class="metric-value" style="color:var(--blue)">${state.workspaces.length}</div><div class="metric-sub">${(state.reconNotes||[]).length} recon notes</div></div>
    </div>
    <div class="goal-bar-bg" style="margin-bottom:24px;"><div class="goal-bar-fill" style="width:${pct}%"></div></div>
    <div class="charts-grid">
      <div class="card"><div class="card-header"><span class="card-header-title">By priority</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="chart-prio"></canvas></div></div></div>
      <div class="card"><div class="card-header"><span class="card-header-title">By status</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="chart-stat"></canvas></div></div></div>
    </div>
    <div class="card"><div class="card-header"><span class="card-header-title">Recent findings</span><button class="btn" onclick="App.nav('findings')" style="font-size:12px;padding:4px 10px;">View all</button></div><div class="table-wrap">${findingsTable(state.findings.slice(0,5),true)}</div></div>`;
    setTimeout(()=>{
      if(typeof Chart==='undefined')return;
      const pc=['p1','p2','p3','p4','p5','na'].map(p=>state.findings.filter(f=>f.priority===p).length),pcols=['#f85149','#f0883e','#d29922','#58a6ff','#8b949e','#6e7681'];
      const cprio=document.getElementById('chart-prio');if(cprio){if(state.charts.prio)state.charts.prio.destroy();state.charts.prio=new Chart(cprio,{type:'doughnut',data:{labels:['P1','P2','P3','P4','P5','N/A'],datasets:[{data:pc,backgroundColor:pcols,borderWidth:0,borderRadius:2}]},options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11},padding:10,boxWidth:10}}}}});}
      const sc=Object.keys(STATUSES).map(s=>state.findings.filter(f=>f.status===s).length),scols=['#bc8cff','#58a6ff','#d29922','#3fb950','#6e7681','#f85149'];
      const cstat=document.getElementById('chart-stat');if(cstat){if(state.charts.stat)state.charts.stat.destroy();state.charts.stat=new Chart(cstat,{type:'bar',data:{labels:Object.values(STATUSES).map(s=>s.label),datasets:[{data:sc,backgroundColor:scols,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#656d76',font:{size:11}},grid:{color:'#21262d'}},y:{ticks:{color:'#656d76',font:{size:11},stepSize:1},grid:{color:'#21262d'}}}}});}
    },50);
  }

  // ─── Streak ───────────────────────────────────────────────────────────────────
  function renderStreak(){
    const el=document.getElementById('panel-streak'),s=state.streak||{},history=s.history||[],today=new Date().toISOString().split('T')[0];
    const days=[];for(let i=29;i>=0;i--){const d=new Date(Date.now()-i*86400000).toISOString().split('T')[0];days.push({date:d,active:history.includes(d)});}
    el.innerHTML=`
    <div class="metrics-grid" style="margin-bottom:24px;">
      <div class="metric-card"><div class="metric-label">🔥 Current streak</div><div class="metric-value" style="color:var(--orange)">${s.current||0}<span style="font-size:16px;"> days</span></div></div>
      <div class="metric-card"><div class="metric-label">🏆 Longest streak</div><div class="metric-value" style="color:var(--yellow)">${s.longest||0}<span style="font-size:16px;"> days</span></div></div>
      <div class="metric-card"><div class="metric-label">📅 Last active</div><div class="metric-value" style="font-size:16px;">${s.lastActive?fmtDate(s.lastActive):'Never'}</div></div>
      <div class="metric-card"><div class="metric-label">📊 Total days</div><div class="metric-value">${history.length}</div></div>
    </div>
    <div class="card"><div class="card-header"><span class="card-header-title">Activity — last 30 days</span></div>
      <div style="padding:20px;"><div style="display:flex;gap:4px;flex-wrap:wrap;">${days.map(d=>`<div title="${d.date}" style="width:28px;height:28px;border-radius:5px;background:${d.active?'var(--green)':'var(--bg3)'};border:1px solid ${d.active?'rgba(63,185,80,0.4)':'var(--border)'};display:flex;align-items:center;justify-content:center;font-size:10px;color:${d.active?'#fff':'var(--text3)'};">${d.date===today?'●':''}</div>`).join('')}</div>
      <div style="display:flex;gap:16px;margin-top:12px;font-size:12px;color:var(--text3);"><span style="color:var(--green);">■ Active</span><span>■ Inactive</span><span style="margin-left:auto;">● Today</span></div></div>
    </div>`;
  }

  // ─── Findings ─────────────────────────────────────────────────────────────────
  function renderFindingsPanel(panelId,mode){
    const el=document.getElementById('panel-'+panelId);
    el.innerHTML=`<div class="filter-bar" id="fb-${panelId}">${mode==='all'?`<button class="filter-chip active" onclick="App.setPrio('all',this,'${panelId}')">All</button>${Object.entries(PRIOS).map(([k,v])=>`<button class="filter-chip" onclick="App.setPrio('${k}',this,'${panelId}')">${v.short}</button>`).join('')}<div class="filter-sep"></div>`:''}<div class="search-wrap" style="margin-left:auto;"><span class="search-icon">${I.search}</span><input placeholder="Search…" oninput="App.setSearch(this.value,'${panelId}')"/></div></div>
    <div class="card"><div class="table-wrap" id="ft-${panelId}">${buildFindingsTable(panelId,mode)}</div></div>`;
  }
  function buildFindingsTable(panelId,mode){let list=[...state.findings];if(mode==='pending')list=list.filter(f=>['submitted','triaged','new'].includes(f.status));if(mode==='resolved')list=list.filter(f=>f.status==='resolved');if(state.filterPriority!=='all')list=list.filter(f=>f.priority===state.filterPriority);if(state.searchQuery){const q=state.searchQuery.toLowerCase();list=list.filter(f=>(f.title||'').toLowerCase().includes(q)||(f.program||'').toLowerCase().includes(q));}return findingsTable(list,false);}
  function findingsTable(list,compact){
    if(!list.length)return`<div class="empty-state">${I.bug}<p>No findings${compact?' yet':' match filters'}.</p><p class="empty-hint">${compact?'Click "Add finding" to log your first bug.':'Try adjusting filters.'}</p></div>`;
    return`<table><thead><tr><th>Title</th><th>Priority</th><th>Status</th><th>Platform</th>${!compact?'<th>Date</th>':''}<th>Bounty</th><th></th></tr></thead><tbody>${list.map(f=>`<tr onclick="App.openDetail('${f.id}')"><td><div class="td-title">${esc(f.title)}</div><div class="td-title-sub">${esc(f.program||'—')}</div></td><td>${pbadge(f.priority)}</td><td>${sbadge(f.status)}</td><td class="td-mono">${esc(f.platform||'—')}</td>${!compact?`<td class="td-mono">${fmtDate(f.date)}</td>`:''}<td class="${f.bounty>0?'bounty-val':'td-mono'}">${f.bounty>0?fmtMoney(f.bounty):'—'}</td><td onclick="event.stopPropagation()"><div style="display:flex;gap:4px;"><button class="icon-btn" onclick="App.generateReport('${f.id}')" title="Report">📋</button><button class="icon-btn" onclick="App.openFindingModal('${f.id}')">${I.edit}</button><button class="icon-btn" onclick="App.deleteFinding('${f.id}')">${I.trash}</button></div></td></tr>`).join('')}</tbody></table>`;
  }
  function setPrio(val,btn,panelId){state.filterPriority=val;document.getElementById('fb-'+panelId)?.querySelectorAll('.filter-chip').forEach(b=>b.classList.remove('active'));btn?.classList.add('active');const el=document.getElementById('ft-'+panelId);if(el)el.innerHTML=buildFindingsTable(panelId,panelId==='findings'?'all':panelId);}
  function setSearch(val,panelId){state.searchQuery=val;const el=document.getElementById('ft-'+panelId);if(el)el.innerHTML=buildFindingsTable(panelId,panelId==='findings'?'all':panelId);}

  // ─── Finding modal ────────────────────────────────────────────────────────────
  function openFindingModal(id){
    state.editId=id||null;const f=id?state.findings.find(x=>x.id===id):null,v=(k,d='')=>f?(f[k]!=null?f[k]:d):d,today=new Date().toISOString().split('T')[0];
    showModal(`<div class="modal-header"><h3>${id?'Edit finding':'Add finding'}</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div>
    <div class="modal-body">
      <div class="form-field form-field-full"><label>Title *</label><input id="mf-title" value="${esc(v('title'))}" placeholder="e.g. SQL injection on /api/login" oninput="App._dupCheck(this.value)"/><div id="dup-warn" style="display:none;margin-top:6px;background:var(--yellow-bg);border:1px solid rgba(210,153,34,.3);border-radius:6px;padding:8px 10px;font-size:12px;color:var(--yellow);"></div></div>
      <div class="form-row" style="margin-top:14px;"><div class="form-field"><label>Program *</label><input id="mf-program" value="${esc(v('program'))}" placeholder="Acme Corp"/></div><div class="form-field"><label>Platform</label><select id="mf-platform"><option value="">Select…</option>${PLATFORMS.map(p=>`<option value="${p}" ${v('platform')===p?'selected':''}>${p}</option>`).join('')}</select></div></div>
      <div class="form-row-3"><div class="form-field"><label>Priority</label><select id="mf-priority">${Object.entries(PRIOS).map(([k,m])=>`<option value="${k}" ${v('priority','p3')===k?'selected':''}>${m.label}</option>`).join('')}</select></div><div class="form-field"><label>Status</label><select id="mf-status">${Object.entries(STATUSES).map(([k,m])=>`<option value="${k}" ${v('status','new')===k?'selected':''}>${m.label}</option>`).join('')}</select></div><div class="form-field"><label>Bounty ($)</label><input id="mf-bounty" type="number" min="0" value="${v('bounty',0)}"/></div></div>
      <div class="form-row"><div class="form-field"><label>Vuln type</label><select id="mf-vulntype"><option value="">Select…</option>${VULN_TYPES.map(t=>`<option value="${t}" ${v('vulnType')===t?'selected':''}>${t}</option>`).join('')}</select></div><div class="form-field"><label>Date found</label><input id="mf-date" type="date" value="${v('date',today)}"/></div></div>
      <div class="form-field form-field-full"><label>URL / Endpoint</label><input id="mf-url" value="${esc(v('url'))}" placeholder="https://target.com/api/…"/></div>
      <div class="form-field form-field-full"><label>Screenshot (paste Ctrl+V, drag, or click)</label><div id="screenshot-zone" class="screenshot-zone" ondragover="event.preventDefault()" ondrop="App._handleImgDrop(event)" onclick="document.getElementById('sc-file').click()">${v('screenshot')?`<img src="${v('screenshot')}" style="max-width:100%;max-height:180px;border-radius:6px;"/>`:`${I.image}<span style="font-size:13px;color:var(--text3);margin-top:6px;display:block;">Click, paste or drag image</span>`}</div><input type="file" id="sc-file" accept="image/*" style="display:none" onchange="App._handleImgFile(this)"/><input type="hidden" id="mf-screenshot" value="${esc(v('screenshot'))}"/></div>
      <div class="form-field form-field-full"><label>Description / Steps</label><textarea id="mf-desc" style="min-height:90px;">${esc(v('desc'))}</textarea></div>
      <div class="form-field form-field-full"><label>Fix / Recommendation</label><textarea id="mf-fix" style="min-height:55px;">${esc(v('fix'))}</textarea></div>
    </div>
    <div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveFinding()">${id?'Update':'Save finding'}</button></div>`);
    setTimeout(()=>document.getElementById('mf-title')?.focus(),50);
    document.addEventListener('paste',_handlePaste,{once:true});
  }
  function _dupCheck(title){const dupes=checkDuplicate(title),el=document.getElementById('dup-warn');if(!el)return;if(dupes.length){el.style.display='block';el.innerHTML=`⚠️ Possible duplicate: ${dupes.map(f=>`<strong>${esc(f.title)}</strong>`).join(', ')}`;}else el.style.display='none';}
  function _handlePaste(e){const items=e.clipboardData?.items||[];for(const item of items){if(item.type.startsWith('image/')){_loadImageFile(item.getAsFile());break;}}}
  function _handleImgDrop(e){e.preventDefault();const file=e.dataTransfer?.files?.[0];if(file&&file.type.startsWith('image/'))_loadImageFile(file);}
  function _handleImgFile(input){const file=input.files?.[0];if(file)_loadImageFile(file);}
  function _loadImageFile(file){const r=new FileReader();r.onload=e=>{const d=e.target.result;const hi=document.getElementById('mf-screenshot');if(hi)hi.value=d;const z=document.getElementById('screenshot-zone');if(z)z.innerHTML=`<img src="${d}" style="max-width:100%;max-height:180px;border-radius:6px;"/><button class="btn" style="margin-top:6px;font-size:11px;" onclick="App._clearImg(event)">Remove</button>`;};r.readAsDataURL(file);}
  function _clearImg(e){e.stopPropagation();const hi=document.getElementById('mf-screenshot');if(hi)hi.value='';const z=document.getElementById('screenshot-zone');if(z)z.innerHTML=`${I.image}<span style="font-size:13px;color:var(--text3);margin-top:6px;display:block;">Click, paste or drag</span>`;}

  async function saveFinding(){
    const title=document.getElementById('mf-title').value.trim(),program=document.getElementById('mf-program').value.trim();
    if(!title||!program){toast('Title and program required.','err');return;}
    updateStreak();
    const f={id:state.editId||genId(),title,program,platform:document.getElementById('mf-platform').value,priority:document.getElementById('mf-priority').value,status:document.getElementById('mf-status').value,vulnType:document.getElementById('mf-vulntype').value,bounty:parseFloat(document.getElementById('mf-bounty').value)||0,url:document.getElementById('mf-url').value.trim(),date:document.getElementById('mf-date').value,desc:document.getElementById('mf-desc').value.trim(),fix:document.getElementById('mf-fix').value.trim(),screenshot:document.getElementById('mf-screenshot').value||null,updated:new Date().toISOString()};
    if(state.editId){const idx=state.findings.findIndex(x=>x.id===state.editId);f.created=state.findings[idx]?.created||f.updated;state.findings[idx]=f;toast('Finding updated!');}
    else{f.created=new Date().toISOString();state.findings.unshift(f);toast('Finding saved!');}
    closeModal();updateBadges();await safeSyncToCloud();renderPanel(state.activePanel);
  }
  async function deleteFinding(id){if(!confirm('Delete this finding?'))return;state.findings=state.findings.filter(x=>x.id!==id);await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);toast('Deleted.');}

  function openDetail(id){
    const f=state.findings.find(x=>x.id===id);if(!f)return;
    showDetail(`<div class="modal-header"><h3 style="max-width:450px;">${esc(f.title)}</h3><button class="icon-btn" onclick="App.closeDetail()">${I.close}</button></div>
    <div class="modal-body"><div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">${pbadge(f.priority)} ${sbadge(f.status)}${f.vulnType?`<span class="badge p4">${esc(f.vulnType)}</span>`:''}${f.bounty>0?`<span style="font-family:var(--mono);font-size:12px;color:var(--green);padding:2px 8px;background:var(--green-bg);border-radius:4px;border:1px solid rgba(63,185,80,.2)">${fmtMoney(f.bounty)}</span>`:''}<button class="btn" style="font-size:12px;padding:3px 10px;margin-left:auto;" onclick="App.generateReport('${f.id}')">📋 Generate report</button></div>
    ${f.screenshot?`<div style="margin-bottom:16px;"><img src="${f.screenshot}" style="max-width:100%;max-height:260px;border-radius:8px;border:1px solid var(--border);object-fit:contain;"/></div>`:''}
    <div class="detail-section"><div class="detail-section-title">Details</div><div class="detail-row"><span class="detail-key">Program</span><span class="detail-val">${esc(f.program||'—')}</span></div><div class="detail-row"><span class="detail-key">Platform</span><span class="detail-val">${esc(f.platform||'—')}</span></div><div class="detail-row"><span class="detail-key">URL</span><span class="detail-val text-mono">${f.url?`<a href="${esc(f.url)}" target="_blank">${esc(f.url)}</a>`:'—'}</span></div><div class="detail-row"><span class="detail-key">Date</span><span class="detail-val">${fmtDate(f.date)}</span></div></div>
    ${f.desc?`<div class="detail-section"><div class="detail-section-title">Description</div><div class="detail-desc">${esc(f.desc)}</div></div>`:''}${f.fix?`<div class="detail-section"><div class="detail-section-title">Fix</div><div class="detail-desc">${esc(f.fix)}</div></div>`:''}
    </div><div class="modal-footer"><button class="btn" onclick="App.closeDetail()">Close</button><button class="btn accent" onclick="App.closeDetail();App.openFindingModal('${f.id}')">Edit</button></div>`);
  }

  // ─── Earnings & Goal ──────────────────────────────────────────────────────────
  function renderEarnings(){
    const el=document.getElementById('panel-earnings'),resolved=state.findings.filter(f=>f.status==='resolved');
    const byPrio=['p1','p2','p3','p4','p5'].map(p=>resolved.filter(f=>f.priority===p).reduce((s,f)=>s+(f.bounty||0),0));
    const byMonth={};resolved.forEach(f=>{const m=(f.date||'').slice(0,7);if(m)byMonth[m]=(byMonth[m]||0)+(f.bounty||0);});
    const months=Object.keys(byMonth).sort(),mvals=months.map(m=>byMonth[m]);
    el.innerHTML=`<div class="metrics-grid" style="margin-bottom:24px;"><div class="metric-card"><div class="metric-label">Total earned</div><div class="metric-value text-green">${fmtMoney(totalEarned())}</div></div><div class="metric-card"><div class="metric-label">This month</div><div class="metric-value text-green">${fmtMoney(monthEarned())}</div></div><div class="metric-card"><div class="metric-label">Resolved bugs</div><div class="metric-value">${resolvedCount()}</div></div><div class="metric-card"><div class="metric-label">Avg per bug</div><div class="metric-value text-green">${resolvedCount()?fmtMoney(Math.round(totalEarned()/resolvedCount())):'$0'}</div></div></div>
    <div class="charts-grid"><div class="card"><div class="card-header"><span class="card-header-title">By priority</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="ce-prio"></canvas></div></div></div><div class="card"><div class="card-header"><span class="card-header-title">Monthly</span></div><div style="padding:16px;"><div class="chart-container"><canvas id="ce-month"></canvas></div></div></div></div>
    <div class="card"><div class="card-header"><span class="card-header-title">Resolved findings</span></div><div class="table-wrap">${findingsTable(resolved,false)}</div></div>`;
    setTimeout(()=>{if(typeof Chart==='undefined')return;const e1=document.getElementById('ce-prio');if(e1)new Chart(e1,{type:'bar',data:{labels:['P1','P2','P3','P4','P5'],datasets:[{data:byPrio,backgroundColor:['#f85149','#f0883e','#d29922','#58a6ff','#8b949e'],borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#656d76'}},y:{ticks:{color:'#656d76',callback:v=>'$'+v}}}}});const e2=document.getElementById('ce-month');if(e2)new Chart(e2,{type:'line',data:{labels:months.length?months:['—'],datasets:[{data:mvals.length?mvals:[0],borderColor:'#3fb950',backgroundColor:'rgba(63,185,80,.08)',fill:true,tension:0.3,pointRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#656d76'}},y:{ticks:{color:'#656d76',callback:v=>'$'+v},beginAtZero:true}}}});},50);
  }
  function renderGoal(){
    const el=document.getElementById('panel-goal'),me=monthEarned(),pct=Math.min(100,(me/state.monthlyGoal*100)),mStr=new Date().toISOString().slice(0,7),mF=state.findings.filter(f=>f.status==='resolved'&&(f.date||'').startsWith(mStr));
    el.innerHTML=`<div class="card" style="margin-bottom:20px;"><div class="card-header"><span class="card-header-title">Monthly earning goal</span></div><div style="padding:20px;"><div style="display:flex;gap:12px;align-items:flex-end;margin-bottom:16px;"><div class="form-field" style="flex:1;"><label>Goal ($)</label><input id="goal-inp" type="number" value="${state.monthlyGoal}"/></div><button class="btn accent" onclick="App.saveGoal()">Update</button></div><div style="display:flex;justify-content:space-between;font-size:13px;color:var(--text2);margin-bottom:6px;"><span>Progress — <strong style="color:var(--text)">${pct.toFixed(0)}%</strong></span><span>${fmtMoney(me)} / ${fmtMoney(state.monthlyGoal)}</span></div><div class="goal-bar-bg"><div class="goal-bar-fill" style="width:${pct}%"></div></div><div class="goal-labels"><span>${fmtMoney(me)} earned</span><span>Goal: ${fmtMoney(state.monthlyGoal)}</span></div>${me>=state.monthlyGoal?'<div style="margin-top:12px;color:var(--green);font-weight:600;">🎉 Goal reached!</div>':`<div style="margin-top:8px;font-size:12px;color:var(--text3);">${fmtMoney(state.monthlyGoal-me)} more to go</div>`}</div></div>
    <div class="card"><div class="card-header"><span class="card-header-title">This month resolved</span></div><div class="table-wrap">${findingsTable(mF,false)}</div></div>`;
  }
  async function saveGoal(){const v=parseFloat(document.getElementById('goal-inp').value);if(!v||v<0){toast('Invalid','err');return;}state.monthlyGoal=v;renderGoal();await safeSyncToCloud();toast('Goal updated!');}

  // ─── Workspaces ───────────────────────────────────────────────────────────────
  function renderWorkspaces(){
    const el=document.getElementById('panel-workspaces');
    if(!state.workspaces.length){el.innerHTML=`<div style="text-align:center;padding:4rem 2rem;">${I.workspace}<div style="color:var(--text3);font-size:14px;margin-top:16px;margin-bottom:4px;">No workspaces yet.</div><button class="btn accent" style="margin-top:12px;" onclick="App.openWorkspaceModal()">${I.plus} New workspace</button></div>`;return;}
    if(state.activeWorkspace){renderWorkspaceDetail(state.activeWorkspace);return;}
    el.innerHTML=`<div class="section-header"><span class="section-title">All workspaces</span><button class="btn accent" onclick="App.openWorkspaceModal()">${I.plus} New workspace</button></div>
    <div class="writeup-grid">${state.workspaces.map(ws=>`<div class="writeup-card" onclick="App.openWorkspace('${ws.id}')"><div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;"><div style="width:36px;height:36px;border-radius:8px;background:${ws.color||'#f78166'};display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">${ws.emoji||'📁'}</div><div><div class="writeup-card-title" style="margin-bottom:2px;">${esc(ws.name)}</div><div style="font-size:11px;color:var(--text3);font-family:var(--mono);">${(ws.entries||[]).length} entries · ${fmtDate(ws.created)}</div></div></div>${ws.description?`<div style="font-size:13px;color:var(--text2);margin-bottom:10px;">${esc(ws.description)}</div>`:''}<div style="display:flex;gap:6px;" onclick="event.stopPropagation()"><button class="btn" style="font-size:12px;padding:4px 10px;" onclick="App.openWorkspace('${ws.id}')">${I.folder} Open</button><button class="btn" style="font-size:12px;padding:4px 10px;" onclick="App.openWorkspaceModal('${ws.id}')">${I.edit}</button><button class="btn" style="font-size:12px;padding:4px 10px;" onclick="App.deleteWorkspace('${ws.id}')">${I.trash}</button></div></div>`).join('')}</div>`;
  }
  function openWorkspace(id){state.activeWorkspace=id;renderWorkspaceDetail(id);}
  function closeWorkspace(){state.activeWorkspace=null;renderWorkspaces();}
  function renderWorkspaceDetail(wsId){
    const el=document.getElementById('panel-workspaces'),ws=state.workspaces.find(w=>w.id===wsId);
    if(!ws){state.activeWorkspace=null;renderWorkspaces();return;}
    const entries=[...(ws.entries||[])].sort((a,b)=>new Date(b.date||b.created)-new Date(a.date||a.created));
    el.innerHTML=`<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;"><button class="btn" onclick="App.closeWorkspace()">← Back</button><div style="display:flex;align-items:center;gap:10px;flex:1;"><div style="width:40px;height:40px;border-radius:10px;background:${ws.color||'#f78166'};display:flex;align-items:center;justify-content:center;font-size:22px;">${ws.emoji||'📁'}</div><div><div style="font-size:17px;font-weight:700;">${esc(ws.name)}</div>${ws.description?`<div style="font-size:12px;color:var(--text3);">${esc(ws.description)}</div>`:''}</div></div><button class="btn accent" onclick="App.openEntryModal('${ws.id}')">${I.plus} New entry</button><button class="btn" onclick="App.openWorkspaceModal('${ws.id}')">${I.edit}</button></div>
    ${!entries.length?`<div class="empty-state">${I.day}<p>No entries yet.</p><p class="empty-hint">Log your daily sessions, PoC commands and notes.</p></div>`:''}
    <div style="display:flex;flex-direction:column;gap:14px;">${entries.map(e=>{const linked=(e.linkedFindingIds||[]).map(fid=>state.findings.find(f=>f.id===fid)).filter(Boolean);return`<div class="ws-entry-card"><div class="ws-entry-header"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;"><div class="ws-entry-date">${fmtDate(e.date||e.created)}</div><div class="ws-entry-title">${esc(e.title)}</div></div><div style="display:flex;gap:4px;"><button class="icon-btn" onclick="App.openEntryModal('${ws.id}','${e.id}')">${I.edit}</button><button class="icon-btn" onclick="App.deleteEntry('${ws.id}','${e.id}')">${I.trash}</button></div></div>${e.body?`<div class="ws-entry-body">${esc(e.body)}</div>`:''} ${e.poc?`<div class="ws-entry-poc"><div class="ws-poc-label">PoC / Steps</div><div class="ws-poc-content">${esc(e.poc)}</div></div>`:''}${e.screenshot?`<div style="padding:0 16px 14px;"><img src="${e.screenshot}" style="max-width:100%;max-height:200px;border-radius:6px;border:1px solid var(--border);object-fit:contain;"/></div>`:''}${e.url?`<div style="margin:0 16px 10px;"><a href="${esc(e.url)}" target="_blank" class="btn" style="font-size:12px;padding:3px 10px;display:inline-flex;align-items:center;gap:4px;">${I.link} ${esc(e.url.slice(0,50))}</a></div>`:''}${(e.tags||[]).length?`<div class="writeup-tags" style="margin:0 16px 12px;">${e.tags.map(t=>`<span class="writeup-tag">${esc(t)}</span>`).join('')}</div>`:''}${linked.length?`<div style="margin:0 16px 14px;display:flex;gap:6px;flex-wrap:wrap;align-items:center;"><span style="font-size:11px;color:var(--text3);">Linked:</span>${linked.map(f=>`<span class="badge ${(PRIOS[f.priority]||PRIOS.na).cls}" style="cursor:pointer;" onclick="App.openDetail('${f.id}')">${esc(f.title.slice(0,28))}</span>`).join('')}</div>`:''}</div>`;}).join('')}</div>`;
  }
  function openWorkspaceModal(id){
    const ws=id?state.workspaces.find(w=>w.id===id):null,v=(k,d='')=>ws?(ws[k]!=null?ws[k]:d):d;
    showModal(`<div class="modal-header"><h3>${id?'Edit workspace':'New workspace'}</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div><div class="modal-body"><div class="form-row"><div class="form-field"><label>Name *</label><input id="wsi-name" value="${esc(v('name'))}" placeholder="HackerOne — Acme Corp"/></div><div class="form-field"><label>Emoji</label><input id="wsi-emoji" value="${esc(v('emoji','📁'))}" maxlength="2" style="font-size:20px;"/></div></div><div class="form-field form-field-full"><label>Description</label><input id="wsi-desc" value="${esc(v('description'))}" placeholder="What is this workspace for?"/></div><div class="form-field form-field-full"><label>Color</label><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;" id="color-picker">${WS_COLORS.map(c=>`<div onclick="App.pickColor('${c}')" style="width:28px;height:28px;border-radius:6px;background:${c};cursor:pointer;border:2px solid ${v('color','#f78166')===c?'#fff':'transparent'};" data-color="${c}"></div>`).join('')}</div><input type="hidden" id="wsi-color" value="${v('color','#f78166')}"/></div></div><div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveWorkspace('${id||''}')">${id?'Update':'Create'}</button></div>`);
    setTimeout(()=>document.getElementById('wsi-name')?.focus(),50);
  }
  function pickColor(c){document.getElementById('wsi-color').value=c;document.querySelectorAll('#color-picker [data-color]').forEach(el=>{el.style.borderColor=el.dataset.color===c?'#fff':'transparent';});}
  async function saveWorkspace(id){
    const name=document.getElementById('wsi-name').value.trim();if(!name){toast('Name required','err');return;}
    const ws={id:id||genId(),name,emoji:document.getElementById('wsi-emoji').value.trim()||'📁',description:document.getElementById('wsi-desc').value.trim(),color:document.getElementById('wsi-color').value||'#f78166',updated:new Date().toISOString()};
    if(id){const idx=state.workspaces.findIndex(w=>w.id===id);ws.created=state.workspaces[idx].created;ws.entries=state.workspaces[idx].entries||[];state.workspaces[idx]=ws;toast('Updated!');}
    else{ws.created=new Date().toISOString();ws.entries=[];state.workspaces.push(ws);toast('Workspace created!');}
    closeModal();updateBadges();await safeSyncToCloud();renderPanel(state.activePanel);
  }
  async function deleteWorkspace(id){if(!confirm('Delete workspace and all its entries?'))return;state.workspaces=state.workspaces.filter(w=>w.id!==id);if(state.activeWorkspace===id)state.activeWorkspace=null;await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);toast('Deleted.');}
  function openEntryModal(wsId,entryId){
    const ws=state.workspaces.find(w=>w.id===wsId);if(!ws)return;
    const entry=entryId?(ws.entries||[]).find(e=>e.id===entryId):null,v=(k,d='')=>entry?(entry[k]!=null?entry[k]:d):d;
    const today=new Date().toISOString().split('T')[0],linkedIds=entry?(entry.linkedFindingIds||[]):[];
    showModal(`<div class="modal-header"><h3>${entryId?'Edit entry':'New entry'} — ${esc(ws.name)}</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div><div class="modal-body"><div class="form-row"><div class="form-field"><label>Date</label><input id="ei-date" type="date" value="${v('date',today)}"/></div><div class="form-field"><label>Title *</label><input id="ei-title" value="${esc(v('title'))}" placeholder="Day 1 — API recon"/></div></div><div class="form-field form-field-full"><label>Notes</label><textarea id="ei-body" style="min-height:100px;" placeholder="What I tested, what I found...">${esc(v('body'))}</textarea></div><div class="form-field form-field-full"><label>PoC / Commands</label><textarea id="ei-poc" class="writeup-editor" style="min-height:80px;" placeholder="curl -X POST https://target.com/api/...">${esc(v('poc'))}</textarea></div><div class="form-field form-field-full"><label>Screenshot</label><div id="ei-sc-zone" class="screenshot-zone" ondragover="event.preventDefault()" ondrop="App._handleEntryImg(event)" onclick="document.getElementById('ei-sc-file').click()">${v('screenshot')?`<img src="${v('screenshot')}" style="max-width:100%;max-height:150px;border-radius:6px;"/>`:`${I.image}<span style="font-size:12px;color:var(--text3);margin-top:4px;display:block;">Click, paste or drag</span>`}</div><input type="file" id="ei-sc-file" accept="image/*" style="display:none" onchange="App._handleEntryImgFile(this)"/><input type="hidden" id="ei-screenshot" value="${esc(v('screenshot'))}"/></div><div class="form-row"><div class="form-field"><label>Reference URL</label><input id="ei-url" value="${esc(v('url'))}" placeholder="https://…"/></div><div class="form-field"><label>Tags</label><input id="ei-tags" value="${esc(entry&&entry.tags?entry.tags.join(', '):'')}" placeholder="recon, xss"/></div></div><div class="form-field form-field-full"><label>Link findings</label><div style="max-height:140px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius);padding:8px;background:var(--bg3);margin-top:4px;">${state.findings.length?state.findings.map(f=>`<label style="display:flex;align-items:center;gap:8px;padding:5px 0;cursor:pointer;font-size:13px;"><input type="checkbox" class="entry-link-cb" value="${f.id}" ${linkedIds.includes(f.id)?'checked':''} style="accent-color:var(--accent);"/>${pbadge(f.priority)} ${esc(f.title.slice(0,38))}</label>`).join(''):'<div style="color:var(--text3);font-size:12px;">No findings yet.</div>'}</div></div></div><div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveEntry('${wsId}','${entryId||''}')">${entryId?'Update':'Save'}</button></div>`);
    setTimeout(()=>document.getElementById('ei-title')?.focus(),50);
  }
  function _handleEntryImg(e){e.preventDefault();const file=e.dataTransfer?.files?.[0];if(file&&file.type.startsWith('image/'))_loadEntryImg(file);}
  function _handleEntryImgFile(input){const file=input.files?.[0];if(file)_loadEntryImg(file);}
  function _loadEntryImg(file){const r=new FileReader();r.onload=e=>{const d=e.target.result;const hi=document.getElementById('ei-screenshot');if(hi)hi.value=d;const z=document.getElementById('ei-sc-zone');if(z)z.innerHTML=`<img src="${d}" style="max-width:100%;max-height:150px;border-radius:6px;"/>`;};r.readAsDataURL(file);}
  async function saveEntry(wsId,entryId){
    const title=document.getElementById('ei-title').value.trim();if(!title){toast('Title required','err');return;}
    const ws=state.workspaces.find(w=>w.id===wsId);if(!ws)return;updateStreak();
    const checks=[...document.querySelectorAll('.entry-link-cb:checked')].map(c=>c.value);
    const tags=document.getElementById('ei-tags').value.split(',').map(t=>t.trim()).filter(Boolean);
    const entry={id:entryId||genId(),title,date:document.getElementById('ei-date').value||new Date().toISOString().split('T')[0],body:document.getElementById('ei-body').value.trim(),poc:document.getElementById('ei-poc').value.trim(),screenshot:document.getElementById('ei-screenshot').value||null,url:document.getElementById('ei-url').value.trim(),tags,linkedFindingIds:checks,updated:new Date().toISOString()};
    if(!ws.entries)ws.entries=[];
    if(entryId){const idx=ws.entries.findIndex(e=>e.id===entryId);entry.created=ws.entries[idx]?.created||entry.updated;ws.entries[idx]=entry;toast('Entry updated!');}
    else{entry.created=new Date().toISOString();ws.entries.push(entry);toast('Entry saved!');}
    closeModal();await safeSyncToCloud();renderWorkspaceDetail(wsId);
  }
  async function deleteEntry(wsId,entryId){if(!confirm('Delete this entry?'))return;const ws=state.workspaces.find(w=>w.id===wsId);if(!ws)return;ws.entries=(ws.entries||[]).filter(e=>e.id!==entryId);await safeSyncToCloud();renderWorkspaceDetail(wsId);toast('Deleted.');}

  // ─── Reminders ────────────────────────────────────────────────────────────────
  function renderReminders(){
    const el=document.getElementById('panel-reminders'),reminders=state.reminders||[],active=reminders.filter(r=>!r.fired);
    el.innerHTML=`<div style="background:var(--blue-bg);border:1px solid rgba(88,166,255,.2);border-radius:8px;padding:12px 14px;font-size:13px;color:var(--blue);margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">${I.bell}<span>Auto-reminders fire after 7 days with no response on submitted findings.</span><button class="btn" onclick="App.requestNotificationPermission()" style="font-size:12px;padding:4px 10px;margin-left:auto;">Enable notifications</button></div>
    ${!reminders.length?`<div class="empty-state">${I.bell}<p>No reminders set.</p></div>`:`<div style="margin-bottom:20px;"><div class="section-title" style="margin-bottom:12px;">Active (${active.length})</div>${active.length?active.map(r=>`<div class="card" style="margin-bottom:10px;padding:14px 16px;display:flex;align-items:center;gap:12px;"><div style="flex:1;"><div style="font-weight:500;font-size:14px;">${esc(r.text)}</div><div style="font-size:12px;color:var(--text3);margin-top:3px;">Due: ${fmtDate(r.dueDate)}</div></div><button class="icon-btn" onclick="App.deleteReminder('${r.id}')">${I.trash}</button></div>`).join(''):'<div style="color:var(--text3);font-size:13px;padding:10px 0;">No active reminders.</div>'}</div>${reminders.filter(r=>r.fired).length?`<div><div class="section-title" style="margin-bottom:12px;">Past</div>${reminders.filter(r=>r.fired).map(r=>`<div style="padding:10px 0;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center;opacity:0.5;"><div style="flex:1;font-size:13px;text-decoration:line-through;">${esc(r.text)}</div><button class="icon-btn" onclick="App.deleteReminder('${r.id}')">${I.trash}</button></div>`).join('')}</div>`:''}`}`;
  }
  function openReminderModal(){
    const inSeven=new Date(Date.now()+7*86400000).toISOString().split('T')[0];
    showModal(`<div class="modal-header"><h3>Add reminder</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div><div class="modal-body"><div class="form-field form-field-full"><label>Reminder text *</label><input id="rm-text" placeholder="Follow up on XSS in Acme Corp"/></div><div class="form-field form-field-full"><label>Due date</label><input id="rm-date" type="date" value="${inSeven}"/></div><div class="form-field form-field-full"><label>Link to finding</label><select id="rm-finding" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:8px 11px;color:var(--text);font-size:13px;width:100%;"><option value="">No finding</option>${state.findings.filter(f=>['submitted','triaged'].includes(f.status)).map(f=>`<option value="${f.id}">${esc(f.title.slice(0,50))}</option>`).join('')}</select></div></div><div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveReminder()">Save reminder</button></div>`);
    setTimeout(()=>document.getElementById('rm-text')?.focus(),50);
  }
  async function saveReminder(){const text=document.getElementById('rm-text').value.trim();if(!text){toast('Text required','err');return;}const r={id:genId(),text,dueDate:document.getElementById('rm-date').value,findingId:document.getElementById('rm-finding').value||null,fired:false,created:new Date().toISOString()};if(!state.reminders)state.reminders=[];state.reminders.push(r);closeModal();await safeSyncToCloud();updateBadges();renderPanel('reminders');toast('Reminder saved! ⏰','info');}
  async function deleteReminder(id){state.reminders=state.reminders.filter(r=>r.id!==id);await safeSyncToCloud();updateBadges();renderPanel('reminders');toast('Deleted.');}

  // ─── Writeups ─────────────────────────────────────────────────────────────────
  function renderWriteups(){
    const el=document.getElementById('panel-writeups');
    if(!state.writeups.length){el.innerHTML=`<div style="text-align:center;padding:4rem 2rem;">${I.writeups}<div style="color:var(--text3);font-size:14px;margin-top:16px;margin-bottom:4px;">No writeups yet.</div><button class="btn accent" style="margin-top:12px;" onclick="App.openWriteupModal()">${I.plus} New writeup</button></div>`;return;}
    el.innerHTML=`<div class="writeup-grid">${[...state.writeups].sort((a,b)=>new Date(b.created)-new Date(a.created)).map(w=>`<div class="writeup-card" onclick="App.openWriteupDetail('${w.id}')"><div class="writeup-card-title">${esc(w.title)}</div><div class="writeup-card-meta"><span>${fmtDate(w.created)}</span>${w.platform?`<span>${esc(w.platform)}</span>`:''}${w.type?`<span>${esc(w.type)}</span>`:''}</div><div class="writeup-card-body">${esc((w.content||'').slice(0,200))}</div>${(w.tags||[]).length?`<div class="writeup-tags">${w.tags.map(t=>`<span class="writeup-tag">${esc(t)}</span>`).join('')}</div>`:''}<div style="display:flex;gap:6px;margin-top:12px;" onclick="event.stopPropagation()"><button class="btn" style="font-size:12px;padding:4px 10px;" onclick="App.openWriteupModal('${w.id}')">${I.edit}</button><button class="btn" style="font-size:12px;padding:4px 10px;" onclick="App.deleteWriteup('${w.id}')">${I.trash}</button>${w.url?`<a class="btn" href="${esc(w.url)}" target="_blank" rel="noopener" style="font-size:12px;padding:4px 10px;text-decoration:none;" onclick="event.stopPropagation()">${I.link}</a>`:''}</div></div>`).join('')}</div>`;
  }
  function openWriteupModal(id){
    const w=id?state.writeups.find(x=>x.id===id):null,v=(k,d='')=>w?(w[k]!=null?w[k]:d):d,today=new Date().toISOString().split('T')[0];
    showModal(`<div class="modal-header"><h3>${id?'Edit writeup':'New writeup'}</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div><div class="modal-body"><div class="form-field form-field-full"><label>Title *</label><input id="wf-title" value="${esc(v('title'))}" placeholder="Stored XSS in Acme Corp — $1500"/></div><div class="form-row" style="margin-top:14px;"><div class="form-field"><label>Platform</label><select id="wf-platform"><option value="">Select…</option>${PLATFORMS.map(p=>`<option value="${p}" ${v('platform')===p?'selected':''}>${p}</option>`).join('')}</select></div><div class="form-field"><label>Vuln type</label><select id="wf-type"><option value="">Select…</option>${VULN_TYPES.map(t=>`<option value="${t}" ${v('type')===t?'selected':''}>${t}</option>`).join('')}</select></div></div><div class="form-row"><div class="form-field"><label>Date</label><input id="wf-date" type="date" value="${v('created',today).split('T')[0]}"/></div><div class="form-field"><label>External URL</label><input id="wf-url" value="${esc(v('url'))}" placeholder="https://…"/></div></div><div class="form-field form-field-full"><label>Tags</label><input id="wf-tags" value="${esc(w&&w.tags?w.tags.join(', '):'')}" placeholder="xss, bugcrowd"/></div><div class="form-field form-field-full" style="margin-top:14px;"><label>Content</label><textarea id="wf-content" class="writeup-editor">${esc(v('content'))}</textarea></div></div><div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.saveWriteup('${id||''}')">${id?'Update':'Save'}</button></div>`);
  }
  async function saveWriteup(id){const title=document.getElementById('wf-title').value.trim();if(!title){toast('Title required','err');return;}const tags=document.getElementById('wf-tags').value.split(',').map(t=>t.trim()).filter(Boolean);const w={id:id||genId(),title,tags,platform:document.getElementById('wf-platform').value,type:document.getElementById('wf-type').value,created:document.getElementById('wf-date').value||new Date().toISOString().split('T')[0],url:document.getElementById('wf-url').value.trim(),content:document.getElementById('wf-content').value.trim(),updated:new Date().toISOString()};if(id){const idx=state.writeups.findIndex(x=>x.id===id);state.writeups[idx]=w;toast('Updated!');}else{state.writeups.unshift(w);toast('Writeup saved!');}closeModal();updateBadges();await safeSyncToCloud();renderPanel(state.activePanel);}
  function openWriteupDetail(id){const w=state.writeups.find(x=>x.id===id);if(!w)return;showDetail(`<div class="modal-header"><h3 style="max-width:500px;line-height:1.4;">${esc(w.title)}</h3><button class="icon-btn" onclick="App.closeDetail()">${I.close}</button></div><div class="modal-body"><div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;">${w.platform?`<span class="badge p3">${esc(w.platform)}</span>`:''}${w.type?`<span class="badge p4">${esc(w.type)}</span>`:''}<span style="font-size:12px;color:var(--text3);font-family:var(--mono);">${fmtDate(w.created)}</span>${w.url?`<a href="${esc(w.url)}" target="_blank" rel="noopener" class="btn" style="font-size:12px;padding:3px 10px;">${I.link} View</a>`:''}</div>${(w.tags||[]).length?`<div class="writeup-tags" style="margin-bottom:16px;">${w.tags.map(t=>`<span class="writeup-tag">${esc(t)}</span>`).join('')}</div>`:''}<div class="writeup-detail-content">${esc(w.content||'No content.')}</div></div><div class="modal-footer"><button class="btn" onclick="App.closeDetail()">Close</button><button class="btn accent" onclick="App.closeDetail();App.openWriteupModal('${w.id}')">Edit</button></div>`);}
  async function deleteWriteup(id){if(!confirm('Delete?'))return;state.writeups=state.writeups.filter(x=>x.id!==id);await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);toast('Deleted.');}

  // ─── Guide ────────────────────────────────────────────────────────────────────
  function renderGuide(){
    const el=document.getElementById('panel-guide');
    el.innerHTML=`<div class="card" style="margin-bottom:20px;"><div class="card-header"><span class="card-header-title">Priority levels</span></div><div style="padding:20px;">${Object.entries(PRIOS).map(([k,v])=>`<div style="display:flex;gap:14px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--border);"><span class="badge ${v.cls}" style="min-width:44px;justify-content:center;">${v.short}</span><div><div style="font-weight:500;font-size:14px;margin-bottom:3px;">${v.label}</div><div style="font-size:13px;color:var(--text2);">${v.desc}</div></div></div>`).join('')}</div></div>
    <div class="card" style="margin-bottom:20px;"><div class="card-header"><span class="card-header-title">CVE Lookup</span></div><div style="padding:20px;"><div style="display:flex;gap:8px;margin-bottom:12px;"><input id="cve-inp" placeholder="CVE-2024-12345" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:8px 12px;color:var(--text);font-size:13px;flex:1;font-family:var(--mono);" onkeydown="if(event.key==='Enter')App.lookupCVE(this.value)"/><button class="btn accent" onclick="App.lookupCVE(document.getElementById('cve-inp').value)">Look up</button></div><div id="cve-result"></div></div></div>
    <div class="card"><div class="card-header"><span class="card-header-title">Status flow</span></div><div style="padding:20px;"><table><thead><tr><th>Status</th><th>Meaning</th></tr></thead><tbody><tr><td>${sbadge('new')}</td><td style="font-size:13px;color:var(--text2);">Found, not yet submitted</td></tr><tr><td>${sbadge('submitted')}</td><td style="font-size:13px;color:var(--text2);">Submitted, waiting for triage</td></tr><tr><td>${sbadge('triaged')}</td><td style="font-size:13px;color:var(--text2);">Confirmed valid, under review</td></tr><tr><td>${sbadge('resolved')}</td><td style="font-size:13px;color:var(--text2);">Fixed and bounty paid</td></tr><tr><td>${sbadge('duplicate')}</td><td style="font-size:13px;color:var(--text2);">Reported by someone else first</td></tr><tr><td>${sbadge('na')}</td><td style="font-size:13px;color:var(--text2);">Out of scope or no bounty</td></tr></tbody></table></div></div>`;
  }

  // ─── Settings ─────────────────────────────────────────────────────────────────
  function renderSettings(){
    const el=document.getElementById('panel-settings'),u=state.currentUser,s=state.settings;
    el.innerHTML=`<div style="max-width:680px;">

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">${I.user} Profile</span></div>
        <div style="padding:20px;">
          <div class="settings-input-row"><div class="form-field" style="flex:1;"><label>Display name</label><input id="st-name" value="${esc(s.displayName||u.username)}"/></div><button class="btn accent" onclick="App.saveProfile()">Save</button></div>
          <div class="settings-row"><div><div class="settings-row-label">Username</div><div class="settings-row-sub text-mono">${esc(u.username)}</div></div></div>
          <div class="settings-row"><div><div class="settings-row-label">Email</div><div class="settings-row-sub">${esc(u.email)}</div></div></div>
          <div class="settings-row"><div><div class="settings-row-label">Member since</div><div class="settings-row-sub">${fmtDate(u.joined)}</div></div></div>
        </div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">🎨 Appearance</span></div>
        <div style="padding:20px;"><div class="settings-row"><div><div class="settings-row-label">Theme</div><div class="settings-row-sub">Currently: ${s.theme==='dark'?'Dark':'Light'} mode</div></div><button class="btn" onclick="App.toggleTheme()">${s.theme==='dark'?'☀️ Switch to Light':'🌙 Switch to Dark'}</button></div></div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">${I.lock} Change password</span></div>
        <div style="padding:20px;">
          <div class="form-field form-field-full"><label>Current password</label><input id="st-oldpw" type="password"/></div>
          <div class="form-row"><div class="form-field"><label>New password</label><input id="st-newpw" type="password"/></div><div class="form-field"><label>Confirm</label><input id="st-newpw2" type="password"/></div></div>
          <span id="pw-err" style="color:var(--red);font-size:12px;display:block;min-height:16px;margin-bottom:8px;"></span>
          <button class="btn accent" onclick="App.changePw()">Update password</button>
        </div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">${I.shield} Two-factor authentication</span></div>
        <div style="padding:20px;">${s.twoFAEnabled?`<div class="tfa-enabled-badge">${I.check} 2FA enabled</div><p style="font-size:13px;color:var(--text2);margin:12px 0 16px;">Your account is protected with TOTP.</p><button class="btn danger" onclick="App.disable2FA()">Disable 2FA</button>`:`<p style="font-size:13px;color:var(--text2);margin-bottom:16px;">Add an extra security layer using Google Authenticator or Authy.</p><button class="btn accent" onclick="App.setup2FA()">${I.shield} Enable 2FA</button>`}</div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">${I.cloud} Cloud sync &amp; cross-device login</span></div>
        <div style="padding:20px;">
          <div style="background:var(--blue-bg);border:1px solid rgba(88,166,255,.2);border-radius:8px;padding:14px;font-size:13px;color:var(--blue);margin-bottom:16px;line-height:1.7;">
            ${I.cloud} <strong>How cross-device login works:</strong><br>
            1. Get a free API key at <a href="https://jsonbin.io" target="_blank" style="color:var(--blue);">jsonbin.io</a> → Sign up → API Keys → copy Secret Key<br>
            2. Paste it below and click Save &amp; sync<br>
            3. On your phone: open the app URL, go to Settings first and add the same API key, then log in with your username and password<br>
            Your data is AES-256 encrypted with your password before it leaves the browser.
          </div>
          <div class="settings-row">
            <div><div class="settings-row-label">Sync status</div><div class="settings-row-sub text-mono">${state.binId?'Data bin: '+state.binId.slice(0,16)+'…':'No cloud bin yet'}</div></div>
            <div style="display:flex;gap:6px;align-items:center;"><span class="sync-dot" id="sync-dot2"></span><span style="font-size:11px;color:var(--text3);" id="sync-label2">—</span></div>
          </div>
          <div class="settings-input-row" style="border-top:1px solid var(--border);padding-top:16px;margin-top:4px;">
            <div class="form-field" style="flex:1;"><label>JSONBin.io API key</label>
              <input id="st-apikey" type="password" value="${localStorage.getItem(LS.APIKEY)||''}" placeholder="$2a$10$…"/>
              <span class="form-hint">Same key must be set on all devices for cross-device login to work</span>
            </div>
            <button class="btn accent" onclick="App.saveApiKey()">Save &amp; sync</button>
          </div>
          <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn" onclick="App.forcSync()">${I.cloud} Sync now</button>
            <button class="btn" onclick="App.refreshAccountFromCloud()">↻ Re-sync account from cloud</button>
          </div>
        </div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title">${I.download} Export &amp; Import</span></div>
        <div style="padding:20px;">
          <div class="settings-row"><div><div class="settings-row-label">Export all data</div><div class="settings-row-sub">Findings, workspaces, writeups, recon notes as JSON</div></div><button class="btn" onclick="App.exportData()">${I.download} Export</button></div>
          <div class="settings-row"><div><div class="settings-row-label">Import data</div><div class="settings-row-sub">Merges by ID — existing data is never deleted</div></div><button class="btn" onclick="document.getElementById('imp-file').click()">${I.upload} Import</button><input type="file" id="imp-file" accept=".json" style="display:none" onchange="App.importData(this)"/></div>
        </div>
      </div>

      <div class="card settings-section"><div class="card-header"><span class="card-header-title" style="color:var(--red);">Danger zone</span></div>
        <div style="padding:20px;">
          <div class="settings-row"><div><div class="settings-row-label">Delete all findings</div><div class="settings-row-sub">${state.findings.length} findings will be permanently removed</div></div><button class="btn danger" onclick="App.deleteAllFindings()">Delete all</button></div>
          <div class="settings-row"><div><div class="settings-row-label">Sign out</div><div class="settings-row-sub">Clears local session. Cloud data stays safe.</div></div><button class="btn danger" onclick="App.doLogout()">Sign out</button></div>
        </div>
      </div>

    </div>`;
    setTimeout(_updateSyncUI,50);
  }

  async function saveProfile(){
    const name=document.getElementById('st-name').value.trim();if(!name)return;
    state.settings.displayName=name;
    const el=document.querySelector('.user-name');if(el)el.textContent=name;
    const av=document.querySelector('.user-avatar');if(av)av.textContent=name.slice(0,2).toUpperCase();
    await safeSyncToCloud();toast('Profile updated!');
  }

  async function changePw(){
    const errEl=document.getElementById('pw-err'),oldP=document.getElementById('st-oldpw').value,newP=document.getElementById('st-newpw').value,newP2=document.getElementById('st-newpw2').value;
    errEl.textContent='';
    if(!oldP||!newP||!newP2){errEl.textContent='All fields required.';return;}
    if(newP.length<8){errEl.textContent='Min 8 characters.';return;}
    if(newP!==newP2){errEl.textContent='Passwords do not match.';return;}
    const oldHash=await hashPw(oldP);
    // Verify against local user store
    const localUsers=getLocalUsers(),user=localUsers.find(u=>(u.id||u.uid)===state.currentUser.id&&u.hash===oldHash);
    if(!user){errEl.textContent='Current password incorrect.';return;}
    // Update hash everywhere
    const newHash=await hashPw(newP);
    user.hash=newHash;saveLocalUsers(localUsers);
    // Update cloud index too
    if(hasApiKey()){
      const indexUsers=await loadIndex()||[];
      const iu=indexUsers.find(u=>u.uid===state.currentUser.id);
      if(iu){iu.hash=newHash;await saveIndex(indexUsers);}
      // Re-encrypt data bin with new password
      state.currentUser.password=newP;
      await saveDataBin(state.binId,newP,state.currentUser.id,buildPayload());
    } else {
      state.currentUser.password=newP;
    }
    toast('Password updated!');
    document.getElementById('st-oldpw').value='';document.getElementById('st-newpw').value='';document.getElementById('st-newpw2').value='';
  }

  async function setup2FA(){
    const secret=genTOTPSecret(),issuer='BugHunterTracker',url=`otpauth://totp/${issuer}:${encodeURIComponent(state.currentUser.username)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    showModal(`<div class="modal-header"><h3>Set up 2FA</h3><button class="icon-btn" onclick="App.closeModal()">${I.close}</button></div>
    <div class="modal-body"><div class="tfa-setup-box">
      <div class="tfa-steps">
        <div class="tfa-step"><div class="tfa-step-num">1</div><div>Install <strong>Google Authenticator</strong> or <strong>Authy</strong> on your phone</div></div>
        <div class="tfa-step"><div class="tfa-step-num">2</div><div>Scan the QR code or enter the secret manually</div></div>
      </div>
      <div class="tfa-qr-wrap" id="tfa-qr"></div>
      <div class="tfa-secret">${secret}</div>
      <button class="btn" style="margin:0 auto 16px;display:flex;gap:6px;" onclick="navigator.clipboard.writeText('${secret}').then(()=>App._toast('Secret copied!'))">${I.copy} Copy secret</button>
      <div class="tfa-step"><div class="tfa-step-num">3</div><div>Enter the 6-digit code from the app to confirm</div></div>
      <div class="form-field" style="margin-top:12px;"><input id="tfa-code" type="text" inputmode="numeric" placeholder="000000" maxlength="6" style="letter-spacing:4px;font-size:22px;text-align:center;font-family:var(--mono);"/></div>
      <span id="tfa-err" style="color:var(--red);font-size:12px;display:block;min-height:16px;"></span>
    </div></div>
    <div class="modal-footer"><button class="btn" onclick="App.closeModal()">Cancel</button><button class="btn accent" onclick="App.confirm2FA('${secret}')">Enable 2FA</button></div>`);
    setTimeout(()=>{const qr=document.getElementById('tfa-qr');if(qr&&typeof QRCode!=='undefined')new QRCode(qr,{text:url,width:144,height:144,correctLevel:QRCode.CorrectLevel.M});else if(qr)qr.innerHTML=`<div style="font-size:9px;word-break:break-all;color:#333;padding:4px;">${url}</div>`;},100);
  }
  async function confirm2FA(secret){
    const code=document.getElementById('tfa-code').value.trim(),errEl=document.getElementById('tfa-err');errEl.textContent='';
    if(!code){errEl.textContent='Enter the code.';return;}
    if(!await verifyTOTP(secret,code)){errEl.textContent='Invalid or expired code.';return;}
    state.settings.twoFAEnabled=true;state.settings.twoFASecret=secret;
    await safeSyncToCloud();closeModal();toast('2FA enabled! 🔐','info');renderPanel('settings');
    if(!document.querySelector('.user-2fa-badge'))document.querySelector('.sidebar-user')?.insertAdjacentHTML('beforeend','<span class="user-2fa-badge">2FA</span>');
  }
  async function disable2FA(){
    if(!confirm('Disable 2FA? This reduces your account security.'))return;
    state.settings.twoFAEnabled=false;state.settings.twoFASecret=null;
    await safeSyncToCloud();toast('2FA disabled.');renderPanel('settings');
    document.querySelector('.user-2fa-badge')?.remove();
  }

  async function saveApiKey(){
    const key=document.getElementById('st-apikey').value.trim();
    if(key)localStorage.setItem(LS.APIKEY,key);else localStorage.removeItem(LS.APIKEY);
    // If we have a bin already, just sync
    if(state.binId&&key){
      const ok=await safeSyncToCloud();
      toast(ok&&state.syncStatus==='ok'?'Synced to cloud! ☁️ You can now log in from any device.':'Sync failed — check the key is correct.', ok?'info':'err');
      return;
    }
    // No bin yet — create one now
    if(key&&!state.binId){
      setSyncStatus('syncing');
      const newBin=await createDataBin(state.currentUser.id,state.currentUser.password,buildPayload());
      if(newBin){
        state.binId=newBin;
        localStorage.setItem(LS.BIN(state.currentUser.id),newBin);
        // Also update the user index with the new bin ID
        const indexUsers=await loadIndex()||[];
        const iu=indexUsers.find(u=>u.uid===state.currentUser.id);
        if(iu){iu.dataBinId=newBin;await saveIndex(indexUsers);}
        else{
          const localUsers=getLocalUsers(),lu=localUsers.find(u=>(u.id||u.uid)===state.currentUser.id);
          indexUsers.push({uid:state.currentUser.id,username:state.currentUser.username,email:state.currentUser.email,hash:lu?.hash||'',dataBinId:newBin,joined:state.currentUser.joined});
          await saveIndex(indexUsers);
        }
        setSyncStatus('ok');state.lastSync=new Date().toISOString();_updateSyncUI();
        toast('Cloud sync set up! You can now log in from any device. ☁️','info');
      } else {
        setSyncStatus('error');
        toast('Failed to create cloud storage. Check your API key.','err');
      }
      return;
    }
    if(!key)toast('API key cleared — local storage only.','info');
  }

  async function forcSync(){
    const ok=await safeSyncToCloud();
    toast(ok&&state.syncStatus==='ok'?'Synced to cloud! ☁️':state.syncStatus==='local'?'No API key — set one in Settings to sync.':'Sync failed — check your API key.',ok&&state.syncStatus==='ok'?'ok':state.syncStatus==='local'?'info':'err');
  }

  // Re-pull everything fresh from cloud (useful after changing API key on another device)
  async function refreshAccountFromCloud(){
    if(!hasApiKey()||!state.binId){toast('Set an API key first.','err');return;}
    setSyncStatus('syncing');
    const data=await loadDataBin(state.binId,state.currentUser.password,state.currentUser.id);
    if(!data){toast('Could not load from cloud. Check API key and bin ID.','err');setSyncStatus('error');return;}
    state.findings=data.findings||[];state.writeups=data.writeups||[];state.workspaces=data.workspaces||[];
    state.reconNotes=data.reconNotes||[];state.reminders=data.reminders||[];state.timeLog=data.timeLog||[];
    state.monthlyGoal=data.monthlyGoal||300;
    state.settings=Object.assign(state.settings,data.settings||{});
    state.streak=data.streak||state.streak;
    _saveCache(state.currentUser.id,data);
    setSyncStatus('ok');updateBadges();renderPanel(state.activePanel);
    toast('Refreshed from cloud! ✅','info');
  }

  function exportData(){
    const blob=new Blob([JSON.stringify({exportedAt:new Date().toISOString(),version:5,username:state.currentUser.username,findings:state.findings,writeups:state.writeups,workspaces:state.workspaces,reconNotes:state.reconNotes,reminders:state.reminders,streak:state.streak,timeLog:state.timeLog,monthlyGoal:state.monthlyGoal},null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`bughunter_export_${new Date().toISOString().slice(0,10)}.json`;a.click();toast('Exported!','info');
  }

  function importData(input){
    const file=input.files?.[0];if(!file)return;
    const reader=new FileReader();
    reader.onload=async e=>{
      try{
        const data=JSON.parse(e.target.result);
        if(!data.findings&&!data.writeups&&!data.workspaces){toast('Invalid export file.','err');return;}
        if(!confirm(`Merge import? Existing data is never deleted.\n• ${(data.findings||[]).length} findings\n• ${(data.writeups||[]).length} writeups\n• ${(data.workspaces||[]).length} workspaces`))return;
        state.findings=mergeById(state.findings,data.findings||[]);
        state.writeups=mergeById(state.writeups,data.writeups||[]);
        state.workspaces=mergeWorkspaces(state.workspaces,data.workspaces||[]);
        state.reconNotes=mergeById(state.reconNotes,data.reconNotes||[]);
        state.reminders=mergeById(state.reminders,data.reminders||[]);
        if(data.timeLog)state.timeLog=mergeById(state.timeLog||[],data.timeLog);
        await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);
        toast('Import merged successfully!','info');
      }catch(ex){toast('Failed to parse file.','err');}
    };
    reader.readAsText(file);input.value='';
  }

  async function deleteAllFindings(){
    if(!confirm(`Delete ALL ${state.findings.length} findings permanently?`))return;
    if(!confirm('Final confirmation — this cannot be undone.'))return;
    state.findings=[];await safeSyncToCloud();updateBadges();renderPanel(state.activePanel);toast('All findings deleted.','err');
  }

  // ─── Modal helpers ────────────────────────────────────────────────────────────
  function showModal(html){const o=document.getElementById('modal-overlay');o.classList.remove('hidden');o.innerHTML=`<div class="modal modal-lg" onclick="event.stopPropagation()">${html}</div>`;}
  function showDetail(html){const o=document.getElementById('detail-overlay');o.classList.remove('hidden');o.innerHTML=`<div class="modal modal-lg" onclick="event.stopPropagation()">${html}</div>`;}
  function closeModal(){document.getElementById('modal-overlay').classList.add('hidden');}
  function closeDetail(){document.getElementById('detail-overlay').classList.add('hidden');}
  function _modalBg(e){if(e.target.id==='modal-overlay')closeModal();}
  function _detailBg(e){if(e.target.id==='detail-overlay')closeDetail();}
  function _toast(msg){toast(msg,'info');}

  // ─── Boot ─────────────────────────────────────────────────────────────────────
  async function boot(){
    // Apply saved theme immediately before anything renders
    const cachedTheme=localStorage.getItem('bht_theme_quick')||'dark';
    document.documentElement.setAttribute('data-theme',cachedTheme);

    const sess=getSession();
    if(sess){
      const uid=sess.split('|')[1];
      if(uid){
        const localUsers=getLocalUsers();
        const user=localUsers.find(u=>(u.id||u.uid)===uid);
        if(user){
          const cached=_getCache(uid);
          if(cached){
            state.currentUser={...user,id:user.id||user.uid,password:'__cached__'};
            state.findings=cached.findings||[];state.writeups=cached.writeups||[];
            state.workspaces=cached.workspaces||[];state.reconNotes=cached.reconNotes||[];
            state.reminders=cached.reminders||[];
            state.streak=cached.streak||{current:0,longest:0,lastActive:null,history:[]};
            state.timeLog=cached.timeLog||[];state.monthlyGoal=cached.monthlyGoal||300;
            state.settings=Object.assign({twoFAEnabled:false,twoFASecret:null,displayName:user.username,theme:'dark'},cached.settings||{});
            state.binId=user.dataBinId||localStorage.getItem(LS.BIN(uid));
            applyTheme(state.settings.theme||'dark');
            localStorage.setItem('bht_theme_quick',state.settings.theme||'dark');
            renderApp();
            setSyncStatus(hasApiKey()?'ok':'local');
            if(!hasApiKey()){
              const sl=document.getElementById('sync-label');
              if(sl)sl.textContent='Set API key in Settings to sync';
            }
            setTimeout(checkReminders,2000);
            setInterval(checkReminders,60000);
            return;
          }
        }
      }
    }
    renderAuth();
  }

  // ─── Public API ───────────────────────────────────────────────────────────────
  return{
    boot,switchAuthTab,doLogin,doRegister,doLogout,
    nav,toggleMenu,closeSidebar,toggleTheme,
    openFindingModal,saveFinding,deleteFinding,openDetail,
    setPrio,setSearch,saveGoal,
    openWorkspaceModal,saveWorkspace,deleteWorkspace,openWorkspace,closeWorkspace,
    openEntryModal,saveEntry,deleteEntry,pickColor,
    openWriteupModal,saveWriteup,openWriteupDetail,deleteWriteup,
    openReconModal,saveRecon,deleteRecon,
    openReminderModal,saveReminder,deleteReminder,requestNotificationPermission,
    renderProgramDirectory,startWorkspaceFromProgram,
    renderProgramStats,renderTimeTracker,startTimer,stopTimer,
    generateReport,_copyReport,_downloadReport,
    lookupCVE,
    setup2FA,confirm2FA,disable2FA,
    saveProfile,changePw,saveApiKey,forcSync,refreshAccountFromCloud,
    exportData,importData,deleteAllFindings,
    closeModal,closeDetail,_modalBg,_detailBg,_toast,
    _dupCheck,_handleImgDrop,_handleImgFile,_clearImg,
    _handleEntryImg,_handleEntryImgFile,
  };
})();
