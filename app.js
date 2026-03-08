/* ================================================================
   CipherStegano Suite — Main Application Logic (Updated for StegoCrypt Pro layout)
================================================================ */

'use strict';

/* ────────────────────────────────────────
   1. GLOBAL STATE
──────────────────────────────────────── */
const S = {
  imgFile      : null, imgData      : null, imgCapBytes  : 0, stegoImgData : null,
  audFile      : null, audSamples   : null, audSR        : 0, audCh        : 0, audCapBytes  : 0, stegoAudBlob : null,
  vidFile      : null, stegoVidBlob : null,
  imgPT : 'text', audPT : 'text', vidPT : 'text',
  imgSF : null, audSF : null, vidSF : null,
  decImgFile : null, decAudFile : null, decVidFile : null,
};

const VID_MAGIC = new Uint8Array([0x43, 0x53, 0x47, 0x41, 0x4E, 0x4F, 0x5F, 0x56, 0x31]);

/* ════════════════════════════════════════
   2. GLOBAL MODE TOGGLE (Encode / Decode)
════════════════════════════════════════ */
let globalMode = 'enc';

function setGlobalMode(mode) {
  globalMode = mode;
  document.getElementById('nav-enc').classList.toggle('active', mode === 'enc');
  document.getElementById('nav-dec').classList.toggle('active', mode === 'dec');
  
  ['img', 'aud', 'vid'].forEach(panel => {
    const wrapper = document.getElementById('panel-' + panel);
    if (wrapper) {
      wrapper.querySelectorAll('.enc-sec').forEach(el => el.style.display = mode === 'enc' ? 'block' : 'none');
      wrapper.querySelectorAll('.dec-sec').forEach(el => el.style.display = mode === 'dec' ? 'block' : 'none');
    }
  });
}

window.addEventListener('DOMContentLoaded', () => {
  setGlobalMode('enc');
});

function switchMedia(m) {
  ['img', 'aud', 'vid'].forEach(t => {
    document.getElementById('panel-' + t).classList.toggle('on', t === m);
    document.getElementById('mt-'    + t).classList.toggle('active', t === m);
  });
}

/* ════════════════════════════════════════
   3. DRAG & DROP & PAYLOAD HELPERS
════════════════════════════════════════ */
function dzO(e, id) { e.preventDefault(); document.getElementById(id).classList.add('over'); }
function dzL(id) { document.getElementById(id).classList.remove('over'); }
function dzD(e, id, callback) {
  e.preventDefault(); dzL(id);
  const file = e.dataTransfer.files[0];
  if (file) callback(file);
}

function setPT(panel, type) {
  S[panel + 'PT'] = type;
  const prefix = { img: 'i', aud: 'a', vid: 'v' }[panel];
  document.getElementById(prefix + 'pt-t').classList.toggle('active', type === 'text');
  document.getElementById(prefix + 'pt-f').classList.toggle('active', type === 'file');
  document.getElementById(panel + '-tp').style.display = type === 'text' ? 'block' : 'none';
  document.getElementById(panel + '-fp').style.display = type === 'file' ? 'block' : 'none';
  updCap(panel);
}

function loadSF(file, panel) {
  if (!file) return;
  S[panel + 'SF'] = file;
  document.getElementById('sft-' + panel + '-n').textContent = file.name;
  document.getElementById('sft-' + panel + '-s').textContent = fmtB(file.size);
  document.getElementById('sft-' + panel).classList.add('show');
  updCap(panel);
}

function clearSF(panel) {
  S[panel + 'SF'] = null;
  document.getElementById('sft-' + panel).classList.remove('show');
  const inputIds = { img: 'inp-si', aud: 'inp-sa', vid: 'inp-sv' };
  document.getElementById(inputIds[panel]).value = '';
  updCap(panel);
}

/* ════════════════════════════════════════
   4. AES CRYPTO & PACKING
════════════════════════════════════════ */
function aesE(plaintext, password) {
  const salt = CryptoJS.lib.WordArray.random(16);
  const key  = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
  const iv   = CryptoJS.lib.WordArray.random(16);
  const cipherResult = CryptoJS.AES.encrypt(plaintext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  return salt.toString(CryptoJS.enc.Hex) + ':' + iv.toString(CryptoJS.enc.Hex) + ':' + cipherResult.ciphertext.toString(CryptoJS.enc.Hex);
}

function aesD(packed, password) {
  const parts = packed.split(':');
  if (parts.length < 3) throw new Error('Invalid data format');
  const salt = CryptoJS.enc.Hex.parse(parts[0]);
  const iv   = CryptoJS.enc.Hex.parse(parts[1]);
  const ct   = CryptoJS.enc.Hex.parse(parts.slice(2).join(':'));
  const key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
  const decrypted = CryptoJS.AES.decrypt({ ciphertext: ct }, key, { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) throw new Error('Wrong password or corrupted data');
  return result;
}

async function packP(panel, password) {
  let plaintext;
  if (S[panel + 'PT'] === 'text') {
    const msg = document.getElementById(panel + '-msg').value.trim();
    if (!msg) throw new Error('Please enter a message');
    plaintext = '__T__' + msg;
  } else {
    const file = S[panel + 'SF'];
    if (!file) throw new Error('Please select a secret file');
    const arrayBuffer = await file.arrayBuffer();
    plaintext = '__F__:' + file.name + ':' + ab2b64(arrayBuffer);
  }
  return aesE(plaintext, password);
}

function unpackD(decrypted) {
  if (decrypted.startsWith('__T__')) return { type: 'text', text: decrypted.slice(5) };
  if (decrypted.startsWith('__F__:')) {
    const rest = decrypted.slice(6);
    const lastColon = rest.lastIndexOf(':');
    return { type: 'file', name: rest.slice(0, lastColon), bytes: b642ab(rest.slice(lastColon + 1)) };
  }
  return { type: 'text', text: decrypted };
}

function ab2b64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b642ab(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* ════════════════════════════════════════
   5. LSB & BINARY UTILS
════════════════════════════════════════ */
function buildBuf(encryptedStr) {
  const data = new TextEncoder().encode(encryptedStr);
  const buffer = new Uint8Array(4 + data.length);
  const len = data.length;
  buffer[0] = (len >> 24) & 0xFF; buffer[1] = (len >> 16) & 0xFF;
  buffer[2] = (len >> 8) & 0xFF; buffer[3] = len & 0xFF;
  buffer.set(data, 4);
  return buffer;
}

function getRGB(pixelData) {
  const rgb = new Uint8Array((pixelData.length / 4) * 3);
  let j = 0;
  for (let i = 0; i < pixelData.length; i += 4) { rgb[j++] = pixelData[i]; rgb[j++] = pixelData[i + 1]; rgb[j++] = pixelData[i + 2]; }
  return rgb;
}

function setRGB(pixelData, rgb) {
  let j = 0;
  for (let i = 0; i < pixelData.length; i += 4) { pixelData[i] = rgb[j++]; pixelData[i + 1] = rgb[j++]; pixelData[i + 2] = rgb[j++]; }
}

function injectL(carrier, payload) {
  let carrierIndex = 0;
  for (let i = 0; i < payload.length; i++) {
    const byte = payload[i];
    for (let bit = 7; bit >= 0; bit--) {
      if (carrierIndex >= carrier.length) throw new Error('Capacity exceeded');
      carrier[carrierIndex] = (carrier[carrierIndex] & 0xFE) | ((byte >> bit) & 1);
      carrierIndex++;
    }
  }
}

function extractL(carrier, numBytes, startBit = 0) {
  const output = new Uint8Array(numBytes);
  for (let i = 0; i < numBytes; i++) {
    let byte = 0;
    for (let bit = 7; bit >= 0; bit--) {
      const carrierIndex = startBit + (i * 8) + (7 - bit);
      if (carrierIndex < carrier.length) byte |= (carrier[carrierIndex] & 1) << bit;
    }
    output[i] = byte;
  }
  return output;
}

function updCap(panel) {
  let payloadBytes = 0;
  if (S[panel + 'PT'] === 'text') {
    const msg = document.getElementById(panel + '-msg')?.value || '';
    payloadBytes = new TextEncoder().encode(msg).length;
  } else {
    payloadBytes = Math.ceil((S[panel + 'SF']?.size || 0) * 1.38);
  }
  payloadBytes += 80;
  const capacity = panel === 'img' ? S.imgCapBytes : panel === 'aud' ? S.audCapBytes : Infinity;
  const percentage = (isFinite(capacity) && capacity > 0) ? Math.min(100, (payloadBytes / capacity) * 100) : (payloadBytes > 0 ? 5 : 0);
  
  const label = document.getElementById(panel + '-clbl');
  if (label) label.textContent = (isFinite(capacity) && capacity > 0) ? `${fmtB(payloadBytes)} of ${fmtB(capacity)} (${percentage.toFixed(1)}%)` : fmtB(payloadBytes);
  
  const fill = document.getElementById(panel + '-cf');
  if (fill) { fill.style.width = Math.min(percentage, 100) + '%'; fill.className = 'cap-fill' + (percentage > 90 ? ' full' : percentage > 70 ? ' warn' : ''); }
}

/* ════════════════════════════════════════
   6. IMAGE ENGINE
════════════════════════════════════════ */
function loadCImg(file) {
  if (!file || !file.type.startsWith('image/')) { showSt('img-est', 'err', 'Not a supported image'); return; }
  S.imgFile = file;
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const w = img.width, h = img.height;
      const canvas = document.createElement('canvas');
      canvas.width = w; canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      S.imgData = ctx.getImageData(0, 0, w, h);
      S.imgCapBytes = Math.floor((w * h * 3) / 8) - 8;
      
      const origCanvas = document.getElementById('cv-orig');
      origCanvas.width = w; origCanvas.height = h;
      origCanvas.getContext('2d').putImageData(S.imgData, 0, 0);
      
      document.getElementById('ftimg-n').textContent = file.name;
      document.getElementById('ftimg-s').textContent = fmtB(file.size);
      document.getElementById('ftimg').classList.add('show');
      document.getElementById('img-dims').textContent = `${w} × ${h} px`;
      document.getElementById('img-cap').textContent = fmtB(S.imgCapBytes);
      document.getElementById('img-type').textContent = file.type.split('/').pop().toUpperCase();
      document.getElementById('img-chips').style.display = 'flex';
      updCap('img');
    };
    img.onerror = () => showSt('img-est', 'err', 'Failed to load image');
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function clearCImg() {
  S.imgFile = null; S.imgData = null; S.imgCapBytes = 0;
  document.getElementById('ftimg').classList.remove('show');
  document.getElementById('img-chips').style.display = 'none';
  document.getElementById('img-prev').style.display = 'none';
  document.getElementById('inp-img').value = '';
  updCap('img');
}

async function encImg() {
  if (!S.imgData) return showSt('img-est', 'err', 'Please select a carrier image first');
  const password = document.getElementById('img-pwd').value;
  if (!password) return showSt('img-est', 'err', 'Please enter a password');
  
  setPg('img-pg', 'img-pf', 0, 'Encrypting...'); await slp(30);
  try {
    const encrypted = await packP('img', password);
    const payload = buildBuf(encrypted);
    if (payload.length * 8 > S.imgData.data.length * 0.75) throw new Error('Payload too large');
    
    setPg('img-pg', 'img-pf', 30, 'Injecting...'); await slp(20);
    const pixels = new Uint8ClampedArray(S.imgData.data);
    const rgb = getRGB(pixels);
    injectL(rgb, payload);
    setRGB(pixels, rgb);
    
    setPg('img-pg', 'img-pf', 90, 'Rendering...'); await slp(20);
    const w = S.imgData.width, h = S.imgData.height;
    const sc = document.getElementById('cv-stg');
    sc.width = w; sc.height = h;
    const stegoImageData = new ImageData(pixels, w, h);
    sc.getContext('2d').putImageData(stegoImageData, 0, 0);
    S.stegoImgData = stegoImageData;
    
    setPg('img-pg', 'img-pf', 100, 'Done!');
    document.getElementById('img-prev').style.display = 'block';
    document.getElementById('img-dl').classList.add('show');
    showSt('img-est', 'ok', '✓ Injected successfully');
  } catch (err) { showSt('img-est', 'err', '✕ ' + err.message); }
  finally { setTimeout(() => document.getElementById('img-pg').classList.remove('on'), 2500); }
}

function dlImg() {
  if (!S.stegoImgData) return;
  const canvas = document.createElement('canvas');
  canvas.width = S.stegoImgData.width; canvas.height = S.stegoImgData.height;
  canvas.getContext('2d').putImageData(S.stegoImgData, 0, 0);
  canvas.toBlob(blob => dl(URL.createObjectURL(blob), 'stego_' + (S.imgFile?.name.replace(/\.[^.]+$/, '') || 'image') + '.png'), 'image/png');
}

function loadDImg(file) {
  if (!file) return;
  S.decImgFile = file;
  document.getElementById('ft-imgd-n').textContent = file.name;
  document.getElementById('ft-imgd').classList.add('show');
}

function decImg() {
  if (!S.decImgFile) return showSt('imgd-st', 'err', 'Select stego image');
  const password = document.getElementById('imgd-pwd').value;
  if (!password) return showSt('imgd-st', 'err', 'Enter password');
  
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = img.width; canvas.height = img.height;
        canvas.getContext('2d').drawImage(img, 0, 0);
        const pixels = canvas.getContext('2d').getImageData(0, 0, img.width, img.height).data;
        const rgb = getRGB(pixels);
        
        const header = extractL(rgb, 4, 0);
        const msgLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
        if (msgLength <= 0 || msgLength > rgb.length / 8 - 4) throw new Error('No data found');
        
        const dataBytes = extractL(rgb, msgLength, 32);
        const decrypted = aesD(new TextDecoder().decode(dataBytes), password);
        renderDec(decrypted, 'imgd');
        showSt('imgd-st', 'ok', '✓ Extracted successfully');
      } catch (err) { showSt('imgd-st', 'err', '✕ ' + err.message); }
    };
    img.onerror = () => showSt('imgd-st', 'err', 'Failed to load image');
    img.src = e.target.result;
  };
  reader.readAsDataURL(S.decImgFile);
}

/* ════════════════════════════════════════
   7. AUDIO ENGINE
════════════════════════════════════════ */
function loadCAud(file) {
  if (!file) return;
  S.audFile = file;
  document.getElementById('ft-aud-n').textContent = file.name;
  document.getElementById('ft-aud-s').textContent = fmtB(file.size);
  document.getElementById('ft-aud').classList.add('show');
  
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      const ctx = new AudioCtx();
      const audioBuffer = await ctx.decodeAudioData(e.target.result.slice(0));
      ctx.close();
      
      const sampleRate = audioBuffer.sampleRate, channels = audioBuffer.numberOfChannels, totalSamples = audioBuffer.length * channels;
      const samples = new Int16Array(totalSamples);
      let index = 0;
      const channelData = [];
      for (let ch = 0; ch < channels; ch++) channelData.push(audioBuffer.getChannelData(ch));
      for (let i = 0; i < audioBuffer.length; i++) {
        for (let ch = 0; ch < channels; ch++) {
          samples[index++] = Math.max(-32768, Math.min(32767, Math.round(channelData[ch][i] * 32767)));
        }
      }
      
      S.audSamples = samples; S.audSR = sampleRate; S.audCh = channels; S.audCapBytes = Math.floor(totalSamples / 8) - 8;
      document.getElementById('aud-sr').textContent = sampleRate.toLocaleString() + ' Hz';
      document.getElementById('aud-ch').textContent = channels + (channels === 1 ? ' (Mono)' : ' (Stereo)');
      document.getElementById('aud-cap').textContent = fmtB(S.audCapBytes);
      document.getElementById('aud-chips').style.display = 'flex';
      updCap('aud');
    } catch (err) { showSt('aud-est', 'err', '✕ Decode failed: ' + err.message); }
  };
  reader.readAsArrayBuffer(file);
}

function clearCAud() {
  S.audFile = null; S.audSamples = null; S.audCapBytes = 0;
  document.getElementById('ft-aud').classList.remove('show');
  document.getElementById('aud-chips').style.display = 'none';
  document.getElementById('inp-aud').value = '';
  updCap('aud');
}

async function encAud() {
  if (!S.audSamples) return showSt('aud-est', 'err', 'Select carrier audio');
  const password = document.getElementById('aud-pwd').value;
  if (!password) return showSt('aud-est', 'err', 'Enter password');
  
  setPg('aud-pg', 'aud-pf', 0, 'Encrypting...'); await slp(30);
  try {
    const encrypted = await packP('aud', password);
    const payload = buildBuf(encrypted);
    if (payload.length * 8 > S.audSamples.length) throw new Error('Payload too large');
    
    setPg('aud-pg', 'aud-pf', 20, 'Injecting...'); await slp(20);
    const samples = new Int16Array(S.audSamples);
    for (let i = 0; i < payload.length; i++) {
      const byte = payload[i];
      for (let bit = 7; bit >= 0; bit--) {
        const sampleIndex = i * 8 + (7 - bit);
        if (sampleIndex >= samples.length) throw new Error('Capacity exceeded');
        samples[sampleIndex] = (samples[sampleIndex] & ~1) | ((byte >> bit) & 1);
      }
    }
    setPg('aud-pg', 'aud-pf', 95, 'Building WAV...'); await slp(20);
    S.stegoAudBlob = mkWav(samples, S.audSR, S.audCh);
    setPg('aud-pg', 'aud-pf', 100, 'Done!');
    document.getElementById('aud-dl').classList.add('show');
    showSt('aud-est', 'ok', '✓ Injected — 16-bit PCM WAV');
  } catch (err) { showSt('aud-est', 'err', '✕ ' + err.message); }
  finally { setTimeout(() => document.getElementById('aud-pg').classList.remove('on'), 2500); }
}

function mkWav(samples, sampleRate, channels) {
  const dataBytes = samples.length * 2;
  const buffer = new ArrayBuffer(44 + dataBytes);
  const view = new DataView(buffer);
  const writeStr = (offset, str) => { for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i)); };
  
  writeStr(0, 'RIFF'); view.setUint32(4, 36 + dataBytes, true); writeStr(8, 'WAVE');
  writeStr(12, 'fmt '); view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, channels, true);
  view.setUint32(24, sampleRate, true); view.setUint32(28, sampleRate * channels * 2, true);
  view.setUint16(32, channels * 2, true); view.setUint16(34, 16, true);
  writeStr(36, 'data'); view.setUint32(40, dataBytes, true);
  new Int16Array(buffer, 44).set(samples);
  return new Blob([buffer], { type: 'audio/wav' });
}

function dlAud() {
  if (!S.stegoAudBlob) return;
  dl(URL.createObjectURL(S.stegoAudBlob), 'stego_' + (S.audFile?.name.replace(/\.[^.]+$/, '') || 'audio') + '.wav');
}

function loadDAud(file) {
  if (!file) return;
  S.decAudFile = file;
  document.getElementById('ft-audd-n').textContent = file.name;
  document.getElementById('ft-audd').classList.add('show');
}

function decAud() {
  if (!S.decAudFile) return showSt('audd-st', 'err', 'Select stego WAV');
  const password = document.getElementById('audd-pwd').value;
  if (!password) return showSt('audd-st', 'err', 'Enter password');
  
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const buffer = e.target.result; const view = new DataView(buffer);
      if (view.getUint32(0, false) !== 0x52494646 || view.getUint32(8, false) !== 0x57415645) throw new Error('Not a valid WAV');
      let offset = 12, dataOffset = 0, dataSize = 0;
      while (offset < view.byteLength - 8) {
        const chunkId = view.getUint32(offset, false);
        const chunkSize = view.getUint32(offset + 4, true);
        offset += 8;
        if (chunkId === 0x64617461) { dataOffset = offset; dataSize = chunkSize; break; }
        offset += chunkSize + (chunkSize % 2);
      }
      if (!dataOffset) throw new Error('Audio data missing');
      
      const samples = new Int16Array(buffer.slice(dataOffset, dataOffset + dataSize));
      const header = new Uint8Array(4);
      for (let i = 0; i < 32; i++) header[Math.floor(i / 8)] |= (samples[i] & 1) << (7 - (i % 8));
      const msgLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
      if (msgLength <= 0 || msgLength > samples.length / 8 - 4) throw new Error('No data found');
      
      const data = new Uint8Array(msgLength);
      for (let i = 0; i < msgLength * 8; i++) data[Math.floor(i / 8)] |= (samples[32 + i] & 1) << (7 - (i % 8));
      
      renderDec(aesD(new TextDecoder().decode(data), password), 'audd');
      showSt('audd-st', 'ok', '✓ Extraction successful');
    } catch (err) { showSt('audd-st', 'err', '✕ ' + err.message); }
  };
  reader.readAsArrayBuffer(S.decAudFile);
}

/* ════════════════════════════════════════
   8. VIDEO ENGINE (EOF)
════════════════════════════════════════ */
function loadCVid(file) {
  if (!file) return;
  S.vidFile = file;
  document.getElementById('ft-vid-n').textContent = file.name;
  document.getElementById('ft-vid-s').textContent = fmtB(file.size);
  document.getElementById('ft-vid').classList.add('show');
  document.getElementById('vid-fsize').textContent = fmtB(file.size);
  document.getElementById('vid-type').textContent = (file.name.split('.').pop() || 'video').toUpperCase();
  document.getElementById('vid-chips').style.display = 'flex';
  updCap('vid');
}

function clearCVid() {
  S.vidFile = null; document.getElementById('ft-vid').classList.remove('show');
  document.getElementById('vid-chips').style.display = 'none'; document.getElementById('inp-vid').value = '';
}

async function encVid() {
  if (!S.vidFile) return showSt('vid-est', 'err', 'Select video');
  const password = document.getElementById('vid-pwd').value;
  if (!password) return showSt('vid-est', 'err', 'Enter password');
  
  setPg('vid-pg', 'vid-pf', 0, 'Encrypting...'); await slp(30);
  try {
    const encrypted = await packP('vid', password);
    const encBytes = new TextEncoder().encode(encrypted);
    
    setPg('vid-pg', 'vid-pf', 35, 'Reading...'); await slp(20);
    const videoBuffer = await S.vidFile.arrayBuffer();
    
    setPg('vid-pg', 'vid-pf', 65, 'Appending...'); await slp(20);
    const totalSize = videoBuffer.byteLength + VID_MAGIC.length + 4 + encBytes.length;
    const output = new Uint8Array(totalSize);
    output.set(new Uint8Array(videoBuffer), 0);
    output.set(VID_MAGIC, videoBuffer.byteLength);
    
    new DataView(output.buffer).setUint32(videoBuffer.byteLength + VID_MAGIC.length, encBytes.length, false);
    output.set(encBytes, videoBuffer.byteLength + VID_MAGIC.length + 4);
    
    setPg('vid-pg', 'vid-pf', 95, 'Finalizing...'); await slp(20);
    S.stegoVidBlob = new Blob([output], { type: S.vidFile.type || 'video/mp4' });
    setPg('vid-pg', 'vid-pf', 100, 'Done!');
    document.getElementById('vid-dl').classList.add('show');
    showSt('vid-est', 'ok', '✓ Embedded');
  } catch (err) { showSt('vid-est', 'err', '✕ ' + err.message); }
  finally { setTimeout(() => document.getElementById('vid-pg').classList.remove('on'), 2500); }
}

function dlVid() {
  if (!S.stegoVidBlob) return;
  dl(URL.createObjectURL(S.stegoVidBlob), 'stego_' + (S.vidFile?.name || 'video.mp4'));
}

function loadDVid(file) {
  if (!file) return; S.decVidFile = file;
  document.getElementById('ft-vidd-n').textContent = file.name;
  document.getElementById('ft-vidd').classList.add('show');
}

async function decVid() {
  if (!S.decVidFile) return showSt('vidd-st', 'err', 'Select stego video');
  const password = document.getElementById('vidd-pwd').value;
  if (!password) return showSt('vidd-st', 'err', 'Enter password');
  
  try {
    const buffer = await S.decVidFile.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const ml = VID_MAGIC.length;
    let magicPos = -1;
    const searchStart = Math.max(0, bytes.length - ml - 4 - (10 * 1024 * 1024));
    
    for (let i = bytes.length - ml - 4; i >= searchStart; i--) {
      let found = true;
      for (let j = 0; j < ml; j++) { if (bytes[i + j] !== VID_MAGIC[j]) { found = false; break; } }
      if (found) { magicPos = i; break; }
    }
    if (magicPos === -1) throw new Error('No hidden data found');
    
    const payloadOff = magicPos + ml;
    const payloadLen = new DataView(buffer).getUint32(payloadOff, false);
    if (payloadLen <= 0 || payloadLen > bytes.length - payloadOff - 4) throw new Error('Corrupted payload');
    
    const encBytes = bytes.slice(payloadOff + 4, payloadOff + 4 + payloadLen);
    renderDec(aesD(new TextDecoder().decode(encBytes), password), 'vidd');
    showSt('vidd-st', 'ok', '✓ Extraction successful');
  } catch (err) { showSt('vidd-st', 'err', '✕ ' + err.message); }
}

/* ════════════════════════════════════════
   9. UI HELPERS & OUTPUT
════════════════════════════════════════ */
function renderDec(decrypted, prefix) {
  const result = unpackD(decrypted);
  const outputEl = document.getElementById(prefix + '-out');
  const dlEl = document.getElementById(prefix + '-fres');
  if (result.type === 'text') {
    outputEl.innerHTML = `<span>${esc(result.text)}</span><button class="cpbtn" onclick="doCopy('${prefix}-out')">COPY</button>`;
    if (dlEl) dlEl.classList.remove('show');
  } else {
    outputEl.innerHTML = '<span class="out-ph">Hidden payload is a file — download below</span>';
    if (dlEl) {
      dlEl.classList.add('show');
      document.getElementById(prefix + '-fn').textContent = result.name;
      document.getElementById(prefix + '-fb').onclick = () => dl(URL.createObjectURL(new Blob([result.bytes], { type: gMime(result.name) })), result.name);
    }
  }
}

function gMime(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  const mimeMap = { pdf: 'application/pdf', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', txt: 'text/plain', zip: 'application/zip', png: 'image/png', jpg: 'image/jpeg', mp3: 'audio/mpeg', mp4: 'video/mp4' };
  return mimeMap[ext] || 'application/octet-stream';
}

function showSt(id, type, msg) {
  const el = document.getElementById(id);
  el.className = 'st on ' + type;
  el.textContent = msg;
}

function setPg(wrapperId, fillId, percent, label) {
  const wrapper = document.getElementById(wrapperId);
  wrapper.classList.add('on');
  document.getElementById(fillId).style.width = percent + '%';
  const labelEl = wrapper.querySelector('.pglbl');
  if (labelEl) labelEl.textContent = label;
}

function fmtB(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

function esc(str) { return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function dl(url, filename) {
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click();
}

function doCopy(elementId) {
  const el = document.getElementById(elementId);
  const text = el.querySelector('span')?.textContent || el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = el.querySelector('.cpbtn');
    if (btn) { btn.textContent = '✓'; setTimeout(() => { btn.textContent = 'COPY'; }, 1500); }
  });
}

function slp(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
