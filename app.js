/* ================================================================
   CipherStegano Suite — Main Application Logic
   File    : app.js
   Version : 5.0

   Table of Contents:
     1.  Global State
     2.  Constants
     3.  Navigation  (switchMedia, switchMode)
     4.  Drag & Drop Helpers
     5.  Payload Type Toggle  (setPT, loadSF, clearSF)
     6.  AES-256-CBC Encryption  (aesE, aesD)
     7.  Payload Packing  (packP, unpackD)
     8.  Binary Helpers  (ab2b64, b642ab)
     9.  LSB (Least Significant Bit) Helpers
    10.  Capacity Updater  (updCap)
    11.  Image Engine  (load, encode, decode, download)
    12.  Audio Engine  (load, encode, decode, download)
    13.  Video Engine — EOF Embed  (load, encode, decode, download)
    14.  Output Rendering  (renderDec, gMime)
    15.  UI Utilities  (showSt, setPg, fmtB, esc, dl, doCopy, slp)
================================================================ */

'use strict';


/* ────────────────────────────────────────
   1. GLOBAL STATE
   Single object that holds all runtime
   data so nothing leaks into global scope.
──────────────────────────────────────── */
const S = {

  /* ── Image carrier ── */
  imgFile      : null,      // Original File object
  imgData      : null,      // ImageData from Canvas API
  imgCapBytes  : 0,         // Max bytes the image can hold
  stegoImgData : null,      // ImageData after LSB injection

  /* ── Audio carrier ── */
  audFile      : null,      // Original File object
  audSamples   : null,      // Int16Array of PCM samples
  audSR        : 0,         // Sample rate (Hz)
  audCh        : 0,         // Number of channels
  audCapBytes  : 0,         // Max bytes the audio can hold
  stegoAudBlob : null,      // WAV Blob after injection

  /* ── Video carrier ── */
  vidFile      : null,      // Original File object
  stegoVidBlob : null,      // Video Blob after EOF embed

  /* ── Payload type per panel ('text' | 'file') ── */
  imgPT : 'text',
  audPT : 'text',
  vidPT : 'text',

  /* ── Secret file (when payload type = 'file') ── */
  imgSF : null,
  audSF : null,
  vidSF : null,

  /* ── Stego files loaded for decoding ── */
  decImgFile : null,
  decAudFile : null,
  decVidFile : null,
};


/* ────────────────────────────────────────
   2. CONSTANTS
──────────────────────────────────────── */

/**
 * Magic signature appended to videos during EOF embedding.
 * Bytes spell "CSGANO_V1" in ASCII.
 * Used to locate the payload when decoding.
 */
const VID_MAGIC = new Uint8Array([
  0x43, 0x53, 0x47, 0x41, 0x4E, 0x4F, 0x5F, 0x56, 0x31
]);


/* ════════════════════════════════════════
   3. NAVIGATION
   Controls which media panel is visible
   and which mode (encode/decode) is active.
════════════════════════════════════════ */

/**
 * Show the selected media panel and highlight its tab.
 * @param {string} m - Media type: 'img' | 'aud' | 'vid'
 */
function switchMedia(m) {
  ['img', 'aud', 'vid'].forEach(t => {
    document.getElementById('panel-' + t).classList.toggle('on', t === m);
    document.getElementById('mt-'    + t).classList.toggle('active', t === m);
  });
}

/**
 * Toggle between Encode and Decode sections inside a panel.
 * @param {string} panel - Panel ID: 'img' | 'aud' | 'vid'
 * @param {string} mode  - 'enc' | 'dec'
 */
function switchMode(panel, mode) {
  const wrapper = document.getElementById('panel-' + panel);

  /* Update active state on the toggle buttons */
  wrapper.querySelectorAll('.mbtn').forEach((btn, i) => {
    btn.classList.toggle('active', i === (mode === 'enc' ? 0 : 1));
  });

  /* Show / hide the correct section */
  wrapper.querySelectorAll('.enc-sec').forEach(el => {
    el.style.display = mode === 'enc' ? 'block' : 'none';
  });
  wrapper.querySelectorAll('.dec-sec').forEach(el => {
    el.style.display = mode === 'dec' ? 'block' : 'none';
  });
}


/* ════════════════════════════════════════
   4. DRAG & DROP HELPERS
════════════════════════════════════════ */

/**
 * Called on dragover — prevents default browser behaviour
 * and adds the visual 'over' class.
 * @param {DragEvent} e
 * @param {string}    id - Drop zone element ID
 */
function dzO(e, id) {
  e.preventDefault();
  document.getElementById(id).classList.add('over');
}

/**
 * Called on dragleave — removes the 'over' class.
 * @param {string} id - Drop zone element ID
 */
function dzL(id) {
  document.getElementById(id).classList.remove('over');
}

/**
 * Called on drop — extracts the dropped file and passes it
 * to the appropriate loader callback.
 * @param {DragEvent} e
 * @param {string}    id       - Drop zone element ID
 * @param {Function}  callback - File loader function to call
 */
function dzD(e, id, callback) {
  e.preventDefault();
  dzL(id);
  const file = e.dataTransfer.files[0];
  if (file) callback(file);
}


/* ════════════════════════════════════════
   5. PAYLOAD TYPE TOGGLE
   Handles switching between Text and File
   payload modes for each media panel.
════════════════════════════════════════ */

/**
 * Switch the payload type for a given panel.
 * @param {string} panel - 'img' | 'aud' | 'vid'
 * @param {string} type  - 'text' | 'file'
 */
function setPT(panel, type) {
  S[panel + 'PT'] = type;

  /* Map panel ID to its button prefix */
  const prefix = { img: 'i', aud: 'a', vid: 'v' }[panel];

  /* Update toggle button styles */
  document.getElementById(prefix + 'pt-t').classList.toggle('active', type === 'text');
  document.getElementById(prefix + 'pt-f').classList.toggle('active', type === 'file');

  /* Show/hide the correct input area */
  document.getElementById(panel + '-tp').style.display = type === 'text' ? 'block' : 'none';
  document.getElementById(panel + '-fp').style.display = type === 'file' ? 'block' : 'none';

  updCap(panel);
}

/**
 * Load a secret file (to be hidden inside the carrier).
 * @param {File}   file  - The file the user selected
 * @param {string} panel - 'img' | 'aud' | 'vid'
 */
function loadSF(file, panel) {
  if (!file) return;

  S[panel + 'SF'] = file;
  document.getElementById('sft-' + panel + '-n').textContent = file.name;
  document.getElementById('sft-' + panel + '-s').textContent = fmtB(file.size);
  document.getElementById('sft-' + panel).classList.add('show');

  updCap(panel);
}

/**
 * Clear the selected secret file for a panel.
 * @param {string} panel - 'img' | 'aud' | 'vid'
 */
function clearSF(panel) {
  S[panel + 'SF'] = null;
  document.getElementById('sft-' + panel).classList.remove('show');

  /* Reset the file input element */
  const inputIds = { img: 'inp-si', aud: 'inp-sa', vid: 'inp-sv' };
  document.getElementById(inputIds[panel]).value = '';

  updCap(panel);
}


/* ════════════════════════════════════════
   6. AES-256-CBC ENCRYPTION
   Uses CryptoJS with PBKDF2 key derivation.

   Encrypted format:
     salt (hex) : iv (hex) : ciphertext (hex)
════════════════════════════════════════ */

/**
 * Encrypt a plaintext string with AES-256-CBC.
 * A random salt and IV are generated each time for security.
 *
 * @param  {string} plaintext - The text to encrypt
 * @param  {string} password  - User-provided passphrase
 * @return {string}           - "salt:iv:ciphertext" (all hex)
 */
function aesE(plaintext, password) {
  const salt = CryptoJS.lib.WordArray.random(16);
  const key  = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
  const iv   = CryptoJS.lib.WordArray.random(16);

  const cipherResult = CryptoJS.AES.encrypt(plaintext, key, {
    iv      : iv,
    mode    : CryptoJS.mode.CBC,
    padding : CryptoJS.pad.Pkcs7,
  });

  return (
    salt.toString(CryptoJS.enc.Hex) + ':' +
    iv.toString(CryptoJS.enc.Hex)   + ':' +
    cipherResult.ciphertext.toString(CryptoJS.enc.Hex)
  );
}

/**
 * Decrypt an AES-256-CBC encrypted string.
 *
 * @param  {string} packed   - "salt:iv:ciphertext" string
 * @param  {string} password - User-provided passphrase
 * @return {string}          - Decrypted plaintext
 * @throws {Error}           - If password is wrong or data is corrupted
 */
function aesD(packed, password) {
  const parts = packed.split(':');
  if (parts.length < 3) throw new Error('Invalid data format');

  const salt = CryptoJS.enc.Hex.parse(parts[0]);
  const iv   = CryptoJS.enc.Hex.parse(parts[1]);
  const ct   = CryptoJS.enc.Hex.parse(parts.slice(2).join(':'));

  const key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });

  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: ct },
    key,
    { iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }
  );

  const result = decrypted.toString(CryptoJS.enc.Utf8);
  if (!result) throw new Error('Wrong password or corrupted data');

  return result;
}


/* ════════════════════════════════════════
   7. PAYLOAD PACKING
   Before encryption, the payload is given
   a type prefix so we know on decode
   whether it was a text message or a file.

   Format:
     Text: "__T__" + message
     File: "__F__:" + filename + ":" + base64data
════════════════════════════════════════ */

/**
 * Build and encrypt the payload for a given panel.
 * Reads either the textarea message or the loaded secret file.
 *
 * @param  {string} panel    - 'img' | 'aud' | 'vid'
 * @param  {string} password - AES password
 * @return {Promise<string>} - Encrypted payload string
 */
async function packP(panel, password) {
  let plaintext;

  if (S[panel + 'PT'] === 'text') {
    /* Text payload */
    const msg = document.getElementById(panel + '-msg').value.trim();
    if (!msg) throw new Error('Please enter a message');
    plaintext = '__T__' + msg;

  } else {
    /* File payload — encode as base64 */
    const file = S[panel + 'SF'];
    if (!file) throw new Error('Please select a secret file');

    const arrayBuffer = await file.arrayBuffer();
    plaintext = '__F__:' + file.name + ':' + ab2b64(arrayBuffer);
  }

  return aesE(plaintext, password);
}

/**
 * Parse a decrypted plaintext string back into a payload object.
 *
 * @param  {string} decrypted - Decrypted string from aesD()
 * @return {{ type: 'text', text: string }
 * | { type: 'file', name: string, bytes: ArrayBuffer }}
 */
function unpackD(decrypted) {
  if (decrypted.startsWith('__T__')) {
    /* Text payload */
    return { type: 'text', text: decrypted.slice(5) };
  }

  if (decrypted.startsWith('__F__:')) {
    /* File payload — split at the last colon to get name and data */
    const rest          = decrypted.slice(6);
    const lastColon     = rest.lastIndexOf(':');
    const filename      = rest.slice(0, lastColon);
    const base64data    = rest.slice(lastColon + 1);
    return { type: 'file', name: filename, bytes: b642ab(base64data) };
  }

  /* Fallback: treat as plain text (legacy compatibility) */
  return { type: 'text', text: decrypted };
}


/* ════════════════════════════════════════
   8. BINARY HELPERS
   Convert between ArrayBuffer and Base64.
════════════════════════════════════════ */

/**
 * Convert an ArrayBuffer to a Base64 string.
 * @param  {ArrayBuffer} buffer
 * @return {string} Base64 string
 */
function ab2b64(buffer) {
  const bytes  = new Uint8Array(buffer);
  let   binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert a Base64 string back to an ArrayBuffer.
 * @param  {string}      base64
 * @return {ArrayBuffer}
 */
function b642ab(base64) {
  const binary = atob(base64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}


/* ════════════════════════════════════════
   9. LSB (LEAST SIGNIFICANT BIT) HELPERS
   Core steganography engine for image/audio.

   How it works:
     Each byte in the carrier has 8 bits.
     We only change the LAST bit (bit 0),
     which changes the byte value by at most 1.
     This delta is imperceptible to human eyes
     or ears, but stores 1 bit of secret data.

     To store 1 byte (8 bits) of secret data
     we need 8 carrier bytes.
════════════════════════════════════════ */

/**
 * Build a binary buffer:  [4-byte length header] + [payload bytes]
 * The 32-bit big-endian length header lets the decoder know
 * exactly how many bytes to extract.
 *
 * @param  {string}     encryptedStr - The encrypted payload string
 * @return {Uint8Array}              - Length-prefixed byte array
 */
function buildBuf(encryptedStr) {
  const data   = new TextEncoder().encode(encryptedStr);
  const buffer = new Uint8Array(4 + data.length);
  const len    = data.length;

  /* Write 32-bit big-endian length */
  buffer[0] = (len >> 24) & 0xFF;
  buffer[1] = (len >> 16) & 0xFF;
  buffer[2] = (len >>  8) & 0xFF;
  buffer[3] =  len        & 0xFF;

  buffer.set(data, 4);
  return buffer;
}

/**
 * Extract the RGB channels from a flat RGBA pixel array.
 * Alpha channel is skipped — modifying alpha causes visible artefacts.
 *
 * @param  {Uint8ClampedArray} pixelData - Flat RGBA array from ImageData
 * @return {Uint8Array}                  - RGB-only byte array
 */
function getRGB(pixelData) {
  const rgb = new Uint8Array((pixelData.length / 4) * 3);
  let j = 0;
  for (let i = 0; i < pixelData.length; i += 4) {
    rgb[j++] = pixelData[i    ]; // R
    rgb[j++] = pixelData[i + 1]; // G
    rgb[j++] = pixelData[i + 2]; // B
    // pixelData[i + 3] = Alpha — intentionally skipped
  }
  return rgb;
}

/**
 * Write modified RGB values back into a flat RGBA pixel array.
 * @param {Uint8ClampedArray} pixelData - Flat RGBA array (modified in place)
 * @param {Uint8Array}        rgb       - Modified RGB-only values
 */
function setRGB(pixelData, rgb) {
  let j = 0;
  for (let i = 0; i < pixelData.length; i += 4) {
    pixelData[i    ] = rgb[j++]; // R
    pixelData[i + 1] = rgb[j++]; // G
    pixelData[i + 2] = rgb[j++]; // B
    // Alpha is left unchanged
  }
}

/**
 * Inject (hide) a byte array into a carrier array using LSB.
 * Each bit of the payload replaces the LSB of a carrier byte.
 *
 * @param {Uint8Array | Int16Array} carrier - The carrier bytes (modified in place)
 * @param {Uint8Array}              payload - The secret bytes to hide
 */
function injectL(carrier, payload) {
  let carrierIndex = 0;
  for (let i = 0; i < payload.length; i++) {
    const byte = payload[i];
    /* Process each bit from MSB (bit 7) to LSB (bit 0) */
    for (let bit = 7; bit >= 0; bit--) {
      if (carrierIndex >= carrier.length) throw new Error('Capacity exceeded');
      /* Clear the LSB and set it to the payload bit */
      carrier[carrierIndex] = (carrier[carrierIndex] & 0xFE) | ((byte >> bit) & 1);
      carrierIndex++;
    }
  }
}

/**
 * Extract hidden bytes from a carrier array using LSB.
 *
 * @param  {Uint8Array | Int16Array} carrier   - The carrier bytes
 * @param  {number}                  numBytes  - Number of bytes to extract
 * @param  {number}                  [startBit=0] - Bit offset to start reading from
 * @return {Uint8Array}                        - Extracted secret bytes
 */
function extractL(carrier, numBytes, startBit = 0) {
  const output = new Uint8Array(numBytes);

  for (let i = 0; i < numBytes; i++) {
    let byte = 0;
    for (let bit = 7; bit >= 0; bit--) {
      const carrierIndex = startBit + (i * 8) + (7 - bit);
      if (carrierIndex < carrier.length) {
        byte |= (carrier[carrierIndex] & 1) << bit;
      }
    }
    output[i] = byte;
  }

  return output;
}


/* ════════════════════════════════════════
   10. CAPACITY UPDATER
   Calculates how much of the carrier's
   available space the current payload uses,
   and updates the capacity bar in the UI.
════════════════════════════════════════ */

/**
 * Update the capacity bar and noise indicator for a panel.
 * @param {string} panel - 'img' | 'aud' | 'vid'
 */
function updCap(panel) {
  let payloadBytes = 0;

  if (S[panel + 'PT'] === 'text') {
    /* Count UTF-8 bytes of the current message */
    const msg = document.getElementById(panel + '-msg')?.value || '';
    payloadBytes = new TextEncoder().encode(msg).length;
  } else {
    /* File payload: base64 encoding adds ~38% overhead */
    payloadBytes = Math.ceil((S[panel + 'SF']?.size || 0) * 1.38);
  }

  /* Add ~80 bytes for the AES encryption header (salt + IV + padding) */
  payloadBytes += 80;

  const capacity   = panel === 'img' ? S.imgCapBytes
                   : panel === 'aud' ? S.audCapBytes
                   : Infinity;

  const percentage = (isFinite(capacity) && capacity > 0)
                   ? Math.min(100, (payloadBytes / capacity) * 100)
                   : (payloadBytes > 0 ? 5 : 0);

  /* Update the label text */
  const label = document.getElementById(panel + '-clbl');
  if (label) {
    label.textContent = (isFinite(capacity) && capacity > 0)
      ? `${fmtB(payloadBytes)} of ${fmtB(capacity)} (${percentage.toFixed(1)}%)`
      : fmtB(payloadBytes);
  }

  /* Update the fill bar width and state class */
  const fill = document.getElementById(panel + '-cf');
  if (fill) {
    fill.style.width  = Math.min(percentage, 100) + '%';
    fill.className    = 'cap-fill'
      + (percentage > 90 ? ' full' : percentage > 70 ? ' warn' : '');
  }

  /* Image-only: update noise level display */
  if (panel === 'img') {
    const noiseEl = document.getElementById('img-noise');
    if (noiseEl) {
      const noiseRatio = (percentage / 100) * 0.0039;
      noiseEl.textContent = (capacity > 0)
        ? `${(noiseRatio * 100).toFixed(4)}%`
        : '—';
    }
  }
}


/* ════════════════════════════════════════
   11. IMAGE ENGINE
   Uses the HTML5 Canvas API to read and
   write pixel data for LSB steganography.

   Steps:
     Encode: File → Image → Canvas → ImageData
             → extract RGB → inject LSB → redraw
     Decode: File → Image → Canvas → ImageData
             → extract RGB → read LSB → decrypt
════════════════════════════════════════ */

/**
 * Load a carrier image into the Canvas and extract its ImageData.
 * Displays metadata chips and a status message.
 * @param {File} file - Any image format (PNG, JPG, WebP, BMP…)
 */
function loadCImg(file) {
  if (!file || !file.type.startsWith('image/')) {
    showSt('img-est', 'err', 'This file type is not a supported image');
    return;
  }

  S.imgFile = file;
  const reader = new FileReader();

  reader.onload = (e) => {
    const img = new Image();

    img.onload = () => {
      const w = img.width;
      const h = img.height;

      /* Draw to an off-screen canvas to access pixel data */
      const canvas = document.createElement('canvas');
      canvas.width  = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      S.imgData     = ctx.getImageData(0, 0, w, h);
      S.imgCapBytes = Math.floor((w * h * 3) / 8) - 8; // 3 channels, 1 bit each

      /* Display original on the comparison canvas */
      const origCanvas = document.getElementById('cv-orig');
      origCanvas.width  = w;
      origCanvas.height = h;
      origCanvas.getContext('2d').putImageData(S.imgData, 0, 0);

      /* Update file tag */
      document.getElementById('ftimg-n').textContent = file.name;
      document.getElementById('ftimg-s').textContent = fmtB(file.size);
      document.getElementById('ftimg').classList.add('show');

      /* Update metadata chips */
      document.getElementById('img-dims').textContent  = `${w} × ${h} px`;
      document.getElementById('img-cap').textContent   = fmtB(S.imgCapBytes);
      document.getElementById('img-fsize').textContent = fmtB(file.size);
      document.getElementById('img-type').textContent  = file.type.split('/').pop().toUpperCase();
      document.getElementById('img-chips').style.display = 'flex';

      /* Warn if the image format is lossy (LSB won't survive re-compression) */
      if (!['image/png', 'image/bmp'].includes(file.type)) {
        showSt('img-est', 'info', 'Output will be saved as PNG to preserve LSB data (lossless)');
      }

      updCap('img');
    };

    img.onerror = () => showSt('img-est', 'err', 'Failed to load image');
    img.src = e.target.result;
  };

  reader.readAsDataURL(file);
}

/**
 * Clear the loaded carrier image and reset the UI.
 */
function clearCImg() {
  S.imgFile      = null;
  S.imgData      = null;
  S.imgCapBytes  = 0;

  document.getElementById('ftimg').classList.remove('show');
  document.getElementById('img-chips').style.display = 'none';
  document.getElementById('img-prev').style.display  = 'none';
  document.getElementById('inp-img').value           = '';

  updCap('img');
}

/**
 * Encode (inject) the secret payload into the carrier image.
 * Uses LSB injection on RGB channels only.
 */
async function encImg() {
  if (!S.imgData) {
    showSt('img-est', 'err', 'Please select a carrier image first');
    return;
  }

  const password = document.getElementById('img-pwd').value;
  if (!password) {
    showSt('img-est', 'err', 'Please enter a password');
    return;
  }

  setPg('img-pg', 'img-pf', 0, 'Encrypting payload...');
  await slp(30);

  try {
    /* Step 1: Encrypt the payload */
    const encrypted = await packP('img', password);
    const payload   = buildBuf(encrypted);

    /* Rough capacity check (1 bit per RGB byte, 75% of all pixels) */
    if (payload.length * 8 > S.imgData.data.length * 0.75) {
      throw new Error('Payload is too large for this image');
    }

    /* Step 2: Extract RGB channels, inject LSB */
    setPg('img-pg', 'img-pf', 30, 'Injecting into RGB channels...');
    await slp(20);

    const pixels = new Uint8ClampedArray(S.imgData.data);
    const rgb    = getRGB(pixels);
    injectL(rgb, payload);
    setRGB(pixels, rgb);

    /* Step 3: Write modified pixels back to the stego canvas */
    setPg('img-pg', 'img-pf', 90, 'Rendering output...');
    await slp(20);

    const w  = S.imgData.width;
    const h  = S.imgData.height;
    const sc = document.getElementById('cv-stg');
    sc.width  = w;
    sc.height = h;
    const stegoImageData = new ImageData(pixels, w, h);
    sc.getContext('2d').putImageData(stegoImageData, 0, 0);
    S.stegoImgData = stegoImageData;

    setPg('img-pg', 'img-pf', 100, 'Done!');

    /* Show comparison preview and download button */
    document.getElementById('img-prev').style.display = 'block';
    document.getElementById('img-dl').classList.add('show');
    showSt('img-est', 'ok', '✓ Payload injected successfully — visually identical to original');

  } catch (err) {
    showSt('img-est', 'err', '✕ ' + err.message);
  } finally {
    setTimeout(() => document.getElementById('img-pg').classList.remove('on'), 2500);
  }
}

/**
 * Trigger download of the stego image as a lossless PNG.
 */
function dlImg() {
  if (!S.stegoImgData) return;

  /* Draw to an off-screen canvas and export as PNG */
  const canvas  = document.createElement('canvas');
  canvas.width  = S.stegoImgData.width;
  canvas.height = S.stegoImgData.height;
  canvas.getContext('2d').putImageData(S.stegoImgData, 0, 0);

  const baseName = S.imgFile?.name.replace(/\.[^.]+$/, '') || 'image';
  canvas.toBlob(
    blob => dl(URL.createObjectURL(blob), 'stego_' + baseName + '.png'),
    'image/png'
  );
}

/**
 * Load a stego image for decoding.
 * @param {File} file - The stego image
 */
function loadDImg(file) {
  if (!file) return;
  S.decImgFile = file;
  document.getElementById('ft-imgd-n').textContent = file.name;
  document.getElementById('ft-imgd').classList.add('show');
}

/**
 * Decode (extract + decrypt) the hidden payload from a stego image.
 */
function decImg() {
  if (!S.decImgFile) {
    showSt('imgd-st', 'err', 'Please select the stego image');
    return;
  }

  const password = document.getElementById('imgd-pwd').value;
  if (!password) {
    showSt('imgd-st', 'err', 'Please enter the password');
    return;
  }

  const reader = new FileReader();

  reader.onload = (e) => {
    const img = new Image();

    img.onload = () => {
      try {
        /* Draw to canvas to access pixel data */
        const canvas = document.createElement('canvas');
        canvas.width  = img.width;
        canvas.height = img.height;
        canvas.getContext('2d').drawImage(img, 0, 0);

        const pixels = canvas.getContext('2d').getImageData(0, 0, img.width, img.height).data;
        const rgb    = getRGB(pixels);

        /* Read the 4-byte length header from the first 32 bits */
        const header     = extractL(rgb, 4, 0);
        const msgLength  = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];

        if (msgLength <= 0 || msgLength > rgb.length / 8 - 4) {
          throw new Error('No hidden data found in this image');
        }

        /* Extract and decrypt the payload (starting at bit 32 = after header) */
        const dataBytes  = extractL(rgb, msgLength, 32);
        const decrypted  = aesD(new TextDecoder().decode(dataBytes), password);

        renderDec(decrypted, 'imgd');
        showSt('imgd-st', 'ok', '✓ Extraction successful');

      } catch (err) {
        showSt('imgd-st', 'err', '✕ ' + err.message);
      }
    };

    img.onerror = () => showSt('imgd-st', 'err', 'Failed to load image');
    img.src = e.target.result;
  };

  reader.readAsDataURL(S.decImgFile);
}


/* ════════════════════════════════════════
   12. AUDIO ENGINE
   Decodes any audio format to raw PCM
   via the Web Audio API, then performs
   LSB injection on each Int16 sample.
   Output is always a valid WAV file.

   Steps:
     Encode: File → FileReader → ArrayBuffer
             → AudioContext.decodeAudioData
             → Int16Array (PCM) → inject LSB
             → mkWav() → Blob

     Decode: WAV File → FileReader → ArrayBuffer
             → parse RIFF chunks → Int16Array
             → read LSB → decrypt
════════════════════════════════════════ */

/**
 * Load any audio file and decode it to 16-bit PCM samples.
 * Supports WAV, MP3, OGG, FLAC, AAC, M4A, OPUS, AIFF, etc.
 * @param {File} file - Any browser-supported audio format
 */
function loadCAud(file) {
  if (!file) return;

  S.audFile = file;
  document.getElementById('ft-aud-n').textContent = file.name;
  document.getElementById('ft-aud-s').textContent = fmtB(file.size);
  document.getElementById('ft-aud').classList.add('show');
  showSt('aud-est', 'info', 'Decoding audio to PCM...');

  const reader = new FileReader();

  reader.onload = async (e) => {
    try {
      /* Web Audio API is required for cross-format decoding */
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) throw new Error('Web Audio API not supported in this browser');

      const ctx          = new AudioCtx();
      const audioBuffer  = await ctx.decodeAudioData(e.target.result.slice(0));
      ctx.close();

      const sampleRate  = audioBuffer.sampleRate;
      const channels    = audioBuffer.numberOfChannels;
      const duration    = audioBuffer.duration;
      const totalSamples= audioBuffer.length * channels;

      /* Interleave all channels into a single Int16 array correctly */
      const samples = new Int16Array(totalSamples);
      let   index   = 0;

      // حفظ بيانات كل القنوات في مصفوفة أولاً
      const channelData = [];
      for (let ch = 0; ch < channels; ch++) {
        channelData.push(audioBuffer.getChannelData(ch));
      }

      // دمج العينات بالتناوب: يسار، يمين، يسار، يمين...
      const lengthPerChannel = audioBuffer.length;
      for (let i = 0; i < lengthPerChannel; i++) {
        for (let ch = 0; ch < channels; ch++) {
          const float32 = channelData[ch][i];
          /* Convert float32 [-1..1] to int16 [-32768..32767] */
          samples[index++] = Math.max(-32768, Math.min(32767, Math.round(float32 * 32767)));
        }
      }

      /* Store in state */
      S.audSamples   = samples;
      S.audSR        = sampleRate;
      S.audCh        = channels;
      S.audCapBytes  = Math.floor(totalSamples / 8) - 8;

      /* Update metadata chips */
      document.getElementById('aud-sr').textContent  = sampleRate.toLocaleString() + ' Hz';
      document.getElementById('aud-ch').textContent  = channels + (channels === 1 ? ' (Mono)' : ' (Stereo)');
      document.getElementById('aud-dur').textContent = duration.toFixed(1) + 's';
      document.getElementById('aud-cap').textContent = fmtB(S.audCapBytes);
      document.getElementById('aud-chips').style.display = 'flex';

      showSt('aud-est', 'ok', '✓ Decoded to PCM — ready to inject');
      updCap('aud');

    } catch (err) {
      showSt('aud-est', 'err', '✕ Decode failed: ' + err.message);
    }
  };

  reader.readAsArrayBuffer(file);
}

/**
 * Clear the loaded carrier audio and reset the UI.
 */
function clearCAud() {
  S.audFile      = null;
  S.audSamples   = null;
  S.audCapBytes  = 0;

  document.getElementById('ft-aud').classList.remove('show');
  document.getElementById('aud-chips').style.display = 'none';
  document.getElementById('inp-aud').value = '';

  updCap('aud');
}

/**
 * Encode (inject) the secret payload into the carrier audio.
 * Injects into the LSB of each Int16 PCM sample.
 */
async function encAud() {
  if (!S.audSamples) {
    showSt('aud-est', 'err', 'Please select a carrier audio file');
    return;
  }

  const password = document.getElementById('aud-pwd').value;
  if (!password) {
    showSt('aud-est', 'err', 'Please enter a password');
    return;
  }

  setPg('aud-pg', 'aud-pf', 0, 'Encrypting...');
  await slp(30);

  try {
    /* Step 1: Encrypt the payload */
    const encrypted = await packP('aud', password);
    const payload   = buildBuf(encrypted);

    if (payload.length * 8 > S.audSamples.length) {
      throw new Error('Payload too large for this audio file');
    }

    /* Step 2: Copy samples and inject LSB bit-by-bit */
    setPg('aud-pg', 'aud-pf', 20, 'Injecting into samples...');
    await slp(20);

    const samples = new Int16Array(S.audSamples);

    for (let i = 0; i < payload.length; i++) {
      const byte = payload[i];
      for (let bit = 7; bit >= 0; bit--) {
        const sampleIndex = i * 8 + (7 - bit);
        if (sampleIndex >= samples.length) throw new Error('Capacity exceeded');
        /* Clear LSB and set it to the payload bit */
        samples[sampleIndex] = (samples[sampleIndex] & ~1) | ((byte >> bit) & 1);
      }
      /* Update progress every 1000 bytes to avoid UI freeze */
      if (i % 1000 === 0) {
        setPg('aud-pg', 'aud-pf', 20 + ((i / payload.length) * 70),
          `Injecting ${((i / payload.length) * 100).toFixed(0)}%`);
      }
    }

    /* Step 3: Build the output WAV file */
    setPg('aud-pg', 'aud-pf', 95, 'Building WAV...');
    await slp(20);

    S.stegoAudBlob = mkWav(samples, S.audSR, S.audCh);

    setPg('aud-pg', 'aud-pf', 100, 'Done!');
    document.getElementById('aud-dl').classList.add('show');
    showSt('aud-est', 'ok', '✓ Injected — 16-bit PCM WAV output');

  } catch (err) {
    showSt('aud-est', 'err', '✕ ' + err.message);
  } finally {
    setTimeout(() => document.getElementById('aud-pg').classList.remove('on'), 2500);
  }
}

/**
 * Build a valid WAV file (RIFF/WAVE format) from a PCM Int16Array.
 * Writes the standard 44-byte RIFF header followed by the PCM data.
 *
 * @param  {Int16Array} samples    - 16-bit PCM audio samples
 * @param  {number}     sampleRate - Sample rate in Hz
 * @param  {number}     channels   - Number of audio channels
 * @return {Blob}                  - Valid WAV file as a Blob
 */
function mkWav(samples, sampleRate, channels) {
  const dataBytes  = samples.length * 2;           // 2 bytes per Int16 sample
  const buffer     = new ArrayBuffer(44 + dataBytes);
  const view       = new DataView(buffer);

  /* Helper to write an ASCII string at a byte offset */
  const writeStr = (offset, str) => {
    for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i));
  };

  /* RIFF chunk descriptor */
  writeStr(0, 'RIFF');
  view.setUint32(4,  36 + dataBytes, true); // File size minus 8 bytes
  writeStr(8, 'WAVE');

  /* fmt sub-chunk */
  writeStr(12, 'fmt ');
  view.setUint32(16, 16,              true); // Sub-chunk size (16 for PCM)
  view.setUint16(20, 1,               true); // Audio format (1 = PCM)
  view.setUint16(22, channels,        true);
  view.setUint32(24, sampleRate,      true);
  view.setUint32(28, sampleRate * channels * 2, true); // Byte rate
  view.setUint16(32, channels * 2,    true); // Block align
  view.setUint16(34, 16,              true); // Bits per sample

  /* data sub-chunk */
  writeStr(36, 'data');
  view.setUint32(40, dataBytes, true);

  /* Write PCM samples after the header */
  new Int16Array(buffer, 44).set(samples);

  return new Blob([buffer], { type: 'audio/wav' });
}

/**
 * Trigger download of the stego audio as a WAV file.
 */
function dlAud() {
  if (!S.stegoAudBlob) return;
  const baseName = S.audFile?.name.replace(/\.[^.]+$/, '') || 'audio';
  dl(URL.createObjectURL(S.stegoAudBlob), 'stego_' + baseName + '.wav');
}

/**
 * Load a stego WAV file for decoding.
 * @param {File} file - The stego WAV file produced during encoding
 */
function loadDAud(file) {
  if (!file) return;
  S.decAudFile = file;
  document.getElementById('ft-audd-n').textContent = file.name;
  document.getElementById('ft-audd').classList.add('show');
}

/**
 * Decode (extract + decrypt) the hidden payload from a stego WAV file.
 * Reads directly from the ArrayBuffer without Web Audio API.
 */
function decAud() {
  if (!S.decAudFile) {
    showSt('audd-st', 'err', 'Please select the stego WAV file');
    return;
  }

  const password = document.getElementById('audd-pwd').value;
  if (!password) {
    showSt('audd-st', 'err', 'Please enter the password');
    return;
  }

  const reader = new FileReader();

  reader.onload = (e) => {
    try {
      const buffer = e.target.result;
      const view   = new DataView(buffer);

      /* Validate RIFF/WAVE signature */
      if (
        view.getUint32(0,  false) !== 0x52494646 || // 'RIFF'
        view.getUint32(8,  false) !== 0x57415645    // 'WAVE'
      ) {
        throw new Error('Not a valid WAV file');
      }

      /* Walk the chunks to find the 'data' chunk */
      let offset       = 12;
      let dataOffset   = 0;
      let dataSize     = 0;

      while (offset < view.byteLength - 8) {
        const chunkId   = view.getUint32(offset, false);
        const chunkSize = view.getUint32(offset + 4, true);
        offset += 8;

        if (chunkId === 0x64617461) { // 'data'
          dataOffset = offset;
          dataSize   = chunkSize;
          break;
        }
        /* Skip past this chunk (chunks must be word-aligned) */
        offset += chunkSize + (chunkSize % 2);
      }

      if (!dataOffset) throw new Error('Audio data chunk not found');

      const samples = new Int16Array(buffer.slice(dataOffset, dataOffset + dataSize));

      /* Extract the 4-byte length header from the first 32 samples */
      const header = new Uint8Array(4);
      for (let i = 0; i < 32; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex  = 7 - (i % 8);
        header[byteIndex] |= (samples[i] & 1) << bitIndex;
      }

      const msgLength = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];

      if (msgLength <= 0 || msgLength > samples.length / 8 - 4) {
        throw new Error('No hidden data found in this file');
      }

      /* Extract the payload bytes that follow the header */
      const data = new Uint8Array(msgLength);
      for (let i = 0; i < msgLength * 8; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex  = 7 - (i % 8);
        data[byteIndex] |= (samples[32 + i] & 1) << bitIndex;
      }

      const decrypted = aesD(new TextDecoder().decode(data), password);
      renderDec(decrypted, 'audd');
      showSt('audd-st', 'ok', '✓ Extraction successful');

    } catch (err) {
      showSt('audd-st', 'err', '✕ ' + err.message);
    }
  };

  reader.readAsArrayBuffer(S.decAudFile);
}


/* ════════════════════════════════════════
   13. VIDEO ENGINE — EOF EMBEDDING
   Strategy: append the encrypted payload
   AFTER the video file's last byte with
   a 9-byte magic signature as a header.

   File layout after encoding:
     [Original video bytes]
     [VID_MAGIC - 9 bytes]
     [payload length - 4 bytes big-endian]
     [encrypted payload bytes]

   All video players (VLC, Chrome, etc.)
   stop at the format's end marker and
   ignore everything that follows, so
   the video plays perfectly.
════════════════════════════════════════ */

/**
 * Load a carrier video file.
 * @param {File} file - Any video format
 */
function loadCVid(file) {
  if (!file) return;

  S.vidFile = file;
  document.getElementById('ft-vid-n').textContent  = file.name;
  document.getElementById('ft-vid-s').textContent  = fmtB(file.size);
  document.getElementById('ft-vid').classList.add('show');
  document.getElementById('vid-fsize').textContent = fmtB(file.size);
  document.getElementById('vid-type').textContent  = (file.name.split('.').pop() || 'video').toUpperCase();
  document.getElementById('vid-chips').style.display = 'flex';

  showSt('vid-est', 'ok', '✓ Video ready — ' + fmtB(file.size));
  updCap('vid');
}

/**
 * Clear the loaded carrier video and reset the UI.
 */
function clearCVid() {
  S.vidFile = null;
  document.getElementById('ft-vid').classList.remove('show');
  document.getElementById('vid-chips').style.display = 'none';
  document.getElementById('inp-vid').value = '';
}

/**
 * Encode (embed) the secret payload into the carrier video using EOF.
 */
async function encVid() {
  if (!S.vidFile) {
    showSt('vid-est', 'err', 'Please select a carrier video');
    return;
  }

  const password = document.getElementById('vid-pwd').value;
  if (!password) {
    showSt('vid-est', 'err', 'Please enter a password');
    return;
  }

  setPg('vid-pg', 'vid-pf', 0, 'Encrypting payload...');
  await slp(30);

  try {
    /* Step 1: Encrypt the payload */
    const encrypted  = await packP('vid', password);
    const encBytes   = new TextEncoder().encode(encrypted);

    /* Step 2: Read the full video into an ArrayBuffer */
    setPg('vid-pg', 'vid-pf', 35, 'Reading video...');
    await slp(20);
    const videoBuffer = await S.vidFile.arrayBuffer();

    /* Step 3: Build the output:
         [video] + [magic] + [4-byte length] + [payload]  */
    setPg('vid-pg', 'vid-pf', 65, 'Appending after EOF...');
    await slp(20);

    const totalSize = videoBuffer.byteLength + VID_MAGIC.length + 4 + encBytes.length;
    const output    = new Uint8Array(totalSize);

    output.set(new Uint8Array(videoBuffer), 0);
    output.set(VID_MAGIC, videoBuffer.byteLength);

    /* Write payload length as 32-bit big-endian */
    const dataView   = new DataView(output.buffer);
    const payloadOff = videoBuffer.byteLength + VID_MAGIC.length;
    dataView.setUint32(payloadOff, encBytes.length, false);
    output.set(encBytes, payloadOff + 4);

    setPg('vid-pg', 'vid-pf', 95, 'Finalizing...');
    await slp(20);

    S.stegoVidBlob = new Blob([output], { type: S.vidFile.type || 'video/mp4' });

    setPg('vid-pg', 'vid-pf', 100, 'Done!');
    document.getElementById('vid-dl').classList.add('show');
    showSt('vid-est', 'ok',
      `✓ Embedded — video plays normally. Total size: ${fmtB(totalSize)}`
    );

  } catch (err) {
    showSt('vid-est', 'err', '✕ ' + err.message);
  } finally {
    setTimeout(() => document.getElementById('vid-pg').classList.remove('on'), 2500);
  }
}

/**
 * Trigger download of the stego video file.
 */
function dlVid() {
  if (!S.stegoVidBlob) return;
  dl(URL.createObjectURL(S.stegoVidBlob), 'stego_' + (S.vidFile?.name || 'video.mp4'));
}

/**
 * Load a stego video file for decoding.
 * @param {File} file - The stego video produced during encoding
 */
function loadDVid(file) {
  if (!file) return;
  S.decVidFile = file;
  document.getElementById('ft-vidd-n').textContent = file.name;
  document.getElementById('ft-vidd').classList.add('show');
}

/**
 * Decode (extract + decrypt) the hidden payload from a stego video.
 * Searches from the end of the file for the magic signature.
 */
async function decVid() {
  if (!S.decVidFile) {
    showSt('vidd-st', 'err', 'Please select the stego video file');
    return;
  }

  const password = document.getElementById('vidd-pwd').value;
  if (!password) {
    showSt('vidd-st', 'err', 'Please enter the password');
    return;
  }

  try {
    const buffer = await S.decVidFile.arrayBuffer();
    const bytes  = new Uint8Array(buffer);
    const ml     = VID_MAGIC.length;
    let   magicPos = -1;

    /* Search the last 10 MB for the magic signature (scanning backward) */
    const searchStart = Math.max(0, bytes.length - ml - 4 - (10 * 1024 * 1024));

    for (let i = bytes.length - ml - 4; i >= searchStart; i--) {
      let found = true;
      for (let j = 0; j < ml; j++) {
        if (bytes[i + j] !== VID_MAGIC[j]) { found = false; break; }
      }
      if (found) { magicPos = i; break; }
    }

    if (magicPos === -1) {
      throw new Error('No hidden data found — this video was not created with CipherStegano');
    }

    /* Read the payload length from the 4 bytes right after the magic */
    const payloadOff = magicPos + ml;
    const dataView   = new DataView(buffer);
    const payloadLen = dataView.getUint32(payloadOff, false);

    if (payloadLen <= 0 || payloadLen > bytes.length - payloadOff - 4) {
      throw new Error('Corrupted payload — length field is invalid');
    }

    /* Extract and decrypt the payload */
    const encBytes  = bytes.slice(payloadOff + 4, payloadOff + 4 + payloadLen);
    const decrypted = aesD(new TextDecoder().decode(encBytes), password);

    renderDec(decrypted, 'vidd');
    showSt('vidd-st', 'ok', '✓ Extraction successful');

  } catch (err) {
    showSt('vidd-st', 'err', '✕ ' + err.message);
  }
}


/* ════════════════════════════════════════
   14. OUTPUT RENDERING
   Parses the decoded payload and renders
   it as either a text message or a file
   download button.
════════════════════════════════════════ */

/**
 * Display the decoded payload in the UI.
 * If it is text: show it in the output box.
 * If it is a file: show a download button.
 *
 * @param {string} decrypted - Decrypted plaintext from aesD()
 * @param {string} prefix    - Element ID prefix: 'imgd' | 'audd' | 'vidd'
 */
function renderDec(decrypted, prefix) {
  const result   = unpackD(decrypted);
  const outputEl = document.getElementById(prefix + '-out');
  const dlEl     = document.getElementById(prefix + '-fres');

  if (result.type === 'text') {
    /* Render the message text */
    outputEl.innerHTML = `
      <span>${esc(result.text)}</span>
      <button class="cpbtn" onclick="doCopy('${prefix}-out')">COPY</button>
    `;
    if (dlEl) dlEl.classList.remove('show');

  } else {
    /* File payload — show download button */
    outputEl.innerHTML = '<span class="out-ph">Hidden payload is a file — download below</span>';

    if (dlEl) {
      dlEl.classList.add('show');
      document.getElementById(prefix + '-fn').textContent = result.name;

      /* Clicking the button reconstructs and downloads the file */
      document.getElementById(prefix + '-fb').onclick = () => {
        const blob = new Blob([result.bytes], { type: gMime(result.name) });
        dl(URL.createObjectURL(blob), result.name);
      };
    }
  }
}

/**
 * Guess the MIME type of a file based on its extension.
 * @param  {string} filename
 * @return {string} MIME type string
 */
function gMime(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();

  const mimeMap = {
    /* Documents */
    pdf  : 'application/pdf',
    docx : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xlsx : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    pptx : 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    txt  : 'text/plain',
    csv  : 'text/csv',
    html : 'text/html',
    json : 'application/json',
    zip  : 'application/zip',
    /* Images */
    png  : 'image/png',
    jpg  : 'image/jpeg',
    jpeg : 'image/jpeg',
    gif  : 'image/gif',
    svg  : 'image/svg+xml',
    webp : 'image/webp',
    /* Audio */
    mp3  : 'audio/mpeg',
    wav  : 'audio/wav',
    ogg  : 'audio/ogg',
    flac : 'audio/flac',
    /* Video */
    mp4  : 'video/mp4',
    webm : 'video/webm',
    mkv  : 'video/x-matroska',
    mov  : 'video/quicktime',
    avi  : 'video/x-msvideo',
  };

  return mimeMap[ext] || 'application/octet-stream';
}


/* ════════════════════════════════════════
   15. UI UTILITIES
   Small helper functions used throughout
   the application.
════════════════════════════════════════ */

/**
 * Show or update a status message element.
 * @param {string} id   - Element ID of the .st element
 * @param {string} type - 'ok' | 'err' | 'info'
 * @param {string} msg  - Message text to display
 */
function showSt(id, type, msg) {
  const el  = document.getElementById(id);
  el.className   = 'st on ' + type;
  el.textContent = msg;
}

/**
 * Update a progress bar and its label.
 * Automatically shows the progress wrapper.
 *
 * @param {string} wrapperId - ID of the .pgwrap element
 * @param {string} fillId    - ID of the .pgfill element
 * @param {number} percent   - Progress value 0–100
 * @param {string} label     - Status label text
 */
function setPg(wrapperId, fillId, percent, label) {
  const wrapper = document.getElementById(wrapperId);
  wrapper.classList.add('on');
  document.getElementById(fillId).style.width = percent + '%';

  const labelEl = wrapper.querySelector('.pglbl');
  if (labelEl) labelEl.textContent = label;
}

/**
 * Format a byte count into a human-readable string.
 * @param  {number} bytes
 * @return {string} e.g. "1.23 MB" | "456 KB" | "89 B"
 */
function fmtB(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024)         return bytes + ' B';
  if (bytes < 1048576)      return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(2) + ' MB';
}

/**
 * Escape HTML special characters to prevent XSS when
 * inserting user-controlled text into innerHTML.
 * @param  {string} str - Raw string
 * @return {string}     - HTML-safe string
 */
function esc(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Programmatically trigger a file download in the browser.
 * @param {string} url      - Object URL or data URL
 * @param {string} filename - Suggested download filename
 */
function dl(url, filename) {
  const anchor    = document.createElement('a');
  anchor.href     = url;
  anchor.download = filename;
  anchor.click();
}

/**
 * Copy the text content of an output box to the clipboard.
 * Briefly changes the button label to "✓ COPIED" as feedback.
 * @param {string} elementId - ID of the .outbox element
 */
function doCopy(elementId) {
  const el   = document.getElementById(elementId);
  const text = el.querySelector('span')?.textContent || el.textContent;

  navigator.clipboard.writeText(text).then(() => {
    const btn = el.querySelector('.cpbtn');
    if (btn) {
      btn.textContent = '✓ COPIED';
      setTimeout(() => { btn.textContent = 'COPY'; }, 1500);
    }
  });
}

/**
 * Return a Promise that resolves after a given number of milliseconds.
 * Used to yield control back to the browser between heavy operations
 * so the UI does not freeze.
 *
 * @param  {number}  ms - Milliseconds to wait
 * @return {Promise<void>}
 */
function slp(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}