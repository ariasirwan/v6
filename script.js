'use strict';
const CryptoMod=(()=>{async function getKeyMaterial(p){return crypto.subtle.importKey('raw',new TextEncoder().encode(p),'PBKDF2',false,['deriveKey','deriveBits'])}async function encrypt(pt,pw){const salt=crypto.getRandomValues(new Uint8Array(16));const iv=crypto.getRandomValues(new Uint8Array(12));const km=await getKeyMaterial(pw);const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['encrypt']);const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,pt);const out=new Uint8Array(16+12+ct.byteLength);out.set(salt,0);out.set(iv,16);out.set(new Uint8Array(ct),28);return out}async function decrypt(eb,pw){if(eb.length<29)throw new Error('Invalid or missing payload');const salt=eb.slice(0,16);const iv=eb.slice(16,28);const ct=eb.slice(28);const km=await getKeyMaterial(pw);const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);try{const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},key,ct);return new Uint8Array(pt)}catch{throw new Error('Decryption failed — wrong password or corrupted data')}}async function derivePrngSeed(pw){const km=await getKeyMaterial(pw+'\x00steg-v2');const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:new TextEncoder().encode('cipherstegano-v2'),iterations:1000,hash:'SHA-256'},km,32);return new DataView(bits).getUint32(0)}return{encrypt,decrypt,derivePrngSeed}})();

const PayloadMod=(()=>{async function pack(t,v,f){if(t==='text'){if(!v) throw new Error('الرسالة السرية فارغة، يرجى كتابة نص');const tb=new TextEncoder().encode(v);const o=new Uint8Array(1+tb.length);o[0]=0x00;o.set(tb,1);return o}else{if(!f) throw new Error('الرجاء اختيار الملف السري أولاً');const ab=await f.arrayBuffer();const fb=new Uint8Array(ab);const nb=new TextEncoder().encode(f.name);if(nb.length>65535)throw new Error('اسم الملف طويل جداً');const o=new Uint8Array(1+2+nb.length+fb.length);o[0]=0x01;o[1]=(nb.length>>8)&0xFF;o[2]=nb.length&0xFF;o.set(nb,3);o.set(fb,3+nb.length);return o}}function unpack(b){if(!b||b.length<1)throw new Error('Empty payload');const t=b[0];if(t===0x00)return{type:'text',text:new TextDecoder().decode(b.slice(1))};if(t===0x01){const nl=(b[1]<<8)|b[2];if(3+nl>b.length)throw new Error('Corrupt file payload header');return{type:'file',name:new TextDecoder().decode(b.slice(3,3+nl)),bytes:b.slice(3+nl)}}throw new Error('Unknown payload type')}return{pack,unpack}})();

const ImageSteg=(()=>{const HP=32,HPS=Math.ceil(HP/3);function shuffleRange(n,seed){const a=new Uint32Array(n);for(let i=0;i<n;i++)a[i]=i;let s=seed>>>0;for(let i=n-1;i>0;i--){s=(Math.imul(s,1664525)+1013904223)>>>0;const j=s%(i+1);const t=a[i];a[i]=a[j];a[j]=t}return a}async function embed(id,pb,pw){const d=id.data;const np=id.width*id.height;const BS=64;const nb=Math.floor((np-HPS)/BS);const mx=Math.floor(nb*BS*3/8);if(pb.length>mx)throw new Error(`Payload (${fmtBytes(pb.length)}) exceeds image capacity (${fmtBytes(mx)})`);const len=pb.length;let hb=0;outer:for(let p=0;p<HPS;p++)for(let c=0;c<3;c++){if(hb>=32)break outer;const bit=(len>>(31-hb))&1;d[p*4+c]=(d[p*4+c]&0xFE)|bit;hb++}const seed=await CryptoMod.derivePrngSeed(pw);const bo=shuffleRange(nb,seed);const tb=pb.length*8;let bi=0;for(let blk=0;blk<nb&&bi<tb;blk++){const bps=HPS+bo[blk]*BS;for(let p=0;p<BS&&bi<tb;p++){const px=bps+p;for(let c=0;c<3&&bi<tb;c++){const bit=(pb[bi>>3]>>(7-(bi&7)))&1;d[px*4+c]=(d[px*4+c]&0xFE)|bit;bi++}}}}async function extract(id,pw){const d=id.data;const np=id.width*id.height;const BS=64;let len=0,hb=0;outer:for(let p=0;p<HPS;p++)for(let c=0;c<3;c++){if(hb>=32)break outer;len=(len<<1)|(d[p*4+c]&1);hb++}const nb=Math.floor((np-HPS)/BS);const mx=Math.floor(nb*BS*3/8);if(len<=0||len>mx)throw new Error('No hidden data detected — check password or image source');const seed=await CryptoMod.derivePrngSeed(pw);const bo=shuffleRange(nb,seed);const pl=new Uint8Array(len);const tb=len*8;let bi=0;for(let blk=0;blk<nb&&bi<tb;blk++){const bps=HPS+bo[blk]*BS;for(let p=0;p<BS&&bi<tb;p++){const px=bps+p;for(let c=0;c<3&&bi<tb;c++){pl[bi>>3]|=(d[px*4+c]&1)<<(7-(bi&7));bi++}}}return pl}function capacityBytes(w,h){const np=w*h;const BS=64;const nb=Math.floor((np-HPS)/BS);return Math.floor(nb*BS*3/8)}return{embed,extract,capacityBytes}})();

const AudioSteg=(()=>{function parseWav(buf){const v=new DataView(buf);if(v.getUint32(0,false)!==0x52494646||v.getUint32(8,false)!==0x57415645)throw new Error('Not a valid WAV file. Only uncompressed WAV PCM is supported.');let off=12,fmtOff=0,dataOff=0,dataSz=0;while(off<v.byteLength-8){const id=v.getUint32(off,false);const sz=v.getUint32(off+4,true);off+=8;if(id===0x666D7420){fmtOff=off;const af=v.getUint16(off,true);if(af!==1)throw new Error('Unsupported WAV encoding — only PCM is supported.')}else if(id===0x64617461){dataOff=off;dataSz=sz;break}off+=sz+(sz%2)}if(!dataOff)throw new Error('WAV data chunk not found');return{buffer:buf,fmtOffset:fmtOff,dataOffset:dataOff,dataSize:dataSz}}function capacityBytes(ds){return Math.floor(ds/2/8)-4}async function embed(buf,pb){const{dataOffset:do_,dataSize:ds}=parseWav(buf);const cap=capacityBytes(ds);if(pb.length>cap)throw new Error(`Payload (${fmtBytes(pb.length)}) exceeds WAV capacity (${fmtBytes(cap)})`);const out=buf.slice(0);const samp=new Int16Array(out,do_,Math.floor(ds/2));const len=pb.length;for(let b=0;b<32;b++){const bit=(len>>(31-b))&1;samp[b]=(samp[b]&~1)|bit}for(let b=0;b<pb.length*8;b++){const bit=(pb[b>>3]>>(7-(b&7)))&1;samp[32+b]=(samp[32+b]&~1)|bit}return out}async function extract(buf){const{dataOffset:do_,dataSize:ds}=parseWav(buf);const samp=new Int16Array(buf,do_,Math.floor(ds/2));let len=0;for(let b=0;b<32;b++)len=(len<<1)|(samp[b]&1);const cap=capacityBytes(ds);if(len<=0||len>cap)throw new Error('No hidden data found in this WAV file');const pl=new Uint8Array(len);for(let b=0;b<len*8;b++)pl[b>>3]|=(samp[32+b]&1)<<(7-(b&7));return pl}return{embed,extract,parseWav,capacityBytes}})();

const VideoSteg=(()=>{const MK=new Uint8Array([0xC5,0x9A,0x3F,0x01,0xE6,0x72,0x4B,0xD8,0x0F]);async function embed(vb,pb){const ts=vb.byteLength+MK.length+4+pb.length;const out=new Uint8Array(ts);out.set(new Uint8Array(vb),0);out.set(MK,vb.byteLength);new DataView(out.buffer).setUint32(vb.byteLength+MK.length,pb.length,false);out.set(pb,vb.byteLength+MK.length+4);return out.buffer}async function extract(buf){const b=new Uint8Array(buf);const ml=MK.length;const lim=Math.max(0,b.length-ml-4-(20*1024*1024));let pos=-1;for(let i=b.length-ml-4;i>=lim;i--){let f=true;for(let j=0;j<ml;j++)if(b[i+j]!==MK[j]){f=false;break}if(f){pos=i;break}}if(pos===-1)throw new Error('No hidden data found in this video file');const lo=pos+ml;const pl=new DataView(buf).getUint32(lo,false);if(pl<=0||pl>b.length-lo-4)throw new Error('Corrupted payload header');return b.slice(lo+4,lo+4+pl)}return{embed,extract}})();

const State={mode:'enc',media:'img',img:{carrierFile:null,imageData:null,capBytes:0,stegoData:null,payloadType:'text',secretFile:null},aud:{carrierFile:null,capBytes:0,stegoBuffer:null,payloadType:'text',secretFile:null},vid:{carrierFile:null,stegoBuffer:null,payloadType:'text',secretFile:null},imgd:{file:null},audd:{file:null},vidd:{file:null}};

function fmtBytes(n){if(!n||n<=0)return'0 B';if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';return(n/1048576).toFixed(2)+' MB'}
function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function mimeFor(fn){const e=(fn.split('.').pop()||'').toLowerCase();const m={pdf:'application/pdf',docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',txt:'text/plain',zip:'application/zip',png:'image/png',jpg:'image/jpeg',mp3:'audio/mpeg',mp4:'video/mp4',wav:'audio/wav'};return m[e]||'application/octet-stream'}
function triggerDownload(url,fn){const a=document.createElement('a');a.href=url;a.download=fn;a.click()}
function showStatus(id,type,msg){const el=document.getElementById(id);if(!el)return;el.className=`status show ${type}`;el.textContent=msg}
function hideStatus(id){const el=document.getElementById(id);if(el)el.className='status'}
function setProgress(wid,fid,lid,pct,lbl){const w=document.getElementById(wid);if(w)w.classList.add('show');const f=document.getElementById(fid);if(f)f.style.width=pct+'%';const l=document.getElementById(lid);if(l)l.textContent=lbl}
function hideProgress(wid){const el=document.getElementById(wid);if(el)el.classList.remove('show')}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}

function renderDecryptedOutput(payload,outId,fileResId,fileNameId,fileDlId){const oe=document.getElementById(outId);const fr=document.getElementById(fileResId);const fn=document.getElementById(fileNameId);if(payload.type==='text'){const b64Text = btoa(unescape(encodeURIComponent(payload.text))); oe.innerHTML=`${escapeHtml(payload.text)}<button class="copy-btn" data-text-b64="${b64Text}">COPY</button>`;if(fr)fr.classList.remove('show')}else{oe.innerHTML='<span class="output-placeholder">↓ File payload — download below</span>';if(fr&&fn){fr.classList.add('show');fn.textContent=payload.name;const db=document.getElementById(fileDlId);if(db)db.onclick=()=>{const blob=new Blob([payload.bytes],{type:mimeFor(payload.name)});triggerDownload(URL.createObjectURL(blob),payload.name)}}}}

function updateCapacityBar(fid,lid,used,total){const f=document.getElementById(fid);const l=document.getElementById(lid);if(!f||!l||!total){if(l)l.textContent='—';return}const pct=Math.min(100,(used/total)*100);f.style.width=pct+'%';f.className='cap-fill'+(pct>90?' over':pct>70?' warn':'');l.textContent=`${fmtBytes(used)} / ${fmtBytes(total)} (${pct.toFixed(1)}%)`}

function updateCapCurrent(panel){if(panel==='img'){const pt=State.img.payloadType;const text=document.getElementById('img-msg')?.value||'';const sf=State.img.secretFile;const used=pt==='text'?new TextEncoder().encode(text).length+1:sf?sf.size+3+new TextEncoder().encode(sf.name).length:0;updateCapacityBar('img-cap-fill','img-cap-lbl',used+28,State.img.capBytes)}else if(panel==='aud'){const pt=State.aud.payloadType;const text=document.getElementById('aud-msg')?.value||'';const sf=State.aud.secretFile;const used=pt==='text'?new TextEncoder().encode(text).length+1:sf?sf.size+3+new TextEncoder().encode(sf.name).length:0;updateCapacityBar('aud-cap-fill','aud-cap-lbl',used+28,State.aud.capBytes)}}

function loadCarrierImage(file){if(!file)return;State.img.carrierFile=file;const url=URL.createObjectURL(file);const img=new Image();img.onload=()=>{const c=document.createElement('canvas');c.width=img.width;c.height=img.height;const ctx=c.getContext('2d');ctx.drawImage(img,0,0);State.img.imageData=ctx.getImageData(0,0,img.width,img.height);State.img.capBytes=ImageSteg.capacityBytes(img.width,img.height);const oc=document.getElementById('cv-orig');if(oc){oc.width=img.width;oc.height=img.height;oc.getContext('2d').putImageData(State.img.imageData,0,0)}document.getElementById('ftag-img-name').textContent=file.name;document.getElementById('ftag-img-size').textContent=fmtBytes(file.size);document.getElementById('ftag-img').classList.add('show');document.getElementById('chip-img-dims').textContent=`${img.width}×${img.height}`;document.getElementById('chip-img-cap').textContent=fmtBytes(State.img.capBytes);document.getElementById('chip-img-fmt').textContent=(file.name.split('.').pop()||'IMG').toUpperCase();document.getElementById('chips-img').style.display='flex';updateCapCurrent('img');URL.revokeObjectURL(url)};img.onerror=()=>showStatus('st-img-enc','err','Failed to load image');img.src=url}

async function doEncodeImage(){const btn=document.getElementById('btn-img-enc');if(!State.img.carrierFile)return showStatus('st-img-enc','err','Select a carrier image first');const pwd=document.getElementById('img-pwd').value;if(!pwd)return showStatus('st-img-enc','err','Enter a password');btn.disabled=true;hideStatus('st-img-enc');setProgress('img-enc-prog','img-enc-fill','img-enc-prog-lbl',20,'Packing payload...');await sleep(20);try{const sc=document.createElement('canvas');sc.width=State.img.imageData.width;sc.height=State.img.imageData.height;const ctx=sc.getContext('2d');ctx.putImageData(State.img.imageData,0,0);const wd=ctx.getImageData(0,0,sc.width,sc.height);setProgress('img-enc-prog','img-enc-fill','img-enc-prog-lbl',35,'Encrypting (PBKDF2+AES-GCM)...');await sleep(10);const rp=await PayloadMod.pack(State.img.payloadType,document.getElementById('img-msg').value,State.img.secretFile);const ep=await CryptoMod.encrypt(rp,pwd);setProgress('img-enc-prog','img-enc-fill','img-enc-prog-lbl',65,'Embedding into image...');await sleep(10);await ImageSteg.embed(wd,ep,pwd);setProgress('img-enc-prog','img-enc-fill','img-enc-prog-lbl',90,'Rendering output...');await sleep(10);const sc2=document.getElementById('cv-steg');sc2.width=wd.width;sc2.height=wd.height;sc2.getContext('2d').putImageData(wd,0,0);State.img.stegoData=wd;setProgress('img-enc-prog','img-enc-fill','img-enc-prog-lbl',100,'Done');document.getElementById('img-enc-output').style.display='block';showStatus('st-img-enc','ok',`✓ Payload embedded — ${fmtBytes(ep.length)} encrypted bytes hidden in image`)}catch(err){showStatus('st-img-enc','err','✕ '+err.message)}finally{btn.disabled=false;setTimeout(()=>hideProgress('img-enc-prog'),2500)}}

function doDownloadImage(){if(!State.img.stegoData)return;document.getElementById('cv-steg').toBlob(blob=>{triggerDownload(URL.createObjectURL(blob),'stego_'+(State.img.carrierFile?.name?.replace(/\.[^.]+$/,'')||'output')+'.png')},'image/png')}

async function doDecodeImage(){const btn=document.getElementById('btn-img-dec');if(!State.imgd.file)return showStatus('st-img-dec','err','Load a stego image first');const pwd=document.getElementById('imgd-pwd').value;if(!pwd)return showStatus('st-img-dec','err','Enter the password');btn.disabled=true;hideStatus('st-img-dec');try{const id=await loadImageDataFromFile(State.imgd.file);showStatus('st-img-dec','info','Deriving key + extracting...');await sleep(10);const ep=await ImageSteg.extract(id,pwd);const rp=await CryptoMod.decrypt(ep,pwd);const res=PayloadMod.unpack(rp);renderDecryptedOutput(res,'imgd-out','imgd-file-res','imgd-file-name','imgd-file-dl');showStatus('st-img-dec','ok','✓ Payload extracted and decrypted successfully')}catch(err){showStatus('st-img-dec','err','✕ '+err.message)}finally{btn.disabled=false}}

function loadImageDataFromFile(file){return new Promise((resolve,reject)=>{const url=URL.createObjectURL(file);const img=new Image();img.onload=()=>{const c=document.createElement('canvas');c.width=img.width;c.height=img.height;const ctx=c.getContext('2d');ctx.drawImage(img,0,0);resolve(ctx.getImageData(0,0,img.width,img.height));URL.revokeObjectURL(url)};img.onerror=()=>reject(new Error('Failed to load image'));img.src=url})}

function loadCarrierAudio(file){if(!file)return;State.aud.carrierFile=file;const reader=new FileReader();reader.onload=e=>{try{const{dataSize}=AudioSteg.parseWav(e.target.result);State.aud.capBytes=AudioSteg.capacityBytes(dataSize);document.getElementById('ftag-aud-name').textContent=file.name;document.getElementById('ftag-aud-size').textContent=fmtBytes(file.size);document.getElementById('ftag-aud').classList.add('show');document.getElementById('chip-aud-cap').textContent=fmtBytes(State.aud.capBytes);document.getElementById('chip-aud-sr').textContent='—';document.getElementById('chip-aud-ch').textContent='—';document.getElementById('chips-aud').style.display='flex';updateCapCurrent('aud')}catch(err){showStatus('st-aud-enc','err','✕ '+err.message)}};reader.readAsArrayBuffer(file)}

async function doEncodeAudio(){const btn=document.getElementById('btn-aud-enc');if(!State.aud.carrierFile)return showStatus('st-aud-enc','err','Select a WAV carrier first');const pwd=document.getElementById('aud-pwd').value;if(!pwd)return showStatus('st-aud-enc','err','Enter a password');btn.disabled=true;hideStatus('st-aud-enc');setProgress('aud-enc-prog','aud-enc-fill','aud-enc-prog-lbl',20,'Packing payload...');await sleep(20);try{const rp=await PayloadMod.pack(State.aud.payloadType,document.getElementById('aud-msg').value,State.aud.secretFile);setProgress('aud-enc-prog','aud-enc-fill','aud-enc-prog-lbl',45,'Encrypting...');await sleep(10);const ep=await CryptoMod.encrypt(rp,pwd);setProgress('aud-enc-prog','aud-enc-fill','aud-enc-prog-lbl',70,'Embedding into WAV...');await sleep(10);const buf=await State.aud.carrierFile.arrayBuffer();State.aud.stegoBuffer=await AudioSteg.embed(buf,ep);setProgress('aud-enc-prog','aud-enc-fill','aud-enc-prog-lbl',100,'Done');document.getElementById('aud-dl-row').classList.add('show');showStatus('st-aud-enc','ok',`✓ Payload embedded — ${fmtBytes(ep.length)} encrypted bytes hidden in WAV`)}catch(err){showStatus('st-aud-enc','err','✕ '+err.message)}finally{btn.disabled=false;setTimeout(()=>hideProgress('aud-enc-prog'),2500)}}

function doDownloadAudio(){if(!State.aud.stegoBuffer)return;const blob=new Blob([State.aud.stegoBuffer],{type:'audio/wav'});triggerDownload(URL.createObjectURL(blob),'stego_'+(State.aud.carrierFile?.name||'output.wav'))}

async function doDecodeAudio(){const btn=document.getElementById('btn-aud-dec');if(!State.audd.file)return showStatus('st-aud-dec','err','Load a stego WAV first');const pwd=document.getElementById('audd-pwd').value;if(!pwd)return showStatus('st-aud-dec','err','Enter the password');btn.disabled=true;hideStatus('st-aud-dec');try{const buf=await State.audd.file.arrayBuffer();const ep=await AudioSteg.extract(buf);showStatus('st-aud-dec','info','Decrypting...');await sleep(10);const rp=await CryptoMod.decrypt(ep,pwd);const res=PayloadMod.unpack(rp);renderDecryptedOutput(res,'audd-out','audd-file-res','audd-file-name','audd-file-dl');showStatus('st-aud-dec','ok','✓ Payload extracted and decrypted successfully')}catch(err){showStatus('st-aud-dec','err','✕ '+err.message)}finally{btn.disabled=false}}

function loadCarrierVideo(file){if(!file)return;State.vid.carrierFile=file;document.getElementById('ftag-vid-name').textContent=file.name;document.getElementById('ftag-vid-size').textContent=fmtBytes(file.size);document.getElementById('ftag-vid').classList.add('show');document.getElementById('chip-vid-size').textContent=fmtBytes(file.size);document.getElementById('chip-vid-fmt').textContent=(file.name.split('.').pop()||'video').toUpperCase();document.getElementById('chips-vid').style.display='flex'}

async function doEncodeVideo(){const btn=document.getElementById('btn-vid-enc');if(!State.vid.carrierFile)return showStatus('st-vid-enc','err','Select a carrier video first');const pwd=document.getElementById('vid-pwd').value;if(!pwd)return showStatus('st-vid-enc','err','Enter a password');btn.disabled=true;hideStatus('st-vid-enc');setProgress('vid-enc-prog','vid-enc-fill','vid-enc-prog-lbl',20,'Packing payload...');await sleep(20);try{const rp=await PayloadMod.pack(State.vid.payloadType,document.getElementById('vid-msg').value,State.vid.secretFile);setProgress('vid-enc-prog','vid-enc-fill','vid-enc-prog-lbl',45,'Encrypting...');await sleep(10);const ep=await CryptoMod.encrypt(rp,pwd);setProgress('vid-enc-prog','vid-enc-fill','vid-enc-prog-lbl',70,'Appending to video...');await sleep(10);const vb=await State.vid.carrierFile.arrayBuffer();State.vid.stegoBuffer=await VideoSteg.embed(vb,ep);setProgress('vid-enc-prog','vid-enc-fill','vid-enc-prog-lbl',100,'Done');document.getElementById('vid-dl-row').classList.add('show');showStatus('st-vid-enc','ok',`✓ Payload appended — ${fmtBytes(ep.length)} encrypted bytes appended to video`)}catch(err){showStatus('st-vid-enc','err','✕ '+err.message)}finally{btn.disabled=false;setTimeout(()=>hideProgress('vid-enc-prog'),2500)}}

function doDownloadVideo(){if(!State.vid.stegoBuffer)return;const blob=new Blob([State.vid.stegoBuffer],{type:State.vid.carrierFile?.type||'video/mp4'});triggerDownload(URL.createObjectURL(blob),'stego_'+(State.vid.carrierFile?.name||'output.mp4'))}

async function doDecodeVideo(){const btn=document.getElementById('btn-vid-dec');if(!State.vidd.file)return showStatus('st-vid-dec','err','Load a stego video first');const pwd=document.getElementById('vidd-pwd').value;if(!pwd)return showStatus('st-vid-dec','err','Enter the password');btn.disabled=true;hideStatus('st-vid-dec');try{const buf=await State.vidd.file.arrayBuffer();const ep=await VideoSteg.extract(buf);showStatus('st-vid-dec','info','Decrypting...');await sleep(10);const rp=await CryptoMod.decrypt(ep,pwd);const res=PayloadMod.unpack(rp);renderDecryptedOutput(res,'vidd-out','vidd-file-res','vidd-file-name','vidd-file-dl');showStatus('st-vid-dec','ok','✓ Payload extracted and decrypted successfully')}catch(err){showStatus('st-vid-dec','err','✕ '+err.message)}finally{btn.disabled=false}}

function setupDropzone(id,cb){const dz=document.getElementById(id);if(!dz)return;dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over')});dz.addEventListener('dragleave',()=>dz.classList.remove('over'));dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');const f=e.dataTransfer.files[0];if(f)cb(f)});const inp=dz.querySelector('input[type="file"]');if(inp)inp.addEventListener('change',()=>{if(inp.files[0])cb(inp.files[0])})}

function setPayloadType(panel,type){State[panel].payloadType=type;const ta=document.getElementById(`${panel}-text-area`);const fa=document.getElementById(`${panel}-file-area`);if(ta)ta.style.display=type==='text'?'block':'none';if(fa)fa.style.display=type==='file'?'block':'none';document.querySelectorAll(`.ptbtn[data-panel="${panel}"]`).forEach(b=>b.classList.toggle('active',b.dataset.type===type));updateCapCurrent(panel)}

function setMode(mode){State.mode=mode;document.getElementById('btn-mode-enc').classList.toggle('active',mode==='enc');document.getElementById('btn-mode-dec').classList.toggle('active',mode==='dec');['img','aud','vid'].forEach(m=>{const p=document.getElementById(`panel-${m}`);if(!p)return;p.querySelectorAll('.mode-section').forEach(s=>{const ie=s.id.endsWith('-enc');s.classList.toggle('active',mode==='enc'?ie:!ie)})})}

function setMedia(media){State.media=media;document.querySelectorAll('.media-btn').forEach(b=>b.classList.toggle('active',b.dataset.media===media));document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('active',p.id===`panel-${media}`))}

document.addEventListener('DOMContentLoaded',()=>{
  document.getElementById('btn-mode-enc').addEventListener('click',()=>setMode('enc'));
  document.getElementById('btn-mode-dec').addEventListener('click',()=>setMode('dec'));
  document.querySelectorAll('.media-btn').forEach(b=>b.addEventListener('click',()=>setMedia(b.dataset.media)));
  document.querySelectorAll('.ptbtn').forEach(b=>b.addEventListener('click',()=>setPayloadType(b.dataset.panel,b.dataset.type)));

  setupDropzone('dz-img',loadCarrierImage);
  setupDropzone('dz-img-sf',f=>{State.img.secretFile=f;document.getElementById('ftag-img-sf-name').textContent=f.name;document.getElementById('ftag-img-sf-size').textContent=fmtBytes(f.size);document.getElementById('ftag-img-sf').classList.add('show');updateCapCurrent('img')});
  
  // Bug Fix: Clean up output areas on clear
  document.getElementById('clear-img').addEventListener('click',()=>{
      State.img.carrierFile=null;State.img.imageData=null;State.img.capBytes=0;
      document.getElementById('ftag-img').classList.remove('show');
      document.getElementById('chips-img').style.display='none';
      document.getElementById('inp-img').value='';
      const out=document.getElementById('img-enc-output'); if(out) out.style.display='none';
  });
  
  document.getElementById('clear-img-sf').addEventListener('click',()=>{State.img.secretFile=null;document.getElementById('ftag-img-sf').classList.remove('show');document.getElementById('inp-img-sf').value='';updateCapCurrent('img')});
  document.getElementById('img-msg').addEventListener('input',()=>updateCapCurrent('img'));
  document.getElementById('btn-img-enc').addEventListener('click',doEncodeImage);
  document.getElementById('btn-img-dl').addEventListener('click',doDownloadImage);
  setupDropzone('dz-imgd',f=>{State.imgd.file=f;document.getElementById('ftag-imgd-name').textContent=f.name;document.getElementById('ftag-imgd').classList.add('show')});
  document.getElementById('btn-img-dec').addEventListener('click',doDecodeImage);

  setupDropzone('dz-aud',loadCarrierAudio);
  setupDropzone('dz-aud-sf',f=>{State.aud.secretFile=f;document.getElementById('ftag-aud-sf-name').textContent=f.name;document.getElementById('ftag-aud-sf-size').textContent=fmtBytes(f.size);document.getElementById('ftag-aud-sf').classList.add('show');updateCapCurrent('aud')});
  
  // Bug Fix: Clean up output areas on clear
  document.getElementById('clear-aud').addEventListener('click',()=>{
      State.aud.carrierFile=null;State.aud.capBytes=0;
      document.getElementById('ftag-aud').classList.remove('show');
      document.getElementById('chips-aud').style.display='none';
      document.getElementById('inp-aud').value='';
      const dl=document.getElementById('aud-dl-row'); if(dl) dl.classList.remove('show');
  });
  
  document.getElementById('clear-aud-sf').addEventListener('click',()=>{State.aud.secretFile=null;document.getElementById('ftag-aud-sf').classList.remove('show');document.getElementById('inp-aud-sf').value='';updateCapCurrent('aud')});
  document.getElementById('aud-msg').addEventListener('input',()=>updateCapCurrent('aud'));
  document.getElementById('btn-aud-enc').addEventListener('click',doEncodeAudio);
  document.getElementById('btn-aud-dl').addEventListener('click',doDownloadAudio);
  setupDropzone('dz-audd',f=>{State.audd.file=f;document.getElementById('ftag-audd-name').textContent=f.name;document.getElementById('ftag-audd').classList.add('show')});
  document.getElementById('btn-aud-dec').addEventListener('click',doDecodeAudio);

  setupDropzone('dz-vid',loadCarrierVideo);
  setupDropzone('dz-vid-sf',f=>{State.vid.secretFile=f;document.getElementById('ftag-vid-sf-name').textContent=f.name;document.getElementById('ftag-vid-sf-size').textContent=fmtBytes(f.size);document.getElementById('ftag-vid-sf').classList.add('show')});
  
  // Bug Fix: Clean up output areas on clear
  document.getElementById('clear-vid').addEventListener('click',()=>{
      State.vid.carrierFile=null;
      document.getElementById('ftag-vid').classList.remove('show');
      document.getElementById('chips-vid').style.display='none';
      document.getElementById('inp-vid').value='';
      const dl=document.getElementById('vid-dl-row'); if(dl) dl.classList.remove('show');
  });
  
  document.getElementById('clear-vid-sf').addEventListener('click',()=>{State.vid.secretFile=null;document.getElementById('ftag-vid-sf').classList.remove('show');document.getElementById('inp-vid-sf').value=''});
  document.getElementById('btn-vid-enc').addEventListener('click',doEncodeVideo);
  document.getElementById('btn-vid-dl').addEventListener('click',doDownloadVideo);
  setupDropzone('dz-vidd',f=>{State.vidd.file=f;document.getElementById('ftag-vidd-name').textContent=f.name;document.getElementById('ftag-vidd').classList.add('show')});
  document.getElementById('btn-vid-dec').addEventListener('click',doDecodeVideo);

  // Bug Fix: Copy button logic updated to prevent text corruption
  document.addEventListener('click',e=>{
      if(e.target.classList.contains('copy-btn')){
          const b64 = e.target.dataset.textB64;
          let text = '';
          if(b64) {
              text = decodeURIComponent(escape(atob(b64)));
          } else {
              const el=document.getElementById(e.target.dataset.target);
              if(!el)return;
              text=el.textContent.replace('COPY','').trim();
          }
          navigator.clipboard.writeText(text).then(()=>{
              e.target.textContent='COPIED ✓';
              setTimeout(()=>{e.target.textContent='COPY'},1500)
          })
      }
  });

  setMode('enc');
  setMedia('img');
});
