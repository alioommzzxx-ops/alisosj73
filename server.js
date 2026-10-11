'use strict';
/**
 * مصنع AI — الخادم الخلفي
 * - بدون أي مكتبات خارجية (Node.js 18 أو أحدث فقط)
 * - مفتاح Anthropic يُقرأ من متغير البيئة ANTHROPIC_API_KEY ولا يصل للمتصفح أبداً
 * - لا يُنفَّذ أي كود ناتج على الخادم: الملفات تُحفظ كنصوص فقط، والمعاينة تعمل في iframe معزول بالمتصفح
 */
const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

/* ───────────── الإعدادات ───────────── */
const PORT = Number(process.env.PORT) || 3000;
// مفتاح احتياطي للتجربة فقط: يُستخدم إذا لم يُضبط ANTHROPIC_API_KEY في الاستضافة.
// تحذير: لا ترفع هذا الملف إلى مستودع عام، وبدّل المفتاح بعد التجربة.
const FALLBACK_API_KEY = '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';
const API_KEY = (process.env.ANTHROPIC_API_KEY || FALLBACK_API_KEY).trim();
const API_BASE = (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com').replace(/\/$/, '');
const MODEL = (process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5').trim();
const MAX_OUTPUT_TOKENS = Number(process.env.MAX_OUTPUT_TOKENS) || 20000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const ACCESS_CODE = process.env.ACCESS_CODE || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const GEN_LIMIT_PER_HOUR = Number(process.env.GENERATE_LIMIT_PER_HOUR) || 10;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT_GENERATIONS) || 3;

const MAX_PROMPT_CHARS = 4000;
const MAX_FILES = 40;
const MAX_FILE_BYTES = 200 * 1024;
const MAX_PROJECT_BYTES = 400 * 1024;
const MAX_PROJECTS_PER_USER = 30;
const ALLOWED_EXT = new Set(['.html', '.css', '.js', '.json', '.md', '.txt', '.svg']);
const ANTHROPIC_VERSION = '2023-06-01';

/* ───────────── أدوات عامة ───────────── */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const buckets = new Map();
function rateHit(key, limit, windowMs) {
  const now = Date.now();
  const arr = (buckets.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= limit) {
    buckets.set(key, arr);
    return Math.max(1, Math.ceil((windowMs - (now - arr[0])) / 1000));
  }
  arr.push(now);
  buckets.set(key, arr);
  return 0;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of buckets) {
    if (!arr.length || now - arr[arr.length - 1] > 3600e3) buckets.delete(k);
  }
}, 10 * 60e3).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const x = req.headers['x-forwarded-for'];
    if (x) return String(x).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function parseCookies(h) {
  const o = {};
  String(h || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return o;
}

function secureHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self' data: blob: https:; script-src 'self' 'unsafe-inline' https:; " +
    "style-src 'self' 'unsafe-inline' https:; img-src * data: blob:; font-src * data:; " +
    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
}

function send(res, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  }, extraHeaders || {}));
  res.end(body);
}

function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'حجم الطلب كبير جداً.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'صيغة الطلب غير صحيحة.')); }
    });
    req.on('error', () => reject(new HttpError(400, 'تعذّر قراءة الطلب.')));
  });
}

function sha(s) { return crypto.createHash('sha256').update(String(s)).digest(); }
function codeOk(req) {
  if (!ACCESS_CODE) return true;
  const given = String(req.headers['x-access-code'] || '');
  return crypto.timingSafeEqual(sha(given), sha(ACCESS_CODE));
}

/* ───────────── المسارات والملفات ───────────── */
const ID_RE = /^p[a-f0-9]{12}$/;
const UID_RE = /^[a-f0-9]{32}$/;
const SEG_RE = /^[A-Za-z0-9_\u0600-\u06FF][A-Za-z0-9_\-.\u0600-\u06FF]*$/;

function safeRel(p) {
  if (typeof p !== 'string') return null;
  p = p.replace(/\\/g, '/').replace(/^\/+/, '').trim();
  if (!p || p.length > 100) return null;
  const parts = p.split('/');
  if (parts.length > 4) return null;
  for (const s of parts) {
    if (!SEG_RE.test(s) || s.includes('..')) return null;
  }
  if (!ALLOWED_EXT.has(path.extname(p).toLowerCase())) return null;
  return parts.join('/');
}

function userDir(uid) { return path.join(DATA_DIR, uid); }
function projectDir(uid, id) { return path.join(DATA_DIR, uid, id); }
function filesDir(uid, id) { return path.join(projectDir(uid, id), 'files'); }
function resolveFile(uid, id, rel) {
  const base = filesDir(uid, id);
  const full = path.join(base, rel);
  if (!full.startsWith(base + path.sep)) return null;
  return full;
}

async function exists(p) { try { await fsp.access(p); return true; } catch { return false; } }

async function atomicWrite(file, content) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = file + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
  await fsp.writeFile(tmp, content, 'utf8');
  await fsp.rename(tmp, file);
}

async function walk(dir, prefix, out) {
  let entries;
  try { entries = await fsp.readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isDirectory()) await walk(path.join(dir, e.name), prefix + e.name + '/', out);
    else if (e.isFile() && !e.name.endsWith('.tmp')) out.push(prefix + e.name);
  }
  return out;
}

async function readFiles(uid, id) {
  const rels = (await walk(filesDir(uid, id), '', [])).sort();
  const files = {};
  for (const rel of rels) {
    const full = resolveFile(uid, id, rel);
    if (full) files[rel] = await fsp.readFile(full, 'utf8');
  }
  return files;
}

async function loadMeta(uid, id) {
  try { return JSON.parse(await fsp.readFile(path.join(projectDir(uid, id), 'meta.json'), 'utf8')); }
  catch { return null; }
}
async function saveMeta(uid, meta) {
  await atomicWrite(path.join(projectDir(uid, meta.id), 'meta.json'), JSON.stringify(meta));
}

function totalBytes(files) {
  return Object.values(files).reduce((n, c) => n + Buffer.byteLength(c, 'utf8'), 0);
}

async function listProjects(uid) {
  let ids = [];
  try { ids = await fsp.readdir(userDir(uid)); } catch { return []; }
  const out = [];
  for (const id of ids) {
    if (!ID_RE.test(id)) continue;
    const m = await loadMeta(uid, id);
    if (m) out.push({ id: m.id, name: m.name, createdAt: m.createdAt, updatedAt: m.updatedAt, fileCount: m.fileCount || 0 });
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

/* ───────────── رسائل أخطاء Anthropic بالعربية ───────────── */
function mapAnthropicError(status, type, message) {
  const msg = String(message || '');
  if (status === 401 || type === 'authentication_error')
    return { status: 502, message: 'مفتاح Anthropic غير صالح أو منتهي. راجع قيمة ANTHROPIC_API_KEY في إعدادات الاستضافة.' };
  if (/credit balance|billing/i.test(msg))
    return { status: 402, message: 'رصيد حساب Anthropic غير كافٍ. أضف رصيداً من console.anthropic.com ثم حاول مجدداً.' };
  if (status === 403 || type === 'permission_error')
    return { status: 502, message: 'مفتاح Anthropic لا يملك صلاحية استخدام هذا النموذج أو هذه الخدمة.' };
  if (status === 404 || type === 'not_found_error')
    return { status: 502, message: `النموذج «${MODEL}» غير متاح لهذا المفتاح. اضغط «اختبار الاتصال» لمعرفة النماذج المتاحة ثم غيّر ANTHROPIC_MODEL.` };
  if (status === 413 || type === 'request_too_large')
    return { status: 413, message: 'حجم الطلب أكبر مما يقبله النموذج. قلّل حجم المشروع أو اختصر طلبك.' };
  if (status === 429 || type === 'rate_limit_error')
    return { status: 429, message: 'تجاوزت حدود الاستخدام لدى Anthropic. انتظر دقيقة ثم حاول مرة أخرى.' };
  if (status === 529 || type === 'overloaded_error')
    return { status: 503, message: 'خوادم Anthropic مشغولة حالياً. أعد المحاولة بعد قليل.' };
  if (status >= 500 || type === 'api_error')
    return { status: 502, message: 'حدث خطأ مؤقت في خوادم Anthropic. أعد المحاولة بعد قليل.' };
  if (status === 400 || type === 'invalid_request_error')
    return { status: 400, message: 'رفضت Anthropic الطلب: ' + msg.slice(0, 200) };
  return { status: 502, message: 'خطأ غير متوقع من Anthropic: ' + msg.slice(0, 200) };
}

async function upstreamError(r) {
  let type = '', message = '';
  try {
    const j = JSON.parse(await r.text());
    type = j && j.error && j.error.type; message = j && j.error && j.error.message;
  } catch { /* ignore */ }
  return mapAnthropicError(r.status, type, message);
}

const NETWORK_ERR = { status: 502, message: 'تعذّر الاتصال بخوادم Anthropic. تحقق من اتصال الخادم بالإنترنت وأعد المحاولة.' };

/* ───────────── تعليمات النموذج ───────────── */
const SYSTEM_PROMPT = `You are "مصنع AI", a senior web engineer. You turn a user's Arabic description into a complete, working front-end project.

OUTPUT FORMAT (strict, machine-parsed):
1. If this is a NEW project, begin with <title>short Arabic project name, max 40 chars</title>
2. Then <summary>2-5 short lines in simple Arabic: what you built or changed, and how to use it. State any assumptions.</summary>
3. Then one block per file:
<file path="relative/path.ext">
FULL file content
</file>
4. To remove a file, output <delete path="relative/path.ext"/>.
Nothing else outside these tags. Never wrap file contents in markdown fences. Never output partial files, diffs, or "rest unchanged" — always the complete file.

RULES:
- Stack: plain HTML + CSS + vanilla JavaScript. No build step, no npm, no frameworks required. The entry file MUST be index.html. Link other files with relative paths (style.css, app.js). Allowed extensions: html, css, js, json, md, svg, txt. Max ${MAX_FILES} files, each under ${Math.round(MAX_FILE_BYTES / 1024)}KB.
- The preview is static and sandboxed: no server code, no API keys, no calls to private APIs. If the idea needs a backend (login, database, payments), build a fully working front-end that stores data with localStorage (wrapped in try/catch) and say in the summary what a real backend would add.
- Avoid external CDN libraries unless clearly necessary.
- Arabic first: <html lang="ar" dir="rtl">, viewport meta tag, mobile-first responsive layout, all visible text in Arabic, clean modern design.
- Everything must really work: real logic, form validation, empty states, no dead buttons, no placeholder "coming soon" features.
- Security: escape user-provided text before inserting into HTML (prefer textContent), never use eval.
- When editing an existing project you receive its current files. Return ONLY files you created or changed, each in full, and keep all other behavior intact.
- If the request is unclear, make sensible assumptions instead of asking questions.
- If the request is for malware, phishing, fraud, or other harmful software, output only <summary> explaining the refusal in Arabic and no files.`;

function buildUserMessage(project, files, history, prompt) {
  if (!project) return `<request>\n${prompt}\n</request>`;
  let s = `<project_name>${project.name}</project_name>\n<current_files>\n`;
  for (const [p, c] of Object.entries(files)) s += `<file path="${p}">\n${c}\n</file>\n`;
  s += '</current_files>\n';
  if (history.length) {
    s += '<recent_chat>\n';
    for (const m of history.slice(-6)) s += `${m.role === 'user' ? 'المستخدم' : 'المساعد'}: ${String(m.text).slice(0, 600)}\n`;
    s += '</recent_chat>\n';
  }
  s += `<request>\n${prompt}\n</request>`;
  return s;
}

function parseOutput(text) {
  const title = (text.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
  const summary = (text.match(/<summary>([\s\S]*?)<\/summary>/) || [])[1];
  const files = [];
  const re = /<file path="([^"]+)">\r?\n?([\s\S]*?)\r?\n?<\/file>/g;
  let m;
  while ((m = re.exec(text))) files.push({ path: m[1], content: m[2] });
  const deletes = [];
  const dre = /<delete path="([^"]+)"\s*\/>/g;
  while ((m = dre.exec(text))) deletes.push(m[1]);
  return { title: title && title.trim(), summary: summary && summary.trim(), files, deletes };
}

/* ───────────── SSE نحو المتصفح ───────────── */
function sse(res, obj) {
  if (!res.writableEnded && !res.destroyed) res.write('data: ' + JSON.stringify(obj) + '\n\n');
}

/* ───────────── حالة التنفيذ ───────────── */
let activeGenerations = 0;
const lockedProjects = new Set();

async function handleGenerate(req, res, ctx) {
  if (!API_KEY) throw new HttpError(503, 'مفتاح Anthropic غير مضبوط على الخادم. أضف متغير البيئة ANTHROPIC_API_KEY ثم أعد تشغيل الخادم.');
  const body = await readJson(req, 40 * 1024);
  const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : '';
  if (prompt.length < 4) throw new HttpError(400, 'اكتب وصفاً أوضح لفكرتك.');
  if (prompt.length > MAX_PROMPT_CHARS) throw new HttpError(400, `الوصف طويل جداً (الحد ${MAX_PROMPT_CHARS} حرف).`);

  let project = null, files = {};
  if (body.projectId !== undefined && body.projectId !== null && body.projectId !== '') {
    if (!ID_RE.test(String(body.projectId))) throw new HttpError(400, 'معرّف المشروع غير صحيح.');
    project = await loadMeta(ctx.uid, body.projectId);
    if (!project) throw new HttpError(404, 'المشروع غير موجود.');
    files = await readFiles(ctx.uid, project.id);
    if (totalBytes(files) > MAX_PROJECT_BYTES) throw new HttpError(413, 'المشروع أكبر من أن يُعدَّل بالذكاء الاصطناعي. احذف بعض الملفات الكبيرة أولاً.');
  } else {
    const existing = await listProjects(ctx.uid);
    if (existing.length >= MAX_PROJECTS_PER_USER) throw new HttpError(400, `وصلت للحد الأقصى (${MAX_PROJECTS_PER_USER} مشروعاً). احذف مشروعاً قديماً أولاً.`);
  }

  const wait = rateHit('gen:ip:' + ctx.ip, GEN_LIMIT_PER_HOUR, 3600e3) || rateHit('gen:uid:' + ctx.uid, GEN_LIMIT_PER_HOUR, 3600e3);
  if (wait) throw new HttpError(429, `وصلت للحد المسموح من عمليات الإنشاء. حاول بعد ${Math.ceil(wait / 60)} دقيقة تقريباً.`);
  if (activeGenerations >= MAX_CONCURRENT) throw new HttpError(503, 'الخادم مشغول بعمليات إنشاء أخرى. أعد المحاولة بعد لحظات.');
  const projectId = project ? project.id : 'p' + crypto.randomBytes(6).toString('hex');
  if (lockedProjects.has(projectId)) throw new HttpError(409, 'هناك عملية إنشاء جارية لهذا المشروع.');

  activeGenerations++;
  lockedProjects.add(projectId);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10 * 60e3);
  res.on('close', () => { if (!res.writableEnded) controller.abort(); });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no',
    Connection: 'keep-alive',
  });
  const keepAlive = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 15000);

  try {
    sse(res, { type: 'start', projectId, mode: project ? 'edit' : 'create' });

    let upstream;
    try {
      upstream = await fetch(API_BASE + '/v1/messages', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'content-type': 'application/json',
          'x-api-key': API_KEY,
          'anthropic-version': ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: MODEL,
          max_tokens: MAX_OUTPUT_TOKENS,
          stream: true,
          system: SYSTEM_PROMPT,
          messages: [{ role: 'user', content: buildUserMessage(project, files, project ? project.messages || [] : [], prompt) }],
        }),
      });
    } catch (e) {
      if (controller.signal.aborted) return;
      sse(res, { type: 'error', message: NETWORK_ERR.message });
      return;
    }

    if (!upstream.ok) {
      const er = await upstreamError(upstream);
      sse(res, { type: 'error', message: er.message });
      return;
    }

    // قراءة بث Anthropic
    const decoder = new TextDecoder();
    let buf = '', full = '', stopReason = '', scanPos = 0, lastProgress = 0, streamError = null;
    const announced = new Set();

    const handleEvent = (data) => {
      let ev;
      try { ev = JSON.parse(data); } catch { return; }
      if (ev.type === 'content_block_delta' && ev.delta && ev.delta.type === 'text_delta') {
        full += ev.delta.text;
        const re = /<file path="([^"]+)">/g;
        re.lastIndex = scanPos;
        let m;
        while ((m = re.exec(full))) {
          if (!announced.has(m[1])) { announced.add(m[1]); sse(res, { type: 'file', path: m[1] }); }
        }
        scanPos = Math.max(0, full.length - 40);
        const now = Date.now();
        if (now - lastProgress > 400) { lastProgress = now; sse(res, { type: 'progress', chars: full.length }); }
      } else if (ev.type === 'message_delta' && ev.delta && ev.delta.stop_reason) {
        stopReason = ev.delta.stop_reason;
      } else if (ev.type === 'error') {
        streamError = mapAnthropicError(0, ev.error && ev.error.type, ev.error && ev.error.message);
      }
    };

    try {
      for await (const chunk of upstream.body) {
        buf += decoder.decode(chunk, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
          for (const line of block.split('\n')) {
            if (line.startsWith('data:')) handleEvent(line.slice(5).trim());
          }
        }
      }
    } catch (e) {
      if (controller.signal.aborted) return;
      sse(res, { type: 'error', message: 'انقطع الاتصال بـ Anthropic أثناء الإنشاء. أعد المحاولة.' });
      return;
    }

    if (streamError) { sse(res, { type: 'error', message: streamError.message }); return; }

    // معالجة الناتج
    const out = parseOutput(full);
    const notes = [];
    if (stopReason === 'max_tokens') notes.push('انقطع الإخراج لأنه وصل للحد الأقصى؛ حُفظت الملفات المكتملة فقط. اطلب من Claude إكمال الباقي.');
    if (stopReason === 'refusal') notes.push('رفض النموذج تنفيذ هذا الطلب.');

    const merged = Object.assign({}, files);
    let accepted = 0;
    for (const f of out.files) {
      const rel = safeRel(f.path);
      if (!rel) { notes.push(`تم تجاهل ملف باسم غير مسموح: ${String(f.path).slice(0, 60)}`); continue; }
      if (Buffer.byteLength(f.content, 'utf8') > MAX_FILE_BYTES) { notes.push(`تم تجاهل ${rel} لأنه أكبر من الحد المسموح.`); continue; }
      merged[rel] = f.content; accepted++;
    }
    for (const d of out.deletes) {
      const rel = safeRel(d);
      if (rel && merged[rel] !== undefined) { delete merged[rel]; accepted++; }
    }
    if (Object.keys(merged).length > MAX_FILES) { sse(res, { type: 'error', message: `عدد الملفات تجاوز ${MAX_FILES}. اطلب مشروعاً أبسط.` }); return; }
    if (totalBytes(merged) > MAX_PROJECT_BYTES) { sse(res, { type: 'error', message: 'حجم المشروع الناتج تجاوز الحد المسموح. اطلب مشروعاً أبسط.' }); return; }

    if (!accepted) {
      // لا ملفات: قد يكون رفضاً أو توضيحاً — نعرض الملخص دون إنشاء مشروع
      if (out.summary) { sse(res, { type: 'message', summary: out.summary, notes }); return; }
      sse(res, { type: 'error', message: 'لم ينتج النموذج أي ملفات. جرّب إعادة صياغة طلبك بتفاصيل أكثر.' });
      return;
    }

    // الحفظ
    const now = Date.now();
    const meta = project || {
      id: projectId,
      name: (out.title || prompt.split('\n')[0]).slice(0, 60),
      createdAt: now,
      messages: [],
    };
    // مزامنة الملفات على القرص
    const dir = filesDir(ctx.uid, projectId);
    const existingRels = Object.keys(files);
    for (const rel of existingRels) {
      if (merged[rel] === undefined) { const full = resolveFile(ctx.uid, projectId, rel); if (full) await fsp.rm(full, { force: true }); }
    }
    for (const [rel, content] of Object.entries(merged)) {
      if (files[rel] === content) continue;
      const full = resolveFile(ctx.uid, projectId, rel);
      if (full) await atomicWrite(full, content);
    }
    await fsp.mkdir(dir, { recursive: true });
    meta.updatedAt = now;
    meta.fileCount = Object.keys(merged).length;
    meta.messages = (meta.messages || []).concat([
      { role: 'user', text: prompt, ts: now },
      { role: 'assistant', text: out.summary || 'تم التنفيذ.', ts: now },
    ]).slice(-40);
    await saveMeta(ctx.uid, meta);

    sse(res, {
      type: 'done',
      summary: out.summary || 'تم التنفيذ.',
      notes,
      project: { id: meta.id, name: meta.name, createdAt: meta.createdAt, updatedAt: meta.updatedAt, messages: meta.messages, files: merged },
    });
  } catch (e) {
    console.error('generate error:', e);
    sse(res, { type: 'error', message: 'حدث خطأ غير متوقع في الخادم أثناء الإنشاء.' });
  } finally {
    clearInterval(keepAlive);
    clearTimeout(timeout);
    activeGenerations--;
    lockedProjects.delete(projectId);
    if (!res.writableEnded) res.end();
  }
}

/* ───────────── اختبار الاتصال بـ Anthropic ───────────── */
async function handleHealth(res) {
  if (!API_KEY) return send(res, 200, { ok: false, message: 'المفتاح ANTHROPIC_API_KEY غير مضبوط على الخادم.' });
  let r;
  try {
    r = await fetch(API_BASE + '/v1/models?limit=100', {
      headers: { 'x-api-key': API_KEY, 'anthropic-version': ANTHROPIC_VERSION },
      signal: AbortSignal.timeout(20000),
    });
  } catch { return send(res, 200, { ok: false, message: NETWORK_ERR.message }); }
  if (!r.ok) { const er = await upstreamError(r); return send(res, 200, { ok: false, message: er.message }); }
  let ids = [];
  try { ids = ((await r.json()).data || []).map(m => m.id); } catch { /* ignore */ }
  const modelOk = ids.includes(MODEL);
  send(res, 200, {
    ok: true, modelOk, model: MODEL, models: ids.slice(0, 30),
    message: modelOk
      ? `الاتصال سليم، والنموذج «${MODEL}» متاح.`
      : `المفتاح يعمل، لكن النموذج «${MODEL}» غير ظاهر ضمن النماذج المتاحة. غيّر ANTHROPIC_MODEL إلى أحد النماذج المعروضة.`,
  });
}

/* ───────────── الموجّه الرئيسي ───────────── */
async function handler(req, res) {
  secureHeaders(res);
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const ip = clientIp(req);

  if (rateHit('all:' + ip, 600, 10 * 60e3)) return send(res, 429, { error: 'طلبات كثيرة جداً. انتظر قليلاً.' });

  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    const html = await fsp.readFile(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(html);
  }
  if (!p.startsWith('/api/')) return send(res, 404, { error: 'غير موجود.' });

  // حماية CSRF: يُرفض أي طلب كتابة قادم من موقع آخر
  if (req.method !== 'GET') {
    const origin = req.headers.origin;
    if (origin) {
      let host = '';
      try { host = new URL(origin).host; } catch { /* ignore */ }
      if (host !== req.headers.host) return send(res, 403, { error: 'مصدر الطلب غير مسموح.' });
    }
  }

  // هوية المتصفح عبر كوكي عشوائي (ليست تسجيل دخول: تفصل مشاريع كل متصفح عن غيره)
  const cookies = parseCookies(req.headers.cookie);
  let uid = cookies.uid;
  const headers = {};
  if (!UID_RE.test(uid || '')) {
    uid = crypto.randomBytes(16).toString('hex');
    const secure = TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    headers['Set-Cookie'] = `uid=${uid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000${secure}`;
  }
  if (headers['Set-Cookie']) res.setHeader('Set-Cookie', headers['Set-Cookie']);
  const ctx = { uid, ip };

  if (req.method === 'GET' && p === '/api/config') {
    return send(res, 200, { needsCode: !!ACCESS_CODE, hasKey: !!API_KEY, model: MODEL, maxPromptChars: MAX_PROMPT_CHARS });
  }

  if (!codeOk(req)) return send(res, 401, { error: 'رمز الدخول غير صحيح.', needsCode: true });

  if (req.method === 'GET' && p === '/api/health/anthropic') {
    if (rateHit('health:' + ip, 10, 10 * 60e3)) throw new HttpError(429, 'محاولات اختبار كثيرة. انتظر قليلاً.');
    return handleHealth(res);
  }

  if (req.method === 'POST' && p === '/api/generate') return handleGenerate(req, res, ctx);

  if (req.method === 'GET' && p === '/api/projects') return send(res, 200, { projects: await listProjects(uid) });

  const m = p.match(/^\/api\/projects\/([^/]+)(?:\/(files))?$/);
  if (m) {
    const id = m[1];
    if (!ID_RE.test(id)) throw new HttpError(400, 'معرّف المشروع غير صحيح.');
    const meta = await loadMeta(uid, id);
    if (!meta) throw new HttpError(404, 'المشروع غير موجود.');

    if (!m[2]) {
      if (req.method === 'GET') {
        const files = await readFiles(uid, id);
        return send(res, 200, { project: { id: meta.id, name: meta.name, createdAt: meta.createdAt, updatedAt: meta.updatedAt, messages: meta.messages || [], files } });
      }
      if (req.method === 'PATCH') {
        const b = await readJson(req, 4096);
        const name = typeof b.name === 'string' ? b.name.trim().slice(0, 60) : '';
        if (!name) throw new HttpError(400, 'الاسم فارغ.');
        meta.name = name; meta.updatedAt = Date.now();
        await saveMeta(uid, meta);
        return send(res, 200, { ok: true, name });
      }
      if (req.method === 'DELETE') {
        if (lockedProjects.has(id)) throw new HttpError(409, 'هناك عملية إنشاء جارية لهذا المشروع.');
        await fsp.rm(projectDir(uid, id), { recursive: true, force: true });
        return send(res, 200, { ok: true });
      }
    } else {
      if (lockedProjects.has(id)) throw new HttpError(409, 'هناك عملية إنشاء جارية لهذا المشروع.');
      if (req.method === 'PUT') {
        const b = await readJson(req, MAX_FILE_BYTES + 4096);
        const rel = safeRel(b.path);
        if (!rel) throw new HttpError(400, 'اسم الملف غير مسموح. المسموح: حروف وأرقام وامتدادات html/css/js/json/md/txt/svg.');
        if (typeof b.content !== 'string') throw new HttpError(400, 'محتوى الملف غير صحيح.');
        if (Buffer.byteLength(b.content, 'utf8') > MAX_FILE_BYTES) throw new HttpError(413, 'الملف أكبر من الحد المسموح.');
        const files = await readFiles(uid, id);
        files[rel] = b.content;
        if (Object.keys(files).length > MAX_FILES) throw new HttpError(400, `عدد الملفات تجاوز ${MAX_FILES}.`);
        if (totalBytes(files) > MAX_PROJECT_BYTES) throw new HttpError(413, 'حجم المشروع تجاوز الحد المسموح.');
        await atomicWrite(resolveFile(uid, id, rel), b.content);
        meta.updatedAt = Date.now(); meta.fileCount = Object.keys(files).length;
        await saveMeta(uid, meta);
        return send(res, 200, { ok: true, updatedAt: meta.updatedAt, fileCount: meta.fileCount });
      }
      if (req.method === 'DELETE') {
        const rel = safeRel(url.searchParams.get('path'));
        if (!rel) throw new HttpError(400, 'اسم الملف غير صحيح.');
        if (rel === 'index.html') throw new HttpError(400, 'لا يمكن حذف index.html.');
        const full = resolveFile(uid, id, rel);
        if (!full || !(await exists(full))) throw new HttpError(404, 'الملف غير موجود.');
        await fsp.rm(full, { force: true });
        meta.updatedAt = Date.now(); meta.fileCount = Math.max(0, (meta.fileCount || 1) - 1);
        await saveMeta(uid, meta);
        return send(res, 200, { ok: true });
      }
    }
  }

  return send(res, 404, { error: 'غير موجود.' });
}

const server = http.createServer((req, res) => {
  handler(req, res).catch(e => {
    if (e instanceof HttpError) {
      if (res.headersSent) return res.end();
      return send(res, e.status, { error: e.message });
    }
    console.error('server error:', e);
    if (!res.headersSent) send(res, 500, { error: 'حدث خطأ غير متوقع في الخادم.' });
    else res.end();
  });
});
server.requestTimeout = 0;
server.headersTimeout = 30000;

fs.mkdirSync(DATA_DIR, { recursive: true });
server.listen(PORT, () => {
  console.log(`مصنع AI يعمل على المنفذ ${PORT}`);
  console.log(API_KEY ? `مفتاح Anthropic: مضبوط (النموذج: ${MODEL})` : 'تنبيه: ANTHROPIC_API_KEY غير مضبوط — لن يعمل الإنشاء قبل ضبطه.');
  console.log(ACCESS_CODE ? 'رمز الدخول: مفعّل' : 'تنبيه: ACCESS_CODE غير مضبوط — أي شخص يملك الرابط يستطيع استهلاك رصيدك.');
});
