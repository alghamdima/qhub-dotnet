// The full Qhub scenario (SCENARIO.md), run against a live instance in real Chrome.
//   QHUB_URL                   default http://localhost:8090
//   QHUB_ADMIN_USER            default admin
//   QHUB_ADMIN_PASSWORD_FILE   default ../deploy/secrets/admin_password
// Every step runs even when an earlier one fails; failures get a screenshot in out/. Exit code 1 if any step failed.
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE = (process.env.QHUB_URL || 'http://localhost:8090').replace(/\/$/, '');
const ADMIN = process.env.QHUB_ADMIN_USER || 'admin';
const ADMIN_PW = fs.readFileSync(process.env.QHUB_ADMIN_PASSWORD_FILE || path.join(__dirname, '..', 'deploy', 'secrets', 'admin_password'), 'utf8').trim();
const OUT = path.join(__dirname, 'out');
fs.mkdirSync(OUT, { recursive: true });

const RUN = crypto.randomBytes(3).toString('hex');
const results = [];
const state = {};
let current = null; // the page to screenshot when a step fails

function pdf(tag, size = 4000) {
  const head = Buffer.from(`%PDF-1.4\n% qhub e2e ${RUN} ${tag}\n`);
  return Buffer.concat([head, crypto.randomBytes(size - head.length)]);
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
function check(ok, message) { if (!ok) throw new Error(message); }
function need(...keys) { for (const k of keys) if (state[k] === undefined) throw new Error(`skipped: needs ${k} from an earlier step`); }

async function step(id, title, fn) {
  const started = Date.now();
  const errorsBefore = pageErrors.length;
  try {
    await fn();
    const jsErrors = pageErrors.slice(errorsBefore);
    if (jsErrors.length) throw new Error('JavaScript errors on the page: ' + jsErrors.join(' | '));
    results.push({ id, title, ok: true, ms: Date.now() - started });
    console.log(`PASS ${id} ${title}`);
  } catch (e) {
    const detail = String(e.message || e).split('\n')[0].slice(0, 300);
    results.push({ id, title, ok: false, detail });
    console.log(`FAIL ${id} ${title}\n     ${detail}`);
    if (current) await current.screenshot({ path: path.join(OUT, `${id}.png`), fullPage: true }).catch(() => {});
  }
}

const pageErrors = [];
async function newPage(browser, locale) {
  const ctx = await browser.newContext({
    locale, acceptDownloads: true, viewport: { width: 1280, height: 900 },
    extraHTTPHeaders: { 'Accept-Language': locale.startsWith('ar') ? 'ar-SA,ar;q=0.9' : 'en-US,en;q=0.9' },
  });
  const page = await ctx.newPage();
  page.on('pageerror', e => pageErrors.push(e.message));
  page.on('response', r => { if (r.status() >= 500) pageErrors.push(`HTTP ${r.status()} ${r.url()}`); });
  // "Are you sure?" questions are answered yes; an alert means something failed.
  page.on('dialog', d => { if (d.type() !== 'confirm') pageErrors.push(`alert: ${d.message()}`); d.accept().catch(() => {}); });
  return page;
}

let logins = 0;
async function login(page, user, password) {
  // The sign-in throttle allows 3 quick tries per IP, then one every 3 s.
  if (++logins > 2) await sleep(3500);
  await page.goto(BASE + '/login');
  await page.getByPlaceholder('Username').fill(user);
  await page.getByPlaceholder('Password').fill(password);
  await submit(page);
}

// Posts the page's form and waits for the page it leads to (not networkidle: the admin page keeps an event stream open).
async function submit(page) {
  await Promise.all([page.waitForResponse(r => r.request().method() === 'POST'), page.click('#submitbutton')]);
  await page.waitForLoadState('load');
}

async function api(method, url, { key = state.apiKey, headers = {}, form } = {}) {
  const init = { method, headers: { Authorization: `Bearer ${key}`, ...headers } };
  if (form) {
    const fd = new FormData();
    for (const [k, v] of Object.entries(form)) {
      if (Buffer.isBuffer(v)) fd.append(k, new Blob([v], { type: 'application/pdf' }), `${k === 'file' ? 'statement' : k}.pdf`);
      else fd.append(k, String(v));
    }
    init.body = fd;
  }
  const res = await fetch(BASE + url, init);
  const type = res.headers.get('content-type') || '';
  const body = type.includes('json') ? await res.json() : Buffer.from(await res.arrayBuffer());
  return { status: res.status, type, body };
}

// The customer opens a link and enters a code; returns the page after the post.
async function enterCode(page, id, code) {
  await page.goto(`${BASE}/d?id=${id}`);
  await page.fill('#passwordFile', code);
  await Promise.all([page.waitForLoadState('load'), page.click('#submitbutton')]);
}
async function downloadBytes(page) {
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('a[href*="downloadFile"]')]);
  return fs.readFileSync(await download.path());
}

async function adminRow(page, name, timeout = 15000) {
  const row = page.locator('#downloadtable tr[id^="row-"]', { hasText: name });
  await row.first().waitFor({ timeout });
  const id = (await row.first().getAttribute('id')).slice(4);
  return { row: row.first(), id };
}

(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: process.env.HEADED !== '1' });
  const admin = await newPage(browser, 'en-US');
  const customerAr = await newPage(browser, 'ar-SA');
  const customerEn = await newPage(browser, 'en-US');
  const staff = await newPage(browser, 'en-US');
  console.log(`Qhub scenario ${RUN} against ${BASE}\n`);

  // ── A. Start page, branding, documentation ──────────────────────────────
  current = admin;
  await step('A1', 'The start page forwards to the sign-in page', async () => {
    await admin.goto(BASE + '/');
    await admin.waitForURL(/\/login$/, { timeout: 5000 });
  });
  await step('A2', 'The sign-in page carries the branding (custom.css, logo, favicon)', async () => {
    const css = await admin.evaluate(() => [...document.styleSheets].some(s => (s.href || '').includes('/custom/custom.')));
    check(css, 'custom.css is not linked');
    for (const asset of ['/custom/en-white.png', '/favicon.png']) {
      const r = await fetch(BASE + asset); check(r.status === 200, `${asset} answered ${r.status}`);
    }
  });
  await step('A3', 'The API documentation opens and lists the routes', async () => {
    await admin.goto(BASE + '/apidocumentation');
    await admin.getByText('/files/add').first().waitFor({ timeout: 10000 });
  });
  await step('A4', 'Security headers are sent', async () => {
    const r = await fetch(BASE + '/login');
    for (const h of ['x-frame-options', 'x-content-type-options', 'referrer-policy'])
      check(r.headers.get(h), `missing ${h}`);
  });

  // ── B. Staff sign-in ────────────────────────────────────────────────────
  await step('B1', 'A wrong password is refused and stays on the sign-in page', async () => {
    await login(admin, ADMIN, 'wrong-password-123');
    check(admin.url().endsWith('/login'), `ended on ${admin.url()}`);
  });
  await step('B2', 'The admin signs in and lands on the upload page', async () => {
    await login(admin, ADMIN, ADMIN_PW);
    check(/\/admin$/.test(admin.url()), `ended on ${admin.url()}`);
    await admin.locator('#uploaddropzone').waitFor();
  });
  await step('B3', 'Admin pages need a session (a fresh browser is sent to sign-in)', async () => {
    for (const p of ['/admin', '/users', '/apiKeys', '/logs']) {
      const r = await fetch(BASE + p, { redirect: 'manual' });
      check(r.status >= 300 && r.status < 400 && (r.headers.get('location') || '').includes('login'), `${p} answered ${r.status}`);
    }
  });

  // ── C. Upload from the admin page ───────────────────────────────────────
  await step('C1', 'An upload without the customer code is refused', async () => {
    await admin.fill('#password', '');
    await admin.setInputFiles('input.dz-hidden-input', { name: `nocode-${RUN}.pdf`, mimeType: 'application/pdf', buffer: pdf('nocode') });
    await admin.getByText("Enter the customer's code").first().waitFor({ timeout: 5000 });
    await sleep(1500);
    check(await admin.locator('#downloadtable tr', { hasText: `nocode-${RUN}` }).count() === 0, 'the file was stored anyway');
  });
  await step('C2', 'An upload with code, 2 downloads and 14 days appears in the list with live status', async () => {
    await admin.goto(BASE + '/admin');
    await admin.fill('#password', '4821');
    await admin.fill('#allowedDownloads', '2');
    await admin.fill('#expiryDays', '14');
    state.adminBytes = pdf('admin', 300000);
    await admin.setInputFiles('input.dz-hidden-input', { name: `statement-${RUN}.pdf`, mimeType: 'application/pdf', buffer: state.adminBytes });
    const { row, id } = await adminRow(admin, `statement-${RUN}.pdf`, 30000);
    state.adminFile = id;
    check((await row.innerText()).includes('2'), 'downloads remaining is not 2');
  });
  await step('C3', 'After a reload the file is still listed with its link and key icon', async () => {
    need('adminFile');
    await admin.reload();
    const href = await admin.locator(`#url-href-${state.adminFile}`).getAttribute('href');
    check(href.endsWith(`/d?id=${state.adminFile}`), `link is ${href}`);
    check(await admin.locator(`#row-${state.adminFile} .bi-key`).count() === 1, 'no password icon');
  });
  await step('C4', 'The QR code opens', async () => {
    need('adminFile');
    await admin.click(`#shareDropdown-${state.adminFile}`);
    await admin.click(`#qrcode-${state.adminFile}`);
    await admin.locator('#qrcode img').waitFor({ timeout: 5000 });
    const ok = await admin.locator('#qrcode img').evaluate(img => img.complete && img.naturalWidth > 0);
    check(ok, 'QR image did not load');
    await admin.click('#qroverlay');
  });
  await step('C5', 'The admin downloads the file from the list (single-use link)', async () => {
    need('adminFile');
    const [download] = await Promise.all([admin.waitForEvent('download', { timeout: 15000 }), admin.click(`#row-${state.adminFile} button[title="Download"]`)]);
    check(Buffer.compare(fs.readFileSync(await download.path()), state.adminBytes) === 0, 'downloaded bytes differ');
  });
  await step('C6', 'Edit: downloads 5 and a new code 7777 are saved', async () => {
    need('adminFile');
    await admin.reload();
    await admin.click(`#row-${state.adminFile} button[title="Edit"]`);
    await admin.locator('#modaledit').waitFor({ state: 'visible' });
    await admin.fill('#mi_edit_down', '5');
    await admin.fill('#mi_edit_pw', '7777');
    await admin.click('#mb_save');
    await admin.locator('#modaledit').waitFor({ state: 'hidden', timeout: 10000 });
    await admin.reload();
    check((await admin.locator(`#cell-downloadsRemaining-${state.adminFile}`).innerText()).includes('5'), 'downloads remaining is not 5');
  });
  await step('C7', 'Delete shows an undo toast, and undo brings the file back', async () => {
    need('adminFile');
    await admin.click(`#button-delete-${state.adminFile}`);
    await admin.locator('#toastUndoButton').waitFor({ state: 'visible', timeout: 5000 });
    await admin.click('#toastUndoButton');
    await admin.locator(`#row-${state.adminFile}`).waitFor({ timeout: 10000 });
    await admin.reload();
    check(await admin.locator(`#row-${state.adminFile}`).count() === 1, 'not listed after reload');
  });

  // ── D. The customer (Arabic and English) ────────────────────────────────
  current = customerAr;
  await step('D1', 'Arabic: the customer page is in Arabic, right to left', async () => {
    need('adminFile');
    await customerAr.goto(`${BASE}/d?id=${state.adminFile}`);
    check(await customerAr.locator('[dir="rtl"][lang="ar"]').count() > 0, 'not rtl/ar');
    check(/[؀-ۿ]/.test(await customerAr.locator('.card-title').first().innerText()), 'title is not Arabic');
  });
  await step('D2', 'Arabic: a wrong code shows the error and attempts left (4)', async () => {
    need('adminFile');
    await enterCode(customerAr, state.adminFile, '1111');
    const text = await customerAr.locator('.text-danger').innerText();
    check(/4/.test(text) && /[؀-ۿ]/.test(text), `message: ${text}`);
  });
  await step('D3', 'Arabic: the old code 4821 no longer opens it (changed in C6)', async () => {
    need('adminFile');
    await enterCode(customerAr, state.adminFile, '4821');
    check(await customerAr.locator('.text-danger').count() === 1, 'the old code was accepted');
  });
  await step('D4', 'Arabic: the right code 7777 opens it and the download is byte-identical', async () => {
    need('adminFile', 'adminBytes');
    await enterCode(customerAr, state.adminFile, '7777');
    check(Buffer.compare(await downloadBytes(customerAr), state.adminBytes) === 0, 'downloaded bytes differ');
  });
  current = admin;
  await step('D5', 'The admin list shows one customer download (5 → 4 remaining)', async () => {
    need('adminFile');
    await admin.reload();
    check((await admin.locator(`#cell-downloadsRemaining-${state.adminFile}`).innerText()).includes('4'), 'downloads remaining is not 4');
  });

  // ── E. API keys and the issuing system ──────────────────────────────────
  await step('E1', 'The API page creates a key and shows it once', async () => {
    await admin.goto(BASE + '/apiKeys');
    await admin.click('#button-newapi');
    const cell = admin.locator('#apitable tr').first().locator('td.font-monospace');
    await cell.waitFor({ timeout: 10000 });
    state.apiKey = (await cell.innerText()).trim();
    state.apiKeyRow = (await admin.locator('#apitable tr').first().getAttribute('id')).slice(4);
    check(state.apiKey.length >= 20, `key looks wrong: ${state.apiKey.length} chars`);
  });
  await step('E2', 'The key gets view, upload, edit, delete and download permissions from the page', async () => {
    need('apiKeyRow');
    await admin.reload();
    for (const p of ['view', 'upload', 'edit', 'delete', 'download']) {
      const icon = admin.locator(`#perm_${p}_${state.apiKeyRow}`);
      if (await icon.evaluate(e => e.classList.contains('perm-notgranted'))) {
        await icon.click();
        await admin.waitForFunction(id => document.getElementById(id).classList.contains('perm-granted'), `perm_${p}_${state.apiKeyRow}`, { timeout: 5000 });
      }
    }
    await admin.reload();
    for (const p of ['view', 'upload', 'edit', 'delete', 'download'])
      check(await admin.locator(`#perm_${p}_${state.apiKeyRow}`).evaluate(e => e.classList.contains('perm-granted')), `${p} not granted after reload`);
  });
  await step('E3', 'API: version needs no key; a wrong key is refused', async () => {
    const v = await api('GET', '/api/info/version', { key: '' });
    check(v.status === 200, `version answered ${v.status}`);
    const bad = await api('GET', '/api/files/list', { key: 'not-a-key' });
    check(bad.status === 401 && bad.body.Result === 'error', `wrong key answered ${bad.status}`);
  });
  await step('E4', 'API: an upload without a code is refused', async () => {
    need('apiKey');
    const r = await api('POST', '/api/files/add', { form: { file: pdf('api-nocode') } });
    check(r.status === 400 && /password is required/.test(r.body.ErrorMessage), `answered ${r.status} ${JSON.stringify(r.body).slice(0, 120)}`);
  });
  await step('E5', 'API: upload with code 2468 returns the link; list, info and QR work', async () => {
    need('apiKey');
    state.apiBytes = pdf('api');
    const r = await api('POST', '/api/files/add', { form: { file: state.apiBytes, password: '2468', allowedDownloads: 1, expiryDays: 3 } });
    check(r.status === 200, `add answered ${r.status} ${JSON.stringify(r.body).slice(0, 160)}`);
    state.apiFile = r.body.FileInfo.Id;
    check(r.body.FileInfo.UrlDownload === `${BASE}/d?id=${state.apiFile}`, `UrlDownload is ${r.body.FileInfo.UrlDownload}`);
    const list = await api('GET', '/api/files/list');
    check(list.status === 200 && list.body.some(f => f.Id === state.apiFile), 'not in /files/list');
    const one = await api('GET', `/api/files/list/${state.apiFile}`);
    check(one.status === 200 && one.body.IsPasswordProtected === true, 'list/{id} wrong');
    const qr = await api('GET', `/api/files/qr/${state.apiFile}`);
    check(qr.status === 200 && qr.type.includes('image/png') && qr.body.length > 100, `qr answered ${qr.status} ${qr.type}`);
  });
  current = customerEn;
  await step('E6', 'English: the customer opens the API file with 2468; after its 1 download the link is gone', async () => {
    need('apiFile', 'apiBytes');
    await enterCode(customerEn, state.apiFile, '2468');
    check((await customerEn.locator('.btn-primary').innerText()).includes('Download'), 'page is not English');
    check(Buffer.compare(await downloadBytes(customerEn), state.apiBytes) === 0, 'downloaded bytes differ');
    await customerEn.goto(`${BASE}/d?id=${state.apiFile}`);
    await customerEn.getByText('Link not valid').waitFor({ timeout: 5000 });
  });
  await step('E7', 'API: reserve a link, fetch its QR, then upload the PDF into it; the customer opens it', async () => {
    need('apiKey');
    const res = await api('POST', '/api/files/reserve');
    check(res.status === 200, `reserve answered ${res.status} ${JSON.stringify(res.body).slice(0, 160)}`);
    const id = res.body.FileInfo.Id;
    const qr = await api('GET', `/api/files/qr/${id}`);
    check(qr.status === 200 && qr.type.includes('image/png'), `qr of the reservation answered ${qr.status}`);
    const bytes = pdf('reserved');
    const fill = await api('POST', '/api/files/content', { headers: { id }, form: { file: bytes, password: '1357' } });
    check(fill.status === 200, `content answered ${fill.status} ${JSON.stringify(fill.body).slice(0, 160)}`);
    await enterCode(customerEn, id, '1357');
    check(Buffer.compare(await downloadBytes(customerEn), bytes) === 0, 'downloaded bytes differ');
  });
  await step('E8', 'API: a chunked upload with a gap is refused; a complete one is stored', async () => {
    need('apiKey');
    const mb = 5 * 1024 * 1024, bytes = pdf('chunks', 2 * mb + 1000); // chunks are at least 5 MB
    const add = (uuid, offset, end) => api('POST', '/api/chunk/add', { form: { file: bytes.subarray(offset, end), uuid, offset, filesize: bytes.length } });
    const done = uuid => api('POST', '/api/chunk/complete', { headers: { uuid, filename: 'base64:' + Buffer.from('كشف-حساب.pdf').toString('base64'), filesize: String(bytes.length), contenttype: 'application/pdf', password: '9753' } });
    const gap = `gap-${RUN}-e2e`, full = `full-${RUN}-e2e`; // ids are at least 10 characters
    await add(gap, 0, mb);
    await add(gap, 2 * mb, bytes.length);
    const refused = await done(gap);
    check(refused.status === 400 && /incomplete/.test(refused.body.ErrorMessage), `incomplete upload answered ${refused.status} ${JSON.stringify(refused.body).slice(0, 160)}`);
    for (const o of [0, mb, 2 * mb]) { const r = await add(full, o, Math.min(o + mb, bytes.length)); check(r.status === 200, `chunk ${o} answered ${r.status} ${JSON.stringify(r.body).slice(0, 160)}`); }
    const ok = await done(full);
    check(ok.status === 200, `complete answered ${ok.status} ${JSON.stringify(ok.body).slice(0, 160)}`);
    state.chunkFile = ok.body.FileInfo.Id;
    check(ok.body.FileInfo.Name === 'كشف-حساب.pdf', `name is ${ok.body.FileInfo.Name}`);
    const back = await api('GET', `/api/files/download/${state.chunkFile}`);
    check(Buffer.compare(back.body, bytes) === 0, 'round-trip bytes differ');
  });
  await step('E9', 'API: modify, duplicate (keeps the code), then delete', async () => {
    need('chunkFile');
    const mod = await api('PUT', '/api/files/modify', { headers: { id: state.chunkFile, allowedDownloads: '7' } });
    check(mod.status === 200 && mod.body.DownloadsRemaining === 7, `modify answered ${mod.status}`);
    const dup = await api('POST', '/api/files/duplicate', { headers: { id: state.chunkFile, originalPassword: 'true' } });
    check(dup.status === 200 && dup.body.IsPasswordProtected, `duplicate answered ${dup.status} ${JSON.stringify(dup.body).slice(0, 160)}`);
    const del = await api('DELETE', '/api/files/delete', { headers: { id: dup.body.Id } });
    check(del.status === 200, `delete answered ${del.status}`);
    const gone = await api('GET', `/api/files/list/${dup.body.Id}`);
    check(gone.status === 404, `deleted file still answers ${gone.status}`);
  });
  current = admin;
  await step('E10', 'Revoking a permission blocks that call; deleting the key blocks everything', async () => {
    need('apiKeyRow', 'apiKey');
    await admin.goto(BASE + '/apiKeys');
    await admin.click(`#perm_upload_${state.apiKeyRow}`);
    await admin.waitForFunction(id => document.getElementById(id).classList.contains('perm-notgranted'), `perm_upload_${state.apiKeyRow}`, { timeout: 5000 });
    const refused = await api('POST', '/api/files/add', { form: { file: pdf('revoked'), password: '1234' } });
    check(refused.status === 403 || refused.status === 401, `upload without permission answered ${refused.status}`);
    await admin.click(`#delete-${state.apiKeyRow}`);
    await admin.locator(`#row-${state.apiKeyRow}`).waitFor({ state: 'detached', timeout: 5000 });
    const dead = await api('GET', '/api/files/list');
    check(dead.status === 401, `deleted key answered ${dead.status}`);
  });

  // ── F. Users ────────────────────────────────────────────────────────────
  const staffName = `staff${RUN}`;
  await step('F1', 'The users page adds a new user', async () => {
    await admin.goto(BASE + '/users');
    await admin.click('#add-user-btn');
    await admin.fill('#e_userName', staffName);
    await admin.click('#mb_addUser');
    const row = admin.locator('#usertable tr', { hasText: staffName });
    await row.first().waitFor({ timeout: 10000 });
    state.staffId = (await row.first().getAttribute('id')).slice(4);
  });
  await step('F2', 'Reset password generates a one-time password for the user', async () => {
    need('staffId');
    await admin.reload();
    await admin.click(`#pwchange-${state.staffId}`);
    await admin.locator('#resetPasswordModal').waitFor({ state: 'visible' });
    if (!(await admin.isChecked('#generateRandomPassword'))) await admin.check('#generateRandomPassword');
    await admin.click('#resetPasswordButton');
    await admin.locator('#l_returnedPw').waitFor({ state: 'visible', timeout: 10000 });
    state.staffPw = (await admin.locator('#l_returnedPw').innerText()).trim();
    check(state.staffPw.length >= 8, 'no password returned');
    await admin.click('#closeModalResetPw');
  });
  await step('F3', 'The user gets the list permission from the page', async () => {
    need('staffId');
    await admin.reload();
    const id = `perm_list_${state.staffId}`;
    await admin.click(`#${id}`);
    await admin.waitForFunction(i => document.getElementById(i).classList.contains('perm-granted'), id, { timeout: 5000 });
  });
  current = staff;
  await step('F4', 'The user signs in with the one-time password and must change it first', async () => {
    need('staffPw');
    await login(staff, staffName, state.staffPw);
    check(/changePassword/i.test(staff.url()), `ended on ${staff.url()}`);
    await staff.goto(BASE + '/admin');
    check(/changePassword/i.test(staff.url()), 'other pages are reachable before the change');
  });
  await step('F5', 'The user sets a new password and reaches the upload page', async () => {
    need('staffPw');
    state.staffNewPw = `New-${RUN}-pw-2026`;
    await staff.goto(BASE + '/changePassword');
    await staff.fill('#newpw', state.staffNewPw);
    await staff.fill('#newpw_c', state.staffNewPw);
    await submit(staff);
    if (/login/.test(staff.url())) await login(staff, staffName, state.staffNewPw);
    check(/\/admin$/.test(staff.url()), `ended on ${staff.url()}`);
  });
  await step('F6', 'The user (no users/logs permission) cannot open the users or logs pages', async () => {
    need('staffNewPw');
    for (const p of ['/users', '/logs']) {
      await staff.goto(BASE + p);
      check(!staff.url().endsWith(p), `${p} opened`);
    }
  });
  await step('F7', 'With the list permission the user sees the admin\'s files', async () => {
    need('staffNewPw', 'adminFile');
    await staff.goto(BASE + '/admin');
    check(await staff.locator(`#row-${state.adminFile}`).count() === 1, "the admin's file is not listed");
  });
  current = admin;
  await step('F8', 'Promote the user to admin and back', async () => {
    need('staffId');
    await admin.goto(BASE + '/users');
    await Promise.all([admin.waitForEvent('load'), admin.click(`#changeRank_${state.staffId}`)]);
    check(/admin/i.test(await admin.locator(`#userlevel_${state.staffId}`).innerText()), 'not admin after promote');
    await Promise.all([admin.waitForEvent('load'), admin.click(`#changeRank_${state.staffId}`)]);
    check(/user/i.test(await admin.locator(`#userlevel_${state.staffId}`).innerText()), 'not user after demote');
  });
  await step('F9', 'Deleting the user ends their session', async () => {
    need('staffId');
    await admin.goto(BASE + '/users');
    await admin.click(`#delete-${state.staffId}`);
    await admin.locator('#deleteModal').waitFor({ state: 'visible' });
    if (await admin.locator('#checkboxDelete').isVisible()) await admin.check('#checkboxDelete');
    await admin.click('#buttonDelete');
    await admin.locator(`#row-${state.staffId}`).waitFor({ state: 'detached', timeout: 10000 });
    await staff.goto(BASE + '/admin');
    check(/login/.test(staff.url()), `the deleted user still reaches ${staff.url()}`);
  });

  // ── G. Lock after 5 wrong codes ─────────────────────────────────────────
  current = customerEn;
  await step('G1', 'Five wrong codes lock the link; the right code is then refused too', async () => {
    // The key was deleted in E10, so the locked file is uploaded from the admin page.
    await admin.goto(BASE + '/admin');
    await admin.fill('#password', '5555');
    await admin.setInputFiles('input.dz-hidden-input', { name: `lock-${RUN}.pdf`, mimeType: 'application/pdf', buffer: pdf('lock') });
    const { id } = await adminRow(admin, `lock-${RUN}.pdf`, 30000);
    for (let i = 0; i < 5; i++) await enterCode(customerEn, id, '0000');
    await customerEn.getByText('locked after 5 wrong attempts').waitFor({ timeout: 5000 });
    // Like the legacy page, the form is shown again on the next visit; the right code must still be refused.
    await enterCode(customerEn, id, '5555');
    await customerEn.getByText('locked after 5 wrong attempts').waitFor({ timeout: 5000 });
    check(await customerEn.locator('a[href*="downloadFile"]').count() === 0, 'the right code opened a locked link');
  });
  await step('G2', 'An unknown link shows "Link not valid"', async () => {
    await customerEn.goto(`${BASE}/d?id=doesnotexist${RUN}`);
    await customerEn.getByText('Link not valid').waitFor({ timeout: 5000 });
  });

  // ── H. Logs and status ──────────────────────────────────────────────────
  current = admin;
  await step('H1', 'The status page shows uptime, files and the log with this run\'s events', async () => {
    await admin.goto(BASE + '/logs');
    await admin.waitForFunction(() => !document.getElementById('logviewer').value.includes('Loading'), null, { timeout: 15000 });
    const log = await admin.locator('#logviewer').inputValue();
    for (const word of [`statement-${RUN}.pdf`, 'Wrong password', staffName])
      check(log.includes(word), `the log has no "${word}"`);
    check((await admin.locator('#uptime').innerText()).trim().length > 0, 'no uptime');
  });
  await step('H2', 'The log filter "Downloads" shows only downloads', async () => {
    await admin.selectOption('#logFilter', 'download');
    await sleep(500);
    const lines = (await admin.locator('#logviewer').inputValue()).split('\n').filter(l => l.trim());
    check(lines.length > 0, 'no download lines');
    check(lines.every(l => /download/i.test(l)), 'other lines are shown: ' + lines.find(l => !/download/i.test(l)));
  });
  await step('H3', 'Reset traffic and delete old logs work', async () => {
    await admin.click('button[onclick="resetTrafficStat()"]');
    await sleep(1000);
    await admin.selectOption('#deleteLogsSel', '30');
    await admin.click('button[onclick="deleteLogs()"]');
    await sleep(1500);
  });

  // ── I. Clean-up and sign-out ────────────────────────────────────────────
  await step('I1', 'The admin deletes the test file for good (no undo)', async () => {
    need('adminFile');
    await admin.goto(BASE + '/admin');
    await admin.click(`#button-delete-${state.adminFile}`);
    await admin.locator(`#row-${state.adminFile}`).waitFor({ state: 'detached', timeout: 10000 }).catch(() => {});
    await sleep(11000); // the undo window is 10 s
    await customerAr.goto(`${BASE}/d?id=${state.adminFile}`);
    check(await customerAr.locator('#passwordFile').count() === 0, 'the deleted link still asks for a code');
  });
  await step('I2', 'Sign-out ends the session', async () => {
    await admin.goto(BASE + '/admin');
    await admin.getByText('Logout', { exact: true }).click();
    await admin.waitForURL(/login/, { timeout: 5000 });
    await admin.goto(BASE + '/admin');
    check(/login/.test(admin.url()), 'still signed in');
  });

  await browser.close();
  const failed = results.filter(r => !r.ok);
  console.log(`\n${results.length - failed.length} passed, ${failed.length} failed (screenshots of failures: ${OUT})`);
  fs.writeFileSync(path.join(OUT, 'results.json'), JSON.stringify({ run: RUN, base: BASE, results }, null, 2));
  process.exit(failed.length ? 1 : 0);
})();
