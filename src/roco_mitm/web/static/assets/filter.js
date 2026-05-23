/* 过滤器 DSL.
 *
 *   key=val          相等 (大小写不敏感, opcode 接受 0x.. / 十进制)
 *   key~val          子串包含 (大小写不敏感)
 *   key>val key<val  数值比较
 *   has_error        快捷布尔
 *   has_schema       仅显示已解码的
 *   多个表达式用空格 (=AND), '|' (OR), '&' (AND, 显式) 连接
 *
 * 支持的 key:
 *   dir          c2s/s2c
 *   opcode       事件 opcode hex/十进制
 *   cat / category
 *   name         opcode_meta.name
 *   sub_id       internal.sub_id_hex
 *   kind         事件 kind: data / heartbeat / ack / inject / ...
 *   payload      payload_hex 子串
 *
 * 例:
 *   dir=s2c opcode=0x03DD
 *   cat=friend & name~Friend
 *   dir=c2s | kind=inject
 */

const VALID_KEYS = new Set(['dir', 'opcode', 'cat', 'category', 'name', 'sub_id', 'kind', 'payload']);
const VALID_FLAGS = new Set(['has_error', 'has_schema', 'has_decoded', 'is_inject']);

function _normalize(v) { return String(v ?? '').toLowerCase(); }

function _opcodeNum(s) {
  if (typeof s === 'number') return s;
  if (s == null) return null;
  s = String(s).trim();
  if (s.toLowerCase().startsWith('0x')) {
    const n = parseInt(s, 16); return Number.isFinite(n) ? n : null;
  }
  const n = parseInt(s, 10);
  return Number.isFinite(n) ? n : null;
}

function _evalKv(ev, key, op, raw) {
  const wanted = String(raw);
  switch (key) {
    case 'dir': return _cmp(ev.direction, op, wanted);
    case 'kind': return _cmp(ev.kind, op, wanted);
    case 'cat':
    case 'category': return _cmp(ev.opcode_meta?.category, op, wanted);
    case 'name': return _cmp(ev.opcode_meta?.name, op, wanted);
    case 'sub_id': return _cmp(ev.internal?.sub_id_hex, op, wanted);
    case 'payload': return _cmp(ev.payload_hex, op, wanted);
    case 'opcode': {
      const lhs = ev.opcode;
      const rhs = _opcodeNum(wanted);
      if (lhs == null || rhs == null) return false;
      if (op === '=') return lhs === rhs;
      if (op === '~') return ev.opcode_hex?.toLowerCase().includes(_normalize(wanted));
      if (op === '>') return lhs > rhs;
      if (op === '<') return lhs < rhs;
      return false;
    }
  }
  return false;
}

function _cmp(value, op, wanted) {
  const v = _normalize(value);
  const w = _normalize(wanted);
  if (op === '=') return v === w;
  if (op === '~') return v.includes(w);
  if (op === '>' || op === '<') {
    const a = parseFloat(v), b = parseFloat(w);
    if (Number.isFinite(a) && Number.isFinite(b)) return op === '>' ? a > b : a < b;
    return false;
  }
  return false;
}

function _evalFlag(ev, flag) {
  switch (flag) {
    case 'has_error': return Boolean(ev.error || ev.decode_error || ev.kind === 'data_decrypt_failed');
    case 'has_schema':
    case 'has_decoded': return Boolean(ev.decoded);
    case 'is_inject': return ev.kind === 'inject';
  }
  return false;
}

/** 把表达式拆成 token: word, '=', '~', '>', '<', '&', '|' */
function tokenize(text) {
  const tokens = [];
  const s = text.trim();
  let i = 0;
  const isWS = c => c === ' ' || c === '\t';
  while (i < s.length) {
    const c = s[i];
    if (isWS(c)) { i++; continue; }
    if (c === '|' || c === '&') { tokens.push({ kind: 'op', val: c }); i++; continue; }
    let j = i;
    while (j < s.length && !isWS(s[j]) && s[j] !== '|' && s[j] !== '&') j++;
    const word = s.slice(i, j);
    const m = word.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*([=~><])\s*(.*)$/);
    if (m) {
      tokens.push({ kind: 'kv', key: m[1].toLowerCase(), op: m[2], val: m[3] });
    } else {
      tokens.push({ kind: 'flag', val: word.toLowerCase() });
    }
    i = j;
  }
  return tokens;
}

/** 编译: 默认 AND 连接, '|' 优先级最低; 返回 (event)=>bool */
export function compileFilter(text) {
  const tokens = tokenize(text);
  if (tokens.length === 0) return null;
  for (const t of tokens) {
    if (t.kind === 'kv' && !VALID_KEYS.has(t.key)) {
      throw new Error(`未知过滤键: ${t.key}; 可用: ${[...VALID_KEYS].join(', ')}`);
    }
    if (t.kind === 'flag' && !VALID_FLAGS.has(t.val)) {
      throw new Error(`未知标志: ${t.val}; 可用: ${[...VALID_FLAGS].join(', ')}`);
    }
  }
  const orGroups = [[]];
  for (const t of tokens) {
    if (t.kind === 'op' && t.val === '|') { orGroups.push([]); continue; }
    if (t.kind === 'op' && t.val === '&') continue;  // 默认就是 AND
    orGroups[orGroups.length - 1].push(t);
  }
  return (ev) => {
    return orGroups.some(group => {
      if (group.length === 0) return true;
      return group.every(t => {
        if (t.kind === 'kv') return _evalKv(ev, t.key, t.op, t.val);
        if (t.kind === 'flag') return _evalFlag(ev, t.val);
        return true;
      });
    });
  };
}
