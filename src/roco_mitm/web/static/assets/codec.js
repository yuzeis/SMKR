/* 表单值默认 / 类型转换助手. 真正的编码走后端 /api/encode. */

const NUMERIC = new Set([
  'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64',
  'fixed32', 'fixed64', 'sfixed32', 'sfixed64', 'float', 'double',
  'enum',
]);

function _baseType(t) {
  if (!t) return '';
  const i = t.indexOf('<');
  return (i >= 0 ? t.slice(0, i) : t).trim();
}

/** 给单个字段算一个空值 (供新增 repeated item / 初始表单使用). */
export function fieldDefault(field) {
  if (!field) return null;
  if (field.repeated) return [];
  const base = _baseType(field.type);
  if (base === 'message') {
    if (field.fields) return computeSchemaFormDefault(field.fields);
    return {}; // 未解析的 ref - 留空对象, 用户可切到 JSON 模式手填
  }
  if (base === 'bool') return false;
  if (NUMERIC.has(base)) return 0;
  if (base === 'string') return '';
  if (base === 'bytes') return '';
  return '';
}

/** 给 schema 的 fields 列表算整个对象的默认值. */
export function computeSchemaFormDefault(fields) {
  const out = {};
  if (!Array.isArray(fields)) return out;
  for (const f of fields) {
    if (!f || !f.name) continue;
    out[f.name] = fieldDefault(f);
  }
  return out;
}

/* 占位: 前端 hex<->form 不在这里做, 全部走后端. 保留 export 以稳定接口. */
export function encodeFormToHex() { throw new Error('请使用 /api/encode'); }
export function decodeHexToForm() { throw new Error('请使用 /api/decode'); }
