/* 共享 reactive 状态 (toast 栈, 包流缓冲) */
const { ref, reactive, computed } = window.Vue;

let _toastId = 0;
export function useToasts() {
  const list = ref([]);
  function push({ kind = 'info', title = '', body = '', duration = 4500 } = {}) {
    const id = ++_toastId;
    list.value.push({ id, kind, title, body });
    setTimeout(() => {
      const i = list.value.findIndex(t => t.id === id);
      if (i >= 0) list.value.splice(i, 1);
    }, duration);
  }
  return { list, push };
}

export function useStream({ capacity = 5000 } = {}) {
  const items = ref([]);              // 环形缓冲
  const expanded = ref(new Set());    // 展开的 seq 集合
  const maxItems = ref(capacity);
  const ordinalBySeq = new Map();
  let headOrdinal = 0;
  let nextOrdinal = 0;
  // 实时 1 秒桶, 由 sparkline 每秒拍快照后清零
  const lastSecond = ref({ c2s: 0, s2c: 0 });

  function trimToCapacity() {
    if (items.value.length > maxItems.value) {
      const drop = items.value.length - maxItems.value;
      const dropped = items.value.splice(0, drop);
      headOrdinal += drop;
      for (const d of dropped) {
        expanded.value.delete(d.seq);
        ordinalBySeq.delete(d.seq);
      }
      return dropped;
    }
    return [];
  }

  function push(ev) {
    ordinalBySeq.set(ev.seq, nextOrdinal++);
    items.value.push(ev);
    const dropped = trimToCapacity();
    if (ev.type === 'packet') {
      if (ev.direction === 'c2s') lastSecond.value.c2s += 1;
      else if (ev.direction === 's2c') lastSecond.value.s2c += 1;
    }
    return dropped;
  }

  function update(seq, patch) {
    const ordinal = ordinalBySeq.get(seq);
    if (ordinal == null) return null;
    const idx = ordinal - headOrdinal;
    if (idx < 0 || idx >= items.value.length) return null;
    const updated = { ...items.value[idx], ...patch };
    items.value.splice(idx, 1, updated);
    return updated;
  }

  function clear() {
    items.value = [];
    expanded.value = new Set();
    ordinalBySeq.clear();
    headOrdinal = 0;
    nextOrdinal = 0;
  }

  function toggleExpand(seq) {
    const s = new Set(expanded.value);
    if (s.has(seq)) s.delete(seq); else s.add(seq);
    expanded.value = s;
  }

  function fmtTime(ts) {
    const d = new Date(ts * 1000);
    const pad = (n, w = 2) => String(n).padStart(w, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  function tickSecond() {
    lastSecond.value = { c2s: 0, s2c: 0 };
  }

  function setCapacity(nextCapacity) {
    const n = Number(nextCapacity);
    maxItems.value = Number.isFinite(n) ? Math.max(100, Math.min(100000, Math.floor(n))) : capacity;
    return trimToCapacity();
  }

  return { items, expanded, maxItems, push, update, clear, toggleExpand, fmtTime, lastSecond, tickSecond, setCapacity };
}
