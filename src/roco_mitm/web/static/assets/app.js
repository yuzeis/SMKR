/* RKMS Web UI — Vue 3 app
 * 使用全局 Vue (window.Vue), 不引入构建系统。
 */
import { computeSchemaFormDefault, fieldDefault } from '/assets/codec.js';
import { compileFilter } from '/assets/filter.js';
import { useToasts, useStream } from '/assets/store.js';

const { createApp, ref, reactive, computed, watch, onMounted, onBeforeUnmount, nextTick, h } = window.Vue;

clearTimeout(window.__rkms_vue_failed);

const DEFAULT_SETTINGS = {
  theme: 'dark',
  stream: {
    max_events: 5000,
    default_filter: '',
    hide_plaintext_short: true,
    hide_decrypt_failed: false,
    hide_no_schema: false,
    hide_unknown_fields: false,
    hide_common_noise: true,
    hidden_opcodes: '0x9001, 0x013D, 0x013F',
  },
  services: {
    http: {
      enabled: true,
      host: '127.0.0.1',
      port: 18196,
      allow_remote: false,
      public_url: '',
    },
    mcp: {
      enabled: false,
      host: '127.0.0.1',
      port: 18210,
      auth_token: '',
      allow_inject: false,
      allow_rfn_exec: false,
      allow_rfn_import: false,
    },
  },
  proxy: {
    s2c_passthrough_after_key: false,
    observe_s2c: true,
    allow_s2c_inject: false,
    observe_c2s: true,
    c2s_batch_packets: 64,
    c2s_batch_bytes: 262144,
    c2s_drain_interval_ms: 0,
    observe_queue_max: 2000,
  },
  observe: {
    auto_decode_packets: false,
    decode_on_click: true,
    rfn_active_watch_only: true,
    rfn_passive_packet_seen: false,
  },
  perf: {
    detail_max_seconds: 60,
    detail_max_events: 20000,
    snapshot_interval_ms: 1000,
  },
};
const STREAM_RENDER_LIMIT = 300;
const SCROLL_THROTTLE_MS = 50;

function migrateSettingsInput(input) {
  const next = { ...(input || {}) };
  const services = { ...(next.services || {}) };
  if (services.https && !services.http) {
    const legacy = services.https || {};
    services.http = {
      enabled: Boolean(legacy.enabled),
      host: legacy.host || '127.0.0.1',
      port: Number(legacy.port) || 18196,
      allow_remote: legacy.host && !['127.0.0.1', 'localhost', '::1'].includes(String(legacy.host)),
      public_url: '',
    };
  }
  delete services.https;
  next.services = services;
  return next;
}

function deepMerge(base, patch) {
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const [key, value] of Object.entries(patch || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base?.[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      out[key] = deepMerge(base[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function sanitizeSettings(input) {
  const next = deepMerge(DEFAULT_SETTINGS, migrateSettingsInput(input));
  next.theme = ['dark', 'light', 'system'].includes(next.theme) ? next.theme : 'dark';
  next.stream.max_events = Math.max(100, Math.min(100000, Number(next.stream.max_events) || 5000));
  if (Array.isArray(next.stream.hidden_opcodes)) {
    next.stream.hidden_opcodes = next.stream.hidden_opcodes.join(', ');
  } else {
    next.stream.hidden_opcodes = String(next.stream.hidden_opcodes || '');
  }
  next.services.http.port = Math.max(1, Math.min(65535, Number(next.services.http.port) || 18196));
  next.services.http.public_url = String(next.services.http.public_url || '');
  next.services.mcp.port = Math.max(1, Math.min(65535, Number(next.services.mcp.port) || 18210));
  next.services.mcp.auth_token = String(next.services.mcp.auth_token || '');
  next.proxy.s2c_passthrough_after_key = Boolean(next.proxy.s2c_passthrough_after_key);
  next.proxy.observe_s2c = Boolean(next.proxy.observe_s2c);
  next.proxy.allow_s2c_inject = Boolean(next.proxy.allow_s2c_inject);
  next.proxy.observe_c2s = Boolean(next.proxy.observe_c2s);
  next.proxy.c2s_batch_packets = Math.max(1, Math.min(1024, Number(next.proxy.c2s_batch_packets) || 64));
  next.proxy.c2s_batch_bytes = Math.max(1024, Math.min(8 * 1024 * 1024, Number(next.proxy.c2s_batch_bytes) || 262144));
  next.proxy.c2s_drain_interval_ms = Math.max(0, Math.min(1000, Number(next.proxy.c2s_drain_interval_ms) || 0));
  next.proxy.observe_queue_max = Math.max(0, Math.min(100000, Number(next.proxy.observe_queue_max) || 0));
  next.observe.auto_decode_packets = Boolean(next.observe.auto_decode_packets);
  next.observe.decode_on_click = Boolean(next.observe.decode_on_click);
  next.observe.rfn_active_watch_only = Boolean(next.observe.rfn_active_watch_only);
  next.observe.rfn_passive_packet_seen = Boolean(next.observe.rfn_passive_packet_seen);
  next.perf.detail_max_seconds = Math.max(1, Math.min(3600, Number(next.perf.detail_max_seconds) || 60));
  next.perf.detail_max_events = Math.max(100, Math.min(1000000, Number(next.perf.detail_max_events) || 20000));
  next.perf.snapshot_interval_ms = Math.max(250, Math.min(10000, Number(next.perf.snapshot_interval_ms) || 1000));
  return next;
}

function normalizeOpcodeToken(value) {
  if (value == null || value === '') return '';
  if (typeof value === 'number') {
    const n = value > 0xFFFF ? (value & 0xFFFF) : value;
    return `0x${n.toString(16).toUpperCase().padStart(4, '0')}`;
  }
  const text = String(value).trim();
  if (!text) return '';
  const n = text.toLowerCase().startsWith('0x') ? Number.parseInt(text.slice(2), 16) : Number.parseInt(text, 16);
  if (!Number.isFinite(n)) return text.toUpperCase();
  const op = n > 0xFFFF ? (n & 0xFFFF) : n;
  return `0x${op.toString(16).toUpperCase().padStart(4, '0')}`;
}

function parseOpcodeSet(text) {
  const out = new Set();
  for (const token of String(text || '').split(/[\s,;，；]+/)) {
    const normalized = normalizeOpcodeToken(token);
    if (normalized) out.add(normalized);
  }
  return out;
}

function copyWithoutUnknown(value) {
  if (Array.isArray(value)) return value.map(copyWithoutUnknown);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    if (key !== '_unknown') out[key] = copyWithoutUnknown(child);
  }
  return out;
}

class RkmsClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.handlers = {};
    this.requests = new Map(); // rid → resolve
    this._rid = 0;
    this._reconnectMs = 600;
  }
  on(event, fn) { (this.handlers[event] = this.handlers[event] || []).push(fn); }
  emit(event, ...args) { (this.handlers[event] || []).forEach(fn => fn(...args)); }

  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.onopen = () => { this.emit('open'); this._reconnectMs = 600; };
    this.ws.onclose = () => {
      this.emit('close');
      setTimeout(() => this.connect(), this._reconnectMs);
      this._reconnectMs = Math.min(this._reconnectMs * 1.5, 5000);
    };
    this.ws.onerror = () => {
      try { this.ws?.close(); } catch {}
    };
    this.ws.onmessage = (e) => {
      let data;
      try { data = JSON.parse(e.data); } catch { return; }
      this._dispatch(data);
    };
  }

  _dispatch(msg) {
    if (msg.type === 'batch') {
      msg.events.forEach(ev => this._dispatch(ev));
      return;
    }
    if (msg.rid != null && this.requests.has(msg.rid)) {
      const { resolve, reject } = this.requests.get(msg.rid);
      this.requests.delete(msg.rid);
      if (msg.type === 'error') reject(new Error(msg.error));
      else resolve(msg);
      return;
    }
    this.emit(msg.type, msg);
    this.emit('*', msg);
  }

  send(op, data = {}) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error('WS 未连接'));
    }
    const rid = ++this._rid;
    return new Promise((resolve, reject) => {
      this.requests.set(rid, { resolve, reject });
      this.ws.send(JSON.stringify({ op, rid, ...data }));
      setTimeout(() => {
        if (this.requests.has(rid)) {
          this.requests.delete(rid);
          reject(new Error('请求超时'));
        }
      }, 8000);
    });
  }
}

const FieldNode = {
  name: 'FieldNode',
  props: ['name', 'value', 'depth'],
  setup(props) {
    const valueClass = computed(() => {
      const v = props.value;
      if (typeof v === 'string') return 'string';
      if (typeof v === 'boolean') return 'bool';
      if (v && typeof v === 'object' && '_hex' in v) return 'bytes';
      return '';
    });
    const isMessage = computed(() => {
      const v = props.value;
      return v && typeof v === 'object' && !Array.isArray(v) && !('_hex' in v) && !('_raw' in v);
    });
    const isArray = computed(() => Array.isArray(props.value));
    const isEmptyMessage = computed(() => {
      if (!isMessage.value) return false;
      return Object.keys(props.value || {}).length === 0;
    });
    const formatted = computed(() => {
      const v = props.value;
      if (v == null) return '∅';
      if (typeof v === 'string') return JSON.stringify(v);
      if (typeof v === 'boolean') return v ? 'true' : 'false';
      if (v && typeof v === 'object') {
        if ('_hex' in v) return `<bytes ${v._hex.length / 2}B ${v._hex.slice(0, 32)}${v._hex.length > 32 ? '…' : ''}>`;
        if ('_raw' in v) return `<raw ${JSON.stringify(v._raw)}>`;
      }
      return String(v);
    });
    function formatUnknownValue(v) {
      if (v == null) return '';
      if (typeof v === 'string') return v;
      return JSON.stringify(v);
    }
    return { valueClass, isMessage, isArray, isEmptyMessage, formatted, formatUnknownValue };
  },
  template: `
    <li>
      <div class="tree-node">
        <span class="field-name">{{ name }}</span>
        <span class="field-type">{{ isArray ? 'repeated' : (isMessage ? 'message' : '') }}</span>
        <span class="field-val" :class="valueClass" v-if="!isMessage && !isArray">{{ formatted }}</span>
        <span class="field-val" v-else-if="isArray">[{{ value.length }}]</span>
        <span class="field-val muted" v-else-if="isEmptyMessage">(empty)</span>
        <span class="field-val" v-else></span>
      </div>
      <ul v-if="isArray">
        <field-node v-for="(item, idx) in value" :key="idx" :name="'['+idx+']'" :value="item" :depth="(depth||0)+1" />
      </ul>
      <ul v-else-if="isMessage && !isEmptyMessage">
        <template v-for="(v, k) in value" :key="k">
          <field-node v-if="k !== '_unknown'" :name="k" :value="v" :depth="(depth||0)+1" />
          <li v-else class="unknown-tag">
            未知字段 × {{ v.length }}
            <ul class="unknown-list">
              <li v-for="(u, i) in v" :key="i">
                #{{ u.no }} wt={{ u.wire }}<span v-if="u.reason"> · {{ u.reason }}</span>
                <span class="mono" v-if="u.value !== undefined"> · {{ formatUnknownValue(u.value) }}</span>
              </li>
            </ul>
          </li>
        </template>
      </ul>
    </li>
  `,
};

const FieldInput = {
  name: 'FieldInput',
  props: ['field', 'modelValue'],
  emits: ['update:modelValue'],
  setup(props, { emit }) {
    const baseType = computed(() => (props.field.type || '').replace(/<.*$/, ''));
    const isMessage = computed(() => baseType.value === 'message');
    const isBool = computed(() => baseType.value === 'bool');
    const isString = computed(() => baseType.value === 'string');
    const isBytes = computed(() => baseType.value === 'bytes');

    function update(v) { emit('update:modelValue', v); }
    function castNum(v) {
      if (v === '' || v == null) return null;
      const n = Number(v);
      return Number.isFinite(n) ? n : v;
    }

    function addRepeatedItem() {
      const arr = Array.isArray(props.modelValue) ? [...props.modelValue] : [];
      arr.push(fieldDefault({ ...props.field, repeated: false }));
      update(arr);
    }
    function removeItemAt(i) {
      const arr = [...(props.modelValue || [])];
      arr.splice(i, 1);
      update(arr);
    }
    function setItemAt(i, v) {
      const arr = [...(props.modelValue || [])];
      arr[i] = v;
      update(arr);
    }

    return { baseType, isMessage, isBool, isString, isBytes, update, castNum,
             addRepeatedItem, removeItemAt, setItemAt };
  },
  template: `
    <!-- repeated -->
    <div v-if="field.repeated" class="repeated-list">
      <div v-for="(item, i) in (modelValue || [])" :key="i" class="repeated-item">
        <field-input
          :field="{...field, repeated: false}"
          :model-value="item"
          @update:model-value="(v) => setItemAt(i, v)" />
        <button class="btn btn-icon btn-danger" @click="removeItemAt(i)" title="删除">×</button>
      </div>
      <button class="btn btn-ghost" @click="addRepeatedItem">+ 添加项</button>
    </div>
    <!-- message -->
    <div v-else-if="isMessage" class="message-box">
      <div v-if="field.fields && field.fields.length === 0" class="empty-state" style="height:auto;padding:8px;">
        (该 message 未定义字段)
      </div>
      <div v-else-if="!field.fields" class="empty-state" style="height:auto;padding:8px;">
        ⚠ 未解析的 message 引用<span v-if="field.ref"> ({{ field.ref }})</span>
      </div>
      <template v-else>
        <div v-for="sub in field.fields" :key="sub.no" class="field-row" :class="{ message: (sub.type||'').startsWith('message') }">
          <div class="label">
            <span><b>{{ sub.name }}</b><span class="desc" v-if="sub.desc">— {{ sub.desc }}</span></span>
            <span class="meta">#{{ sub.no }} · {{ sub.type }}{{ sub.repeated ? ' (repeated)' : '' }}</span>
          </div>
          <div class="control">
            <field-input
              :field="sub"
              :model-value="(modelValue || {})[sub.name]"
              @update:model-value="(v) => update({ ...(modelValue || {}), [sub.name]: v })" />
          </div>
        </div>
      </template>
    </div>
    <!-- bool -->
    <select v-else-if="isBool" :value="modelValue ? '1' : '0'" @change="(e) => update(e.target.value === '1')">
      <option value="0">false</option>
      <option value="1">true</option>
    </select>
    <!-- string -->
    <input v-else-if="isString" type="text" :value="modelValue ?? ''" @input="(e) => update(e.target.value)" />
    <!-- bytes -->
    <input v-else-if="isBytes" type="text" placeholder="hex (e.g. 0a1b2c)" :value="modelValue ?? ''"
           @input="(e) => update(e.target.value)" />
    <!-- numeric / enum -->
    <input v-else type="text" :placeholder="field.type" :value="modelValue ?? ''"
           @input="(e) => update(castNum(e.target.value))" />
  `,
};

const OpcodePicker = {
  name: 'OpcodePicker',
  props: ['opcodes', 'selected'],
  emits: ['select'],
  setup(props, { emit }) {
    const query = ref('');
    const open = ref(false);
    const activeIdx = ref(0);
    const inputRef = ref(null);

    const filtered = computed(() => {
      const q = query.value.trim().toLowerCase();
      if (!q) return props.opcodes.slice(0, 200);
      const exactHex = q.startsWith('0x') ? q.toUpperCase() : null;
      const num = q.match(/^\d+$/) ? parseInt(q, 10) : null;
      return props.opcodes.filter(o => {
        if (exactHex && o.hex.toUpperCase().includes(exactHex)) return true;
        if (num != null && o.id === num) return true;
        if ((o.hex || '').toLowerCase().includes(q)) return true;
        if ((o.name || '').toLowerCase().includes(q)) return true;
        if ((o.category || '').toLowerCase() === q) return true;
        if ((o.desc || '').toLowerCase().includes(q)) return true;
        return false;
      }).slice(0, 200);
    });

    function pick(o) {
      emit('select', o);
      query.value = '';
      open.value = false;
    }

    function onKeydown(e) {
      if (!open.value) return;
      if (e.key === 'ArrowDown') { activeIdx.value = Math.min(activeIdx.value + 1, filtered.value.length - 1); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { activeIdx.value = Math.max(activeIdx.value - 1, 0); e.preventDefault(); }
      else if (e.key === 'Enter')   { const o = filtered.value[activeIdx.value]; if (o) pick(o); e.preventDefault(); }
      else if (e.key === 'Escape')  { open.value = false; }
    }

    function onBlur() { setTimeout(() => { open.value = false; }, 180); }
    function onFocus() { open.value = true; activeIdx.value = 0; }

    const display = computed(() => {
      if (open.value) return query.value;
      if (props.selected) return `${props.selected.hex} · ${props.selected.name || ''}`;
      return query.value;
    });

    return { query, open, activeIdx, filtered, pick, onKeydown, onBlur, onFocus, inputRef, display };
  },
  template: `
    <div class="opcode-picker">
      <input
        class="opcode-input mono"
        ref="inputRef"
        :value="display"
        @input="(e) => { query = e.target.value; open = true; activeIdx = 0; }"
        @focus="onFocus" @blur="onBlur" @keydown="onKeydown"
        placeholder="搜索 opcode (0x03DD / Friend / cat=friend / 1852…)" />
      <div class="opcode-list" v-if="open && filtered.length">
        <div v-for="(o, i) in filtered" :key="o.hex"
             class="item" :class="{ active: i === activeIdx }"
             @mousedown.prevent="pick(o)" @mouseenter="activeIdx = i">
          <span class="hex">{{ o.hex }}</span>
          <span class="name">
            <span>{{ o.name || '(unnamed)' }}</span>
            <span class="desc" v-if="o.desc">{{ o.desc }}</span>
          </span>
          <span class="meta">
            <span class="dir-tag" :class="o.direction" v-if="o.direction">{{ o.direction }}</span>
            <span class="cat-tag" :class="o.category" v-if="o.category">{{ o.category }}</span>
          </span>
        </div>
      </div>
      <div class="opcode-list" v-else-if="open">
        <div class="item" style="grid-template-columns: 1fr; color: var(--text-4);">无匹配</div>
      </div>
    </div>
  `,
};

const App = {
  components: { FieldNode, FieldInput, OpcodePicker },
  setup() {
    const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
    const client = new RkmsClient(wsUrl);

    const status = reactive({
      connected: false,
      session_key_hex: '',
      session_key_ascii: '',
      upstream: '',
      ready_for_inject: false,
      c2s_count: 0,
      s2c_count: 0,
      last_gcp_seq: 0,
      c2s_seq_offset: 0,
      session_id_hex: '',
      registry_stats: { opcodes: 0, messages: 0 },
      ws_connected: false,
      services: deepMerge(DEFAULT_SETTINGS.services, {}),
    });
    const liveCounters = reactive({
      c2s: 0,
      s2c: 0,
      inject: 0,
    });
    const perf = reactive({
      window_sec: 0,
      process_cpu_pct: 0,
      system_cpu_pct: null,
      rss_mb: null,
      queue: { outbound_depth: 0, outbound_max: 0 },
      metrics: {},
    });
    const toasts = useToasts();
    const stream = useStream({ capacity: 5000 });
    const streamListRef = ref(null);
    const lastInject = ref(null);
    const injectReply = ref(null);
    const settings = reactive(sanitizeSettings({}));
    const showSettingsModal = ref(false);
    const settingsSaving = ref(false);
    const settingsError = ref('');
    const showRfnPanel = ref(false);
    const rfnConsole = reactive({
      loading: false,
      actionBusy: '',
      error: '',
      status: null,
      functions: [],
      bindings: { packet: [], http: [], schedule: [] },
      jobs: [],
      namespaces: [],
      cache: [],
      buffer: [],
      events: [],
      imports: [],
      rksStatus: null,
      execName: 'HttpCapDemo',
      execArgs: '[{"method":"GET","path":"/rfn/cap-demo","query":{}}]',
      execResult: null,
      jobResult: null,
      importName: 'scratch',
      importFunction: '',
      importArgs: '[]',
      importSource: '.function Main() -> any\n.no_side_effect true\n.deterministic true\n  map.from_pairs r0, "ok", true, "source", "imported"\n  ret r0\n.end',
      importResult: null,
    });
    const opcodes = ref([]); // [{ id, hex, name, direction, category, desc, schema_status }]
    const opcodesByHex = computed(() => {
      const m = {};
      for (const o of opcodes.value) m[o.hex] = o;
      return m;
    });
    const templates = ref([]);

    const filterText = ref('');
    const filterErr = ref('');
    const compiledFilter = computed(() => {
      filterErr.value = '';
      if (!filterText.value.trim()) return null;
      try {
        return compileFilter(filterText.value);
      } catch (e) {
        filterErr.value = e.message;
        return null;
      }
    });
    const visibleStream = ref([]);
    const renderedStream = computed(() => {
      const list = visibleStream.value;
      return list.length > STREAM_RENDER_LIMIT ? list.slice(-STREAM_RENDER_LIMIT) : list;
    });
    const hiddenOpcodeSet = computed(() => parseOpcodeSet(settings.stream.hidden_opcodes));
    const visibleOrdinalBySeq = new Map();
    let visibleHeadOrdinal = 0;
    let visibleNextOrdinal = 0;
    let scrollTimer = null;
    let scrollRaf = 0;
    let lastScrollAt = 0;

    function rebuildVisibleIndex() {
      visibleOrdinalBySeq.clear();
      visibleHeadOrdinal = 0;
      visibleNextOrdinal = 0;
      for (const ev of visibleStream.value) {
        visibleOrdinalBySeq.set(ev.seq, visibleNextOrdinal++);
      }
    }

    function trimVisibleToCapacity() {
      const maxItems = Math.max(100, Number(stream.maxItems.value) || 5000);
      if (visibleStream.value.length <= maxItems) return;
      const drop = visibleStream.value.length - maxItems;
      const dropped = visibleStream.value.splice(0, drop);
      visibleHeadOrdinal += drop;
      for (const ev of dropped) visibleOrdinalBySeq.delete(ev.seq);
    }

    function scheduleScrollBottom() {
      if (scrollTimer != null || scrollRaf) return;
      const now = performance.now();
      const delay = Math.max(0, SCROLL_THROTTLE_MS - (now - lastScrollAt));
      scrollTimer = window.setTimeout(() => {
        scrollTimer = null;
        nextTick(() => {
          scrollRaf = window.requestAnimationFrame(() => {
            scrollRaf = 0;
            lastScrollAt = performance.now();
            const el = streamListRef.value;
            if (el) el.scrollTop = el.scrollHeight;
          });
        });
      }, delay);
    }

    function eventPassesVisibleFilters(ev) {
      if (packetShouldBeHidden(ev)) return false;
      const f = compiledFilter.value;
      if (!f) return true;
      try { return f(ev); } catch { return true; }
    }

    function removeVisibleBySeq(seq) {
      const ordinal = visibleOrdinalBySeq.get(seq);
      if (ordinal == null) return;
      const idx = ordinal - visibleHeadOrdinal;
      if (idx < 0 || idx >= visibleStream.value.length) {
        visibleOrdinalBySeq.delete(seq);
        return;
      }
      if (idx === 0) {
        visibleStream.value.shift();
        visibleHeadOrdinal += 1;
        visibleOrdinalBySeq.delete(seq);
      } else {
        visibleStream.value.splice(idx, 1);
        rebuildVisibleIndex();
      }
    }

    function upsertVisibleEvent(ev, { scroll = true } = {}) {
      const displayEv = normalizePacketForDisplay(ev);
      const isVisible = eventPassesVisibleFilters(displayEv);
      const ordinal = visibleOrdinalBySeq.get(displayEv.seq);
      if (!isVisible) {
        if (ordinal != null) removeVisibleBySeq(displayEv.seq);
        return displayEv;
      }
      if (ordinal != null) {
        const idx = ordinal - visibleHeadOrdinal;
        if (idx >= 0 && idx < visibleStream.value.length) {
          visibleStream.value.splice(idx, 1, displayEv);
          return displayEv;
        }
        visibleOrdinalBySeq.delete(displayEv.seq);
      }
      visibleOrdinalBySeq.set(displayEv.seq, visibleNextOrdinal++);
      visibleStream.value.push(displayEv);
      trimVisibleToCapacity();
      if (scroll) scheduleScrollBottom();
      return displayEv;
    }

    function appendVisibleEvents(events) {
      if (!Array.isArray(events) || events.length === 0) return;
      const pendingVisible = [];
      let changed = false;
      for (const ev of events) {
        const displayEv = normalizePacketForDisplay(ev);
        maybeCaptureInjectReply(displayEv);
        const isVisible = eventPassesVisibleFilters(displayEv);
        const ordinal = visibleOrdinalBySeq.get(displayEv.seq);
        if (!isVisible) {
          if (ordinal != null) {
            removeVisibleBySeq(displayEv.seq);
            changed = true;
          }
          continue;
        }
        if (ordinal != null) {
          const idx = ordinal - visibleHeadOrdinal;
          if (idx >= 0 && idx < visibleStream.value.length) {
            visibleStream.value.splice(idx, 1, displayEv);
            changed = true;
          } else {
            visibleOrdinalBySeq.delete(displayEv.seq);
          }
          continue;
        }
        visibleOrdinalBySeq.set(displayEv.seq, visibleNextOrdinal++);
        pendingVisible.push(displayEv);
      }
      const chunkSize = 512;
      for (let i = 0; i < pendingVisible.length; i += chunkSize) {
        visibleStream.value.push(...pendingVisible.slice(i, i + chunkSize));
      }
      if (pendingVisible.length) {
        trimVisibleToCapacity();
        changed = true;
      }
      if (changed) scheduleScrollBottom();
    }

    function dropVisibleEvents(dropped) {
      if (!dropped || dropped.length === 0) return;
      let changed = false;
      for (const ev of dropped) {
        if (!visibleOrdinalBySeq.has(ev.seq)) continue;
        removeVisibleBySeq(ev.seq);
        changed = true;
      }
      if (changed) scheduleScrollBottom();
    }

    function rebuildVisibleStream() {
      const next = [];
      const maxItems = Math.max(100, Number(stream.maxItems.value) || 5000);
      for (const ev of stream.items.value) {
        const displayEv = normalizePacketForDisplay(ev);
        if (eventPassesVisibleFilters(displayEv)) next.push(displayEv);
      }
      visibleStream.value = next.length > maxItems ? next.slice(-maxItems) : next;
      rebuildVisibleIndex();
      scheduleScrollBottom();
    }

    watch([
      compiledFilter,
      () => settings.stream.hide_plaintext_short,
      () => settings.stream.hide_decrypt_failed,
      () => settings.stream.hide_no_schema,
      () => settings.stream.hide_unknown_fields,
      () => settings.stream.hide_common_noise,
      () => settings.stream.hidden_opcodes,
      () => stream.maxItems.value,
    ], rebuildVisibleStream);

    const paused = ref(false);
    let themeMedia = null;

    function applyTheme() {
      const requested = settings.theme || 'dark';
      const resolved = requested === 'system'
        ? (window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
        : requested;
      document.documentElement.dataset.theme = resolved;
      document.documentElement.dataset.themeMode = requested;
    }

    function applySettings({ applyDefaultFilter = false } = {}) {
      if (!['dark', 'light', 'system'].includes(settings.theme)) settings.theme = 'dark';
      const maxEvents = Math.max(100, Math.min(100000, Number(settings.stream.max_events) || 5000));
      if (settings.stream.max_events !== maxEvents) settings.stream.max_events = maxEvents;
      const httpPort = Math.max(1, Math.min(65535, Number(settings.services.http.port) || 18196));
      if (settings.services.http.port !== httpPort) settings.services.http.port = httpPort;
      const mcpPort = Math.max(1, Math.min(65535, Number(settings.services.mcp.port) || 18210));
      if (settings.services.mcp.port !== mcpPort) settings.services.mcp.port = mcpPort;
      settings.proxy.c2s_batch_packets = Math.max(1, Math.min(1024, Number(settings.proxy.c2s_batch_packets) || 64));
      settings.proxy.c2s_batch_bytes = Math.max(1024, Math.min(8 * 1024 * 1024, Number(settings.proxy.c2s_batch_bytes) || 262144));
      settings.proxy.c2s_drain_interval_ms = Math.max(0, Math.min(1000, Number(settings.proxy.c2s_drain_interval_ms) || 0));
      settings.proxy.observe_queue_max = Math.max(0, Math.min(100000, Number(settings.proxy.observe_queue_max) || 0));
      settings.observe.auto_decode_packets = Boolean(settings.observe.auto_decode_packets);
      settings.observe.decode_on_click = Boolean(settings.observe.decode_on_click);
      settings.observe.rfn_active_watch_only = Boolean(settings.observe.rfn_active_watch_only);
      settings.observe.rfn_passive_packet_seen = Boolean(settings.observe.rfn_passive_packet_seen);
      settings.perf.detail_max_seconds = Math.max(1, Math.min(3600, Number(settings.perf.detail_max_seconds) || 60));
      settings.perf.detail_max_events = Math.max(100, Math.min(1000000, Number(settings.perf.detail_max_events) || 20000));
      settings.perf.snapshot_interval_ms = Math.max(250, Math.min(10000, Number(settings.perf.snapshot_interval_ms) || 1000));
      if (Array.isArray(settings.stream.hidden_opcodes)) {
        settings.stream.hidden_opcodes = settings.stream.hidden_opcodes.join(', ');
      } else if (settings.stream.hidden_opcodes == null) {
        settings.stream.hidden_opcodes = '';
      }
      dropVisibleEvents(stream.setCapacity(settings.stream.max_events));
      if (applyDefaultFilter || (!filterText.value && settings.stream.default_filter)) {
        filterText.value = settings.stream.default_filter || '';
      }
      applyTheme();
    }

    function packetShouldBeHidden(ev) {
      const streamCfg = settings.stream || {};
      const errText = `${ev.error || ''} ${ev.decode_error || ''}`;
      const hiddenOpcodes = hiddenOpcodeSet.value;
      const packetOpcodes = [
        normalizeOpcodeToken(ev.opcode_hex || ev.opcode),
        normalizeOpcodeToken(ev.wire?.command_hex || ev.wire?.command),
      ].filter(Boolean);
      if (streamCfg.hide_common_noise && packetOpcodes.some(op => hiddenOpcodes.has(op))) return true;
      if (ev.kind === 'data_decrypt_failed') {
        const isPlaintextShort = errText.includes('plaintext 长度不足 32')
          || (/plaintext/i.test(errText) && errText.includes('32'));
        if (streamCfg.hide_plaintext_short && isPlaintextShort) return true;
        if (streamCfg.hide_decrypt_failed) return true;
      }
      if (streamCfg.hide_no_schema && ev.decode_status === 'no_schema') return true;
      return false;
    }

    function logShouldBeHidden(ev) {
      const streamCfg = settings.stream || {};
      const message = String(ev.message || '');
      const isPlaintextShort = message.includes('plaintext 长度不足 32')
        || (/plaintext/i.test(message) && message.includes('32'));
      if (streamCfg.hide_plaintext_short && isPlaintextShort) return true;
      if (streamCfg.hide_decrypt_failed && (message.includes('解密失败') || /decrypt/i.test(message))) return true;
      return false;
    }

    function normalizePacketForDisplay(ev) {
      if (!settings.stream?.hide_unknown_fields || !ev.decoded) return ev;
      return { ...ev, decoded: copyWithoutUnknown(ev.decoded) };
    }

    function metric(name) {
      return perf.metrics?.[name] || { count: 0, bytes: 0, avg_ms: 0, max_ms: 0, mbps: 0 };
    }

    function fmtPct(value) {
      const n = Number(value);
      return Number.isFinite(n) ? `${n.toFixed(n < 10 ? 1 : 0)}%` : '-';
    }

    function fmtMs(name, field = 'avg_ms') {
      const n = Number(metric(name)[field]);
      if (!Number.isFinite(n)) return '-';
      if (n < 0.01) return n.toFixed(3);
      if (n < 10) return n.toFixed(2);
      return n.toFixed(1);
    }

    function fmtMbps(name) {
      const n = Number(metric(name).mbps);
      if (!Number.isFinite(n) || n <= 0) return '0';
      return n < 1 ? n.toFixed(3) : n.toFixed(2);
    }

    function applyPerf(ev) {
      const data = ev.data || {};
      perf.window_sec = Number(data.window_sec) || 0;
      perf.process_cpu_pct = Number(data.process_cpu_pct) || 0;
      perf.system_cpu_pct = data.system_cpu_pct;
      perf.rss_mb = data.rss_mb;
      perf.queue = data.queue || { outbound_depth: 0, outbound_max: 0 };
      perf.metrics = data.metrics || {};
    }

    let liveCounterStartTs = 0;
    const pendingPackets = [];
    let packetFlushRaf = 0;
    const PACKET_FLUSH_LIMIT = 1200;

    function syncLiveCounters(snapshot = {}, { reset = false } = {}) {
      const c2s = Math.max(0, Number(snapshot.c2s_count) || 0);
      const s2c = Math.max(0, Number(snapshot.s2c_count) || 0);
      const inject = Math.max(0, Number(snapshot.c2s_seq_offset) || 0);
      if (reset) {
        liveCounters.c2s = c2s;
        liveCounters.s2c = s2c;
        liveCounters.inject = inject;
        return;
      }
      liveCounters.c2s = Math.max(liveCounters.c2s, c2s);
      liveCounters.s2c = Math.max(liveCounters.s2c, s2c);
      liveCounters.inject = Math.max(liveCounters.inject, inject);
    }

    function accountLivePacket(ev) {
      if (!ev || ev.type !== 'packet') return;
      const evTs = Number(ev.ts) || 0;
      if (liveCounterStartTs && evTs && evTs <= liveCounterStartTs) return;
      if (ev.direction === 'c2s') liveCounters.c2s += 1;
      else if (ev.direction === 's2c') liveCounters.s2c += 1;
    }

    function schedulePacketFlush() {
      if (packetFlushRaf) return;
      packetFlushRaf = window.requestAnimationFrame(flushPacketEvents);
    }

    function flushPacketEvents() {
      if (packetFlushRaf) {
        window.cancelAnimationFrame(packetFlushRaf);
        packetFlushRaf = 0;
      }
      if (!pendingPackets.length) return;
      const batch = pendingPackets.splice(0, PACKET_FLUSH_LIMIT);
      const dropped = stream.pushBatch(batch);
      dropVisibleEvents(dropped);
      appendVisibleEvents(batch);
      if (pendingPackets.length) schedulePacketFlush();
    }

    function enqueuePacketEvent(ev) {
      accountLivePacket(ev);
      if (paused.value) return;
      pendingPackets.push(ev);
      schedulePacketFlush();
    }

    function applyPacketUpdate(ev) {
      const targetSeq = Number(ev.target_seq);
      if (!Number.isFinite(targetSeq)) return;
      flushPacketEvents();
      const patch = { ...ev };
      delete patch.type;
      delete patch.seq;
      delete patch.target_seq;
      let updated = stream.update(targetSeq, patch);
      if (!updated) return;
      const displayEv = normalizePacketForDisplay(updated);
      upsertVisibleEvent(updated);
      if (injectReply.value?.seq === targetSeq) {
        injectReply.value = displayEv;
      }
      maybeCaptureInjectReply(displayEv);
    }

    function requestDecodeNow(ev) {
      if (!settings.observe?.decode_on_click) return;
      const canDecode = ['queued', 'deferred', 'raw'].includes(ev?.decode_status) || (!ev?.decoded && ev?.payload_hex);
      if (!ev || !canDecode || !ev.payload_hex) return;
      const opcode = ev.opcode_hex || ev.opcode;
      if (!opcode || !ev.seq) return;
      client.send('decode_now', {
        target_seq: ev.seq,
        opcode_hex: ev.opcode_hex,
        opcode: ev.opcode,
        payload_hex: ev.payload_hex,
      }).catch(() => {});
    }

    function togglePacketExpand(ev) {
      const wasExpanded = stream.expanded.value.has(ev.seq);
      stream.toggleExpand(ev.seq);
      if (!wasExpanded) requestDecodeNow(ev);
    }

    function expectedReplyOpcode(opcode) {
      const n = Number(opcode);
      return Number.isFinite(n) ? n + 1 : null;
    }

    function rememberInject(info) {
      const opcode = Number(info.opcode);
      const replyOpcode = expectedReplyOpcode(opcode);
      lastInject.value = {
        ts: Date.now() / 1000,
        opcode,
        opcode_hex: info.opcode_hex,
        opcode_name: selectedOp.value?.name || '',
        reply_opcode: replyOpcode,
        reply_opcode_hex: replyOpcode == null ? '' : normalizeOpcodeToken(replyOpcode),
        inject_seq: info.inject_seq,
        counter2_source: info.counter2_source,
      };
      injectReply.value = null;
    }

    function maybeCaptureInjectReply(ev) {
      const inj = lastInject.value;
      if (!inj || injectReply.value) return;
      if (ev.direction !== 's2c' || ev.kind !== 'data') return;
      if (typeof ev.ts === 'number' && ev.ts + 1 < inj.ts) return;
      if (normalizeOpcodeToken(ev.opcode_hex || ev.opcode) !== inj.reply_opcode_hex) return;
      injectReply.value = normalizePacketForDisplay(ev);
      requestDecodeNow(ev);
    }

    async function loadSettings() {
      settingsError.value = '';
      try {
        const r = await fetch('/api/settings');
        if (!r.ok) throw new Error(await r.text());
        const data = await r.json();
        Object.assign(settings, sanitizeSettings(data.settings || {}));
        applySettings({ applyDefaultFilter: true });
      } catch (e) {
        settingsError.value = e.message;
        applySettings();
      }
    }

    async function saveSettings() {
      settingsSaving.value = true;
      settingsError.value = '';
      try {
        applySettings();
        const payload = sanitizeSettings(settings);
        const r = await fetch('/api/settings', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ settings: payload }),
        });
        if (!r.ok) throw new Error(await r.text());
        const data = await r.json();
        Object.assign(settings, sanitizeSettings(data.settings || payload));
        applySettings();
        await pullStatus();
        toasts.push({ kind: 'ok', title: '设置已保存' });
        showSettingsModal.value = false;
      } catch (e) {
        settingsError.value = e.message;
        toasts.push({ kind: 'err', title: '保存设置失败', body: e.message });
      } finally {
        settingsSaving.value = false;
      }
    }

    watch(settings, () => applySettings(), { deep: true });

    function clearStream() {
      pendingPackets.length = 0;
      if (packetFlushRaf) {
        window.cancelAnimationFrame(packetFlushRaf);
        packetFlushRaf = 0;
      }
      stream.clear();
      visibleStream.value = [];
      rebuildVisibleIndex();
    }

    client.on('open', () => {
      status.ws_connected = true;
      toasts.push({ kind: 'ok', title: 'WebSocket 已连接' });
    });
    client.on('close', () => { status.ws_connected = false; });
    client.on('hello', (m) => {
      Object.assign(status, m.status || {});
      liveCounterStartTs = Number(m.ts) || (Date.now() / 1000);
      syncLiveCounters(m.status || {}, { reset: true });
    });
    client.on('packet', enqueuePacketEvent);
    client.on('packet_update', applyPacketUpdate);
    client.on('stream_reset', (ev) => {
      clearStream();
      trafficWindow.value = [];
      lastInject.value = null;
      injectReply.value = null;
      liveCounterStartTs = Number(ev.ts) || (Date.now() / 1000);
      syncLiveCounters({}, { reset: true });
      toasts.push({
        kind: 'warn',
        title: '检测到新 session_key，已清空旧数据',
        body: ev.old_key_preview && ev.new_key_preview ? `${ev.old_key_preview} → ${ev.new_key_preview}` : '',
      });
    });
    client.on('session', (ev) => {
      if (ev.snapshot) {
        Object.assign(status, ev.snapshot);
        syncLiveCounters(ev.snapshot, { reset: ev.name === 'session_closed' });
      }
      if (ev.name === 'session_key') {
        toasts.push({ kind: 'ok', title: '已捕获 session_key', body: ev.info?.key_hex });
      } else if (ev.name === 'upstream_connected') {
        toasts.push({ kind: 'ok', title: '上游已连接', body: status.upstream });
      } else if (ev.name === 'session_closed') {
        toasts.push({ kind: 'warn', title: '会话已断开' });
      }
    });
    client.on('log', (ev) => {
      if (logShouldBeHidden(ev)) return;
      if (ev.level === 'error' || ev.level === 'warn') {
        toasts.push({ kind: ev.level === 'error' ? 'err' : 'warn', title: ev.message });
      }
    });
    client.on('perf', applyPerf);

    let statusTimer = null;
    async function pullStatus() {
      try {
        const r = await fetch('/api/status');
        if (r.ok) {
          const data = await r.json();
          Object.assign(status, data);
          syncLiveCounters(data);
        }
      } catch { }
    }

    async function loadOpcodes() {
      const r = await fetch('/api/opcodes');
      const data = await r.json();
      opcodes.value = data.opcodes || [];
      Object.assign(status.registry_stats, data.stats || {});
    }
    async function loadTemplates() {
      const r = await fetch('/api/templates');
      const data = await r.json();
      templates.value = data.items || [];
    }

    function asJson(value) {
      try {
        return JSON.stringify(value ?? null, null, 2);
      } catch {
        return String(value);
      }
    }

    async function rfnJson(url, options = {}) {
      const r = await fetch(url, { cache: 'no-store', ...options });
      const text = await r.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = { ok: false, error: text };
      }
      if (!r.ok) {
        const err = new Error(data?.error || data?.error_code || `${url} ${r.status}`);
        err.data = data;
        throw err;
      }
      return data;
    }

    async function loadRfnConsole() {
      rfnConsole.loading = true;
      rfnConsole.error = '';
      try {
        const [
          rfnStatus,
          functions,
          bindings,
          jobs,
          namespaces,
          cache,
          buffer,
          events,
          imports,
          rksStatus,
        ] = await Promise.all([
          rfnJson('/api/rfn/status'),
          rfnJson('/api/rfn/functions'),
          rfnJson('/api/rfn/bindings'),
          rfnJson('/api/rfn/jobs'),
          rfnJson('/api/rfn/db/namespaces'),
          rfnJson('/api/rfn/cache'),
          rfnJson('/api/rfn/buffer'),
          rfnJson('/api/rfn/db/events?limit=20'),
          rfnJson('/api/rfn/imports'),
          rfnJson('/api/rks/status'),
        ]);
        rfnConsole.status = rfnStatus;
        rfnConsole.functions = functions.functions || [];
        rfnConsole.bindings = bindings.bindings || { packet: [], http: [], schedule: [] };
        rfnConsole.jobs = jobs.jobs || [];
        rfnConsole.namespaces = namespaces.namespaces || [];
        rfnConsole.cache = cache.items || [];
        rfnConsole.buffer = buffer.items || [];
        rfnConsole.events = events.events || [];
        rfnConsole.imports = imports.items || [];
        rfnConsole.rksStatus = rksStatus;
      } catch (e) {
        rfnConsole.error = e.message;
        toasts.push({ kind: 'err', title: 'RFN 刷新失败', body: e.message });
      } finally {
        rfnConsole.loading = false;
      }
    }

    async function openRfnPanel() {
      showRfnPanel.value = true;
      await loadRfnConsole();
    }

    async function reloadRfnFromPanel() {
      rfnConsole.actionBusy = 'reload';
      rfnConsole.error = '';
      try {
        rfnConsole.execResult = await rfnJson('/api/rfn/reload', { method: 'POST' });
        await loadRfnConsole();
        toasts.push({ kind: 'ok', title: 'RFN 已重新加载' });
      } catch (e) {
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function execRfnFromPanel() {
      rfnConsole.actionBusy = 'exec';
      rfnConsole.error = '';
      try {
        const args = JSON.parse(rfnConsole.execArgs || '[]');
        if (!Array.isArray(args)) throw new Error('args 必须是 JSON 数组');
        rfnConsole.execResult = await rfnJson('/api/rfn/exec', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ function: rfnConsole.execName, args }),
        });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.execResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function runRfnJob(jobKey) {
      rfnConsole.actionBusy = jobKey;
      rfnConsole.error = '';
      try {
        rfnConsole.jobResult = await rfnJson(`/api/rfn/jobs/${encodeURIComponent(jobKey)}/run`, { method: 'POST' });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.jobResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function setRfnJobEnabled(jobKey, enabled) {
      rfnConsole.actionBusy = jobKey;
      rfnConsole.error = '';
      try {
        rfnConsole.jobResult = await rfnJson(`/api/rfn/jobs/${encodeURIComponent(jobKey)}/enable`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ enabled: Boolean(enabled) }),
        });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.jobResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function cancelRfnJob(jobKey) {
      if (!confirm(`删除 RFN job "${jobKey}" ?\n删除会移除 SQLite job spec；临时停用请使用“禁用”。`)) return;
      rfnConsole.actionBusy = jobKey;
      rfnConsole.error = '';
      try {
        rfnConsole.jobResult = await rfnJson(`/api/rfn/jobs/${encodeURIComponent(jobKey)}/cancel`, { method: 'POST' });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.jobResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    function parseImportArgs() {
      const args = JSON.parse(rfnConsole.importArgs || '[]');
      if (!Array.isArray(args)) throw new Error('导入参数必须是 JSON 数组');
      return args;
    }

    async function validateRfnImport() {
      rfnConsole.actionBusy = 'import';
      rfnConsole.error = '';
      try {
        rfnConsole.importResult = await rfnJson('/api/rfn/imports/validate', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ source: rfnConsole.importSource, args: parseImportArgs() }),
        });
      } catch (e) {
        rfnConsole.importResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function runRfnImportSource() {
      rfnConsole.actionBusy = 'import';
      rfnConsole.error = '';
      try {
        rfnConsole.importResult = await rfnJson('/api/rfn/imports/run', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            source: rfnConsole.importSource,
            function: rfnConsole.importFunction,
            args: parseImportArgs(),
          }),
        });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.importResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function importAndRunRfnSource() {
      rfnConsole.actionBusy = 'import';
      rfnConsole.error = '';
      try {
        const saved = await rfnJson('/api/rfn/imports', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ name: rfnConsole.importName, source: rfnConsole.importSource }),
        });
        if (!saved.ok) {
          rfnConsole.importResult = saved;
          rfnConsole.error = saved.error || saved.error_code || '导入失败';
          return;
        }
        const run = await rfnJson(`/api/rfn/imports/${encodeURIComponent(saved.name)}/run`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ function: rfnConsole.importFunction, args: parseImportArgs() }),
        });
        rfnConsole.importResult = { ok: Boolean(run.ok), imported: saved, run };
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.importResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function runImportedRfn(name) {
      rfnConsole.actionBusy = `import:${name}`;
      rfnConsole.error = '';
      try {
        rfnConsole.importResult = await rfnJson(`/api/rfn/imports/${encodeURIComponent(name)}/run`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ function: rfnConsole.importFunction, args: parseImportArgs() }),
        });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.importResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    async function deleteImportedRfn(name) {
      if (!confirm(`删除导入脚本 "${name}" ?`)) return;
      rfnConsole.actionBusy = `import:${name}`;
      rfnConsole.error = '';
      try {
        rfnConsole.importResult = await rfnJson(`/api/rfn/imports/${encodeURIComponent(name)}`, { method: 'DELETE' });
        await loadRfnConsole();
      } catch (e) {
        rfnConsole.importResult = { ok: false, error: e.message, data: e.data || null };
        rfnConsole.error = e.message;
      } finally {
        rfnConsole.actionBusy = '';
      }
    }

    const selectedOp = ref(null);     // 元数据
    const selectedSchema = ref(null); // expanded fields
    const formValue = reactive({});
    const editMode = ref('form');     // 'form' | 'json' | 'hex'
    const hexValue = ref('');
    const jsonValue = ref('{}');
    const jsonError = ref('');

    async function selectOpcode(meta) {
      selectedOp.value = meta;
      const r = await fetch(`/api/opcodes/${meta.hex}`);
      if (!r.ok) {
        toasts.push({ kind: 'err', title: '加载 schema 失败', body: `${r.status}` });
        return;
      }
      const data = await r.json();
      selectedSchema.value = data.fields;
      for (const k of Object.keys(formValue)) delete formValue[k];
      const def = computeSchemaFormDefault(data.fields);
      Object.assign(formValue, def);
      hexValue.value = '';
      jsonValue.value = JSON.stringify(def, null, 2);
      editMode.value = data.fields ? 'form' : 'hex';
    }

    const previewHex = ref('');
    const previewLen = ref(0);
    const previewError = ref('');
    let previewTimer = null;
    watch([formValue, editMode, hexValue, jsonValue, selectedSchema], () => {
      clearTimeout(previewTimer);
      previewTimer = setTimeout(updatePreview, 120);
    }, { deep: true });

    async function updatePreview() {
      previewError.value = '';
      if (!selectedOp.value) { previewHex.value = ''; previewLen.value = 0; return; }
      if (editMode.value === 'hex') {
        try {
          const clean = hexValue.value.replace(/\s+/g, '');
          if (clean.length % 2) throw new Error('hex 长度必须为偶数');
          if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('hex 含非法字符');
          previewHex.value = clean.toLowerCase();
          previewLen.value = clean.length / 2;
        } catch (e) { previewError.value = e.message; }
        return;
      }
      let value;
      if (editMode.value === 'json') {
        try {
          jsonError.value = '';
          value = JSON.parse(jsonValue.value);
        } catch (e) {
          jsonError.value = e.message;
          previewError.value = e.message;
          return;
        }
      } else {
        value = JSON.parse(JSON.stringify(formValue));
      }
      // 优先走后端 /api/encode 保证与服务端一致
      try {
        const r = await fetch('/api/encode', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ opcode_hex: selectedOp.value.hex, value }),
        });
        if (!r.ok) {
          const txt = await r.text();
          previewError.value = txt;
          return;
        }
        const data = await r.json();
        previewHex.value = data.payload_hex;
        previewLen.value = data.payload_len;
      } catch (e) {
        previewError.value = e.message;
      }
    }

    async function send() {
      if (!selectedOp.value) return;
      try {
        if (String(selectedOp.value.direction || '').toLowerCase() === 's2c') {
          const ok = confirm(`当前选择的是 S2C opcode：${selectedOp.value.hex} ${selectedOp.value.name || ''}\n真的要注入 S2C 吗？`);
          if (!ok) return;
        }
        const payload = { opcode_hex: selectedOp.value.hex };
        if (editMode.value === 'hex') {
          payload.payload_hex = hexValue.value.replace(/\s+/g, '');
        } else if (editMode.value === 'json') {
          payload.value = JSON.parse(jsonValue.value);
        } else {
          payload.value = JSON.parse(JSON.stringify(formValue));
        }
        const r = await client.send('inject', payload);
        const info = r.info;
        rememberInject(info);
        toasts.push({
          kind: 'ok',
          title: `已注入 ${info.opcode_hex}`,
          body: `seq=${info.inject_seq} c2=${info.counter2_source}`,
        });
      } catch (e) {
        toasts.push({ kind: 'err', title: '注入失败', body: e.message });
      }
    }

    const showSaveModal = ref(false);
    const saveName = ref('');

    async function saveTemplate() {
      if (!saveName.value.trim() || !selectedOp.value) return;
      const payload = {
        name: saveName.value.trim(),
        opcode_hex: selectedOp.value.hex,
        opcode_name: selectedOp.value.name,
        mode: editMode.value,
        value: editMode.value === 'json' ? JSON.parse(jsonValue.value)
            : editMode.value === 'hex' ? null
            : JSON.parse(JSON.stringify(formValue)),
        payload_hex: editMode.value === 'hex' ? hexValue.value.replace(/\s+/g, '') : null,
      };
      try {
        const r = await fetch('/api/templates', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!r.ok) throw new Error(await r.text());
        await loadTemplates();
        showSaveModal.value = false; saveName.value = '';
        toasts.push({ kind: 'ok', title: '模板已保存', body: payload.name });
      } catch (e) {
        toasts.push({ kind: 'err', title: '保存失败', body: e.message });
      }
    }

    async function loadTemplate(t) {
      const meta = opcodesByHex.value[t.opcode_hex];
      if (!meta) {
        toasts.push({ kind: 'warn', title: '模板对应 opcode 已不存在', body: t.opcode_hex });
        return;
      }
      await selectOpcode(meta);
      editMode.value = t.mode || 'form';
      if (t.mode === 'hex' && t.payload_hex) hexValue.value = t.payload_hex;
      else if (t.value) {
        if (editMode.value === 'json') jsonValue.value = JSON.stringify(t.value, null, 2);
        else { for (const k of Object.keys(formValue)) delete formValue[k]; Object.assign(formValue, t.value); }
      }
      toasts.push({ kind: 'ok', title: '已加载模板', body: t.name });
    }

    async function deleteTemplate(t) {
      if (!confirm(`删除模板 "${t.name}" ?`)) return;
      await fetch(`/api/templates/${encodeURIComponent(t.name)}`, { method: 'DELETE' });
      await loadTemplates();
    }

    const trafficWindow = ref([]); // [{t, c2s, s2c}]
    let trafficTimer = null;
    trafficTimer = setInterval(() => {
      const now = Date.now();
      const cutoff = now - 60_000;
      let lastBucketTime = trafficWindow.value.length
        ? trafficWindow.value[trafficWindow.value.length - 1].t : 0;
      trafficWindow.value.push({
        t: now,
        c2s: stream.lastSecond.value.c2s,
        s2c: stream.lastSecond.value.s2c,
      });
      while (trafficWindow.value.length > 0 && trafficWindow.value[0].t < cutoff) {
        trafficWindow.value.shift();
      }
      stream.tickSecond();
    }, 1000);

    onMounted(async () => {
      themeMedia = window.matchMedia?.('(prefers-color-scheme: light)');
      themeMedia?.addEventListener?.('change', applyTheme);
      await loadSettings();
      client.connect();
      await Promise.all([loadOpcodes(), loadTemplates(), pullStatus()]);
      statusTimer = setInterval(pullStatus, 4000);
    });
    onBeforeUnmount(() => {
      if (statusTimer) clearInterval(statusTimer);
      if (trafficTimer) clearInterval(trafficTimer);
      if (scrollTimer != null) clearTimeout(scrollTimer);
      if (scrollRaf) cancelAnimationFrame(scrollRaf);
      if (packetFlushRaf) cancelAnimationFrame(packetFlushRaf);
      themeMedia?.removeEventListener?.('change', applyTheme);
    });

    return {
      status, liveCounters, perf, toasts, stream, opcodes, templates,
      streamListRef, lastInject, injectReply,
      settings, showSettingsModal, settingsSaving, settingsError,
      showRfnPanel, rfnConsole,
      visibleStream, renderedStream, filterText, filterErr, paused,
      selectedOp, selectedSchema, formValue, editMode, hexValue, jsonValue, jsonError,
      previewHex, previewLen, previewError,
      showSaveModal, saveName,
      trafficWindow,
      selectOpcode, send, saveTemplate, loadTemplate, deleteTemplate, saveSettings,
      openRfnPanel, loadRfnConsole, reloadRfnFromPanel, execRfnFromPanel,
      runRfnJob, setRfnJobEnabled, cancelRfnJob, asJson,
      validateRfnImport, runRfnImportSource, importAndRunRfnSource,
      runImportedRfn, deleteImportedRfn,
      togglePacketExpand,
      fmtPct, fmtMs, fmtMbps,
      reloadSchemas: loadOpcodes,
      togglePause: () => { paused.value = !paused.value; },
      clearStream,
    };
  },
  template: '#app-template',
};

try {
  const tpl = document.createElement('template');
  tpl.id = 'app-template';
  const res = await fetch('/assets/template.html', { cache: 'no-store' });
  if (!res.ok) throw new Error(`template.html ${res.status}`);
  tpl.innerHTML = await res.text();
  document.body.appendChild(tpl);
  createApp(App).mount('#app');
} catch (e) {
  clearTimeout(window.__rkms_vue_failed);
  const app = document.querySelector('#app') || document.body;
  const box = document.createElement('div');
  box.style.cssText = 'padding:24px;font:14px system-ui;color:#f3f4f6;background:#111827;min-height:100vh;';
  const title = document.createElement('h1');
  title.style.cssText = 'font-size:18px;margin:0 0 10px;';
  title.textContent = '界面加载失败';
  const detail = document.createElement('pre');
  detail.style.cssText = 'white-space:pre-wrap;color:#fca5a5;';
  detail.textContent = String(e?.message || e);
  box.append(title, detail);
  app.replaceChildren(box);
}
