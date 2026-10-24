// Central chat routing: POST /v1/chat/completions for authenticated desktop devices.
// The client selects a catalogue model by its internal id. The server decides the upstream model, base URL and key.
import type { ServerResponse } from 'node:http';
import type { Ctx, Deps, DeviceAuth } from '../context.ts';
import { HttpError, fail, int, log, readJson, sendOpenAiError, UUID } from '../http/util.ts';
import { REASONING_LEVELS, normalizeCapabilities } from './catalogue.ts';
import { authenticateDevice } from './devices.ts';
import { acquireSlot, releaseSlot } from '../persistent-limits.ts';
import { providerApiKey } from './providers.ts';
import { UpstreamError } from './upstream.ts';
import { allowedModelIds, isAllowed } from './registry.ts';

const BODY_LIMIT = 4 * 1024 * 1024;
const MAX_MESSAGES = 400;
const MAX_TEXT_CHARS = 1_500_000;
const MAX_TOOLS = 128;
const UPSTREAM_BODY_LIMIT = 16 * 1024 * 1024;
const TOP_LEVEL = ['model', 'messages', 'tools', 'tool_choice', 'temperature', 'top_p', 'max_tokens', 'reasoning_effort', 'stream', 'stream_options'];
const ROLES = ['system', 'user', 'assistant', 'tool'];

export interface ChatRequest {
  model: string;
  messages: Record<string, any>[];
  tools?: Record<string, any>[];
  tool_choice?: unknown;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  reasoning_effort?: string;
  stream: boolean;
  include_usage: boolean;
  hasImages: boolean;
}

const oa = (code: string, message: string, status = 400, headers: Record<string, string> = {}) => new HttpError(status, code, message, headers);

/** Validates the client request. Unknown fields are refused, so nothing reaches the upstream unless it is listed here. */
export function parseChatRequest(body: Record<string, unknown>, maxOutputTokens: number): ChatRequest {
  for (const k of Object.keys(body)) if (!TOP_LEVEL.includes(k)) throw oa('unsupported_parameter', `the parameter "${k}" is not supported`);
  if (typeof body.model !== 'string' || !UUID.test(body.model)) throw oa('invalid_request', 'model must be a model id from the catalogue');
  if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > MAX_MESSAGES) {
    throw oa('invalid_request', `messages must be a list of 1 to ${MAX_MESSAGES} items`);
  }
  let textChars = 0;
  let hasImages = false;
  const messages = body.messages.map((raw, i) => {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw oa('invalid_request', `messages[${i}] must be an object`);
    const m = raw as Record<string, any>;
    if (!ROLES.includes(m.role)) throw oa('invalid_request', `messages[${i}].role is not valid`);
    const out: Record<string, any> = { role: m.role };
    if (typeof m.content === 'string') {
      textChars += m.content.length;
      out.content = m.content;
    } else if (Array.isArray(m.content)) {
      out.content = m.content.map((p: any) => {
        if (p?.type === 'text' && typeof p.text === 'string') {
          textChars += p.text.length;
          return { type: 'text', text: p.text };
        }
        if (p?.type === 'image_url' && typeof p.image_url?.url === 'string' && p.image_url.url.length <= 8_000_000) {
          hasImages = true;
          return { type: 'image_url', image_url: { url: p.image_url.url, ...(p.image_url.detail ? { detail: String(p.image_url.detail).slice(0, 10) } : {}) } };
        }
        throw oa('invalid_request', `messages[${i}].content has an unsupported part`);
      });
    } else if (m.content === null && m.role === 'assistant') {
      out.content = null;
    } else {
      throw oa('invalid_request', `messages[${i}].content must be text or a list of parts`);
    }
    if (m.name !== undefined) {
      if (typeof m.name !== 'string' || m.name.length > 64) throw oa('invalid_request', `messages[${i}].name is not valid`);
      out.name = m.name;
    }
    if (m.tool_call_id !== undefined) {
      if (typeof m.tool_call_id !== 'string' || m.tool_call_id.length > 200) throw oa('invalid_request', `messages[${i}].tool_call_id is not valid`);
      out.tool_call_id = m.tool_call_id;
    }
    if (m.tool_calls !== undefined) {
      if (!Array.isArray(m.tool_calls) || m.tool_calls.length > 64) throw oa('invalid_request', `messages[${i}].tool_calls is not valid`);
      out.tool_calls = m.tool_calls.map((t: any) => {
        if (typeof t?.id !== 'string' || typeof t?.function?.name !== 'string' || typeof t?.function?.arguments !== 'string') {
          throw oa('invalid_request', `messages[${i}].tool_calls has an invalid entry`);
        }
        textChars += t.function.arguments.length;
        return { id: t.id.slice(0, 200), type: 'function', function: { name: t.function.name.slice(0, 200), arguments: t.function.arguments } };
      });
    }
    return out;
  });
  if (textChars > MAX_TEXT_CHARS) throw oa('invalid_request', 'the conversation is too large for one request');

  let tools: Record<string, any>[] | undefined;
  if (body.tools !== undefined) {
    if (!Array.isArray(body.tools) || body.tools.length > MAX_TOOLS) throw oa('invalid_request', `tools must be a list of at most ${MAX_TOOLS} functions`);
    tools = body.tools.map((t: any) => {
      if (t?.type !== 'function' || typeof t.function?.name !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(t.function.name)) {
        throw oa('invalid_request', 'each tool must be a function with a valid name');
      }
      return { type: 'function', function: { name: t.function.name, description: typeof t.function.description === 'string' ? t.function.description.slice(0, 4000) : undefined, parameters: t.function.parameters ?? { type: 'object', properties: {} } } };
    });
  }
  let toolChoice: unknown;
  if (body.tool_choice !== undefined) {
    if (['auto', 'none', 'required'].includes(body.tool_choice as string)) toolChoice = body.tool_choice;
    else if ((body.tool_choice as any)?.type === 'function' && typeof (body.tool_choice as any).function?.name === 'string') toolChoice = { type: 'function', function: { name: (body.tool_choice as any).function.name } };
    else throw oa('invalid_request', 'tool_choice is not valid');
  }
  const num = (k: string, min: number, max: number): number | undefined => {
    const v = body[k];
    if (v === undefined || v === null) return undefined;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max) throw oa('invalid_request', `${k} must be a number from ${min} to ${max}`);
    return v;
  };
  const temperature = num('temperature', 0, 2);
  const topP = num('top_p', 0, 1);
  let maxTokens: number | undefined;
  if (body.max_tokens !== undefined && body.max_tokens !== null) {
    maxTokens = int({ max_tokens: body.max_tokens }, 'max_tokens', { min: 1, max: maxOutputTokens });
  }
  let reasoning: string | undefined;
  if (body.reasoning_effort !== undefined && body.reasoning_effort !== null) {
    if (!(REASONING_LEVELS as readonly string[]).includes(body.reasoning_effort as string)) throw oa('invalid_request', 'reasoning_effort must be low, medium or high');
    reasoning = body.reasoning_effort as string;
  }
  const stream = body.stream === undefined ? false : body.stream === true;
  if (body.stream !== undefined && typeof body.stream !== 'boolean') throw oa('invalid_request', 'stream must be true or false');
  let includeUsage = false;
  if (body.stream_options !== undefined) {
    if (!stream) throw oa('invalid_request', 'stream_options requires stream: true');
    const so = body.stream_options as any;
    if (!so || typeof so !== 'object' || Object.keys(so).some((k) => k !== 'include_usage') || (so.include_usage !== undefined && typeof so.include_usage !== 'boolean')) {
      throw oa('invalid_request', 'stream_options may only contain include_usage');
    }
    includeUsage = so.include_usage === true;
  }
  return {
    model: body.model,
    messages,
    tools,
    tool_choice: toolChoice,
    temperature,
    top_p: topP,
    max_tokens: maxTokens,
    reasoning_effort: reasoning,
    stream,
    include_usage: includeUsage,
    hasImages,
  };
}

/** Builds the upstream body. Only validated fields are copied, and the upstream model id comes from the database. */
export function buildUpstreamBody(req: ChatRequest, upstreamModelId: string, reasoningLevelsAllowed: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = { model: upstreamModelId, messages: req.messages, stream: req.stream };
  if (req.stream && req.include_usage) out.stream_options = { include_usage: true };
  if (req.tools) out.tools = req.tools;
  if (req.tool_choice !== undefined) out.tool_choice = req.tool_choice;
  if (req.temperature !== undefined) out.temperature = req.temperature;
  if (req.top_p !== undefined) out.top_p = req.top_p;
  if (req.max_tokens !== undefined) out.max_tokens = req.max_tokens;
  if (req.reasoning_effort && reasoningLevelsAllowed) out.reasoning_effort = req.reasoning_effort;
  return out;
}

const LEASE_SECONDS = 900;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,64}$/;

/** Optional client Idempotency-Key. It stops a retried request from running (and being billed) twice. It does not replay answers. */
export function idempotencyKey(req: { headers: Record<string, string | string[] | undefined> }): string | null {
  const raw = req.headers['idempotency-key'];
  if (raw === undefined) return null;
  if (typeof raw !== 'string' || !IDEMPOTENCY_KEY.test(raw)) {
    fail(400, 'invalid_request', 'Idempotency-Key must be 8 to 64 letters, digits, dots, colons, underscores or hyphens');
  }
  return raw;
}

async function policyNumber(deps: Deps, key: string, fallback: number): Promise<number> {
  const { rows } = await deps.db.query('SELECT (value)::text::int AS v FROM settings WHERE key = $1', [key]);
  return rows[0]?.v ?? fallback;
}

export async function chatCompletions(ctx: Ctx): Promise<void> {
  const { res, deps } = ctx;
  let deviceId: string | null = null;
  try {
    const device = await authenticateDevice(ctx);
    deviceId = device.deviceId;
    const clientRequestId = idempotencyKey(ctx.req);
    // Rate counts and concurrency leases are stored in PostgreSQL, so they hold across restarts and across replicas.
    const perMinute = await policyNumber(deps, 'rate_limit_per_minute', 60);
    const rl = await deps.limits.hit(`chat:dev:${device.deviceId}`, perMinute, 60);
    if (!rl.allowed) fail(429, 'rate_limited', 'too many requests from this device; wait and try again', { 'retry-after': String(rl.retryAfterSeconds) });
    const maxConcurrent = await policyNumber(deps, 'max_concurrent_per_device', 2);
    const slot = await acquireSlot(deps.db, {
      deviceId: device.deviceId,
      requestId: ctx.requestId,
      clientRequestId,
      maxConcurrent,
      leaseSeconds: LEASE_SECONDS,
    });
    if (slot === 'duplicate') fail(409, 'duplicate_request', 'this request was already received; send a new Idempotency-Key for a new request');
    if (slot === 'busy') fail(429, 'too_many_requests', 'this device already has requests running; wait for one to finish');
    try {
      await handle(ctx, device, clientRequestId);
    } finally {
      await releaseSlot(deps.db, ctx.requestId).catch((e) => log('error', 'could not release request slot', { requestId: ctx.requestId, error: errText(e) }));
    }
  } catch (e) {
    if (res.headersSent) {
      if (!res.writableEnded) res.end();
      if (!(e instanceof HttpError)) log('error', 'chat failed after the stream started', { error: errText(e), deviceId });
      return;
    }
    if (e instanceof HttpError) {
      sendOpenAiError(res, e.status, e.code, e.message, e.headers);
      return;
    }
    if (e instanceof UpstreamError) {
      sendOpenAiError(res, 502, 'upstream_error', 'the provider failed to answer');
      return;
    }
    log('error', 'chat route failed', { error: errText(e), deviceId });
    sendOpenAiError(res, 500, 'internal_error', 'the request could not be completed');
  }
}

function errText(e: unknown): string {
  return e instanceof Error ? e.name + ': ' + e.message.slice(0, 300) : 'unknown error';
}

async function handle(ctx: Ctx, device: DeviceAuth, clientRequestId: string | null): Promise<void> {
  const { deps, req } = ctx;
  const deviceId = device.deviceId;
  const body = await readJson(req, BODY_LIMIT);
  const policy = await deps.db.query("SELECT (value)::text::int AS v FROM settings WHERE key = 'max_output_tokens'");
  const parsed = parseChatRequest(body, policy.rows[0]?.v ?? 8192);

  const allowed = await allowedModelIds(deps.db, deviceId, device.modelAccess);
  const m = await loadRoute(deps, parsed.model);
  if (!m || !isAllowed(allowed, m.id)) throw oa('model_not_found', 'this model is not in the catalogue for this computer; refresh the model list', 404);
  if (!m.model_enabled || !m.provider_enabled) throw oa('model_disabled', 'this model is currently disabled; choose another model', 403);
  checkCompatible(m, parsed, true);

  // The fallback is resolved from the registry too, and only used when it is enabled, permitted and compatible.
  const chain: RouteRow[] = [m];
  if (m.fallback_model_id) {
    const fb = await loadRoute(deps, m.fallback_model_id);
    if (fb && fb.model_enabled && fb.provider_enabled && isAllowed(allowed, fb.id) && checkCompatible(fb, parsed, false)) chain.push(fb);
  }

  for (let i = 0; i < chain.length; i++) {
    const done = await attempt(ctx, deviceId, clientRequestId, parsed, chain[i], { requested: m, canFallBack: i < chain.length - 1 });
    if (done) return;
  }
}

interface RouteRow {
  id: string;
  upstream_model_id: string;
  display_name: string;
  model_enabled: boolean;
  capabilities: unknown;
  fallback_model_id: string | null;
  provider_id: string;
  provider_name: string;
  provider_enabled: boolean;
  base_url: string;
  auth_scheme: string;
  timeout_ms: number;
  max_retries: number;
}

async function loadRoute(deps: Deps, modelId: string): Promise<RouteRow | null> {
  const { rows } = await deps.db.query(
    `SELECT m.id, m.upstream_model_id, m.display_name, m.enabled AS model_enabled, m.capabilities, m.fallback_model_id,
            p.id AS provider_id, p.name AS provider_name, p.enabled AS provider_enabled, p.base_url, p.auth_scheme, p.timeout_ms, p.max_retries
       FROM models m JOIN providers p ON p.id = m.provider_id WHERE m.id = $1`,
    [modelId],
  );
  return (rows[0] as RouteRow | undefined) ?? null;
}

/** Throws (for the requested model) or returns false (for a fallback) when the request needs a capability the model lacks. */
function checkCompatible(m: RouteRow, parsed: ChatRequest, raise: boolean): boolean {
  const caps = normalizeCapabilities(m.capabilities);
  const no = (msg: string) => {
    if (raise) throw oa('unsupported_parameter', msg);
    return false;
  };
  // A fallback must be known to support what the request uses; the requested model is only refused when known not to.
  const ok = (c: { supported: boolean | null }) => (raise ? c.supported !== false : c.supported === true);
  if (parsed.tools && !ok(caps.tools)) return no('this model does not support tools');
  if (parsed.hasImages && !ok(caps.vision)) return no('this model does not accept images');
  if (parsed.reasoning_effort) {
    const levels = caps.reasoning.levels ?? [];
    if (caps.reasoning.supported !== true || (levels.length && !levels.includes(parsed.reasoning_effort))) return no('this model does not support that reasoning level');
  }
  return true;
}

/** Failures that say the provider (not the request) is the problem. Only these may move a request to the fallback. */
function shouldFallBack(e: unknown): boolean {
  return e instanceof UpstreamError && ['auth', 'rate_limited', 'timeout', 'unreachable', 'server'].includes(e.kind);
}

/**
 * One upstream attempt. Returns true when the client got its answer (or an error), false when the caller should try the
 * fallback. A fallback is only possible before any byte was sent to the client, so a stream is never spliced.
 */
async function attempt(
  ctx: Ctx,
  deviceId: string,
  clientRequestId: string | null,
  parsed: ChatRequest,
  m: RouteRow,
  route: { requested: RouteRow; canFallBack: boolean },
): Promise<boolean> {
  const { deps, res } = ctx;
  const isFallback = m.id !== route.requested.id;
  let key: string | null = null;
  if (m.auth_scheme === 'bearer') {
    key = await providerApiKey(deps, m.provider_id);
    if (!key) {
      if (route.canFallBack) {
        log('warn', 'model has no provider key; using its fallback', { requestId: ctx.requestId, model: m.id });
        return false;
      }
      throw oa('upstream_auth_failed', 'the provider has no API key configured; the owner must add it', 502);
    }
  }

  const upstreamBody = buildUpstreamBody(parsed, m.upstream_model_id, true);
  const url = `${m.base_url}/chat/completions`;
  const started = Date.now();
  const controller = new AbortController();
  let finished = false;
  let movedOn = false;
  let outcome: { status: 'ok' | 'error' | 'cancelled'; http: number; code: string | null; ttft: number | null; usage: { p: number | null; c: number | null } } = {
    status: 'error',
    http: 500,
    code: 'internal_error',
    ttft: null,
    usage: { p: null, c: null },
  };
  const onClose = () => {
    if (!finished) controller.abort();
  };
  res.on('close', onClose);
  // Tells the desktop which registry model answered, so a fallback is never silent.
  const routingHeaders: Record<string, string> = isFallback ? { 'x-devora-model': m.id, 'x-devora-fallback-from': route.requested.id } : { 'x-devora-model': m.id };

  try {
    const upstream = await callUpstream(deps, url, upstreamBody, key, m.timeout_ms, m.max_retries > 0 ? 1 : 0, parsed.stream, controller);
    if (!parsed.stream) {
      const text = await readLimited(upstream, UPSTREAM_BODY_LIMIT);
      let json: any;
      try {
        json = JSON.parse(text);
      } catch {
        throw new UpstreamError('bad_response', 'malformed response');
      }
      if (!json || !Array.isArray(json.choices)) throw new UpstreamError('bad_response', 'malformed response');
      json.model = m.id;
      const usage = usageOf(json.usage);
      outcome = { status: 'ok', http: 200, code: null, ttft: Date.now() - started, usage };
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...routingHeaders });
      res.end(JSON.stringify(json));
    } else {
      for (const [k, v] of Object.entries(routingHeaders)) res.setHeader(k, v);
      outcome = await pipeStream(upstream, res, started, controller);
    }
  } catch (e) {
    if (controller.signal.aborted && !timeoutFlag.get(controller) && !res.headersSent) {
      outcome = { status: 'cancelled', http: 499, code: 'client_disconnected', ttft: null, usage: { p: null, c: null } };
    } else {
      const mapped = mapUpstreamError(e);
      outcome = { status: 'error', http: mapped.status, code: mapped.code, ttft: null, usage: { p: null, c: null } };
      if (!res.headersSent && route.canFallBack && shouldFallBack(e)) {
        movedOn = true;
        log('warn', 'upstream failed; using the configured fallback', { requestId: ctx.requestId, model: m.id, code: mapped.code });
      } else if (!res.headersSent) sendOpenAiError(res, mapped.status, mapped.code, mapped.message, mapped.headers);
      else if (!res.writableEnded) res.end();
    }
  } finally {
    finished = true;
    res.off('close', onClose);
    await writeLog(deps, {
      requestId: ctx.requestId,
      // The idempotency key belongs to the request, so only the attempt that answers carries it (the column is unique).
      clientRequestId: movedOn ? null : clientRequestId,
      deviceId,
      modelId: m.id,
      modelName: m.display_name,
      providerId: m.provider_id,
      providerName: m.provider_name,
      stream: parsed.stream,
      latencyMs: Date.now() - started,
      ...outcome,
    });
  }
  return !movedOn;
}

function usageOf(u: any): { p: number | null; c: number | null } {
  return {
    p: Number.isInteger(u?.prompt_tokens) ? u.prompt_tokens : null,
    c: Number.isInteger(u?.completion_tokens) ? u.completion_tokens : null,
  };
}

interface Mapped {
  status: number;
  code: string;
  message: string;
  headers?: Record<string, string>;
}

/** Upstream failures become stable codes. Provider messages are not forwarded, because they may echo details the owner did not intend to expose. */
export function mapUpstreamError(e: unknown): Mapped {
  if (e instanceof HttpError) return { status: e.status, code: e.code, message: e.message, headers: e.headers };
  if (e instanceof UpstreamError) {
    switch (e.kind) {
      case 'auth':
        return { status: 502, code: 'upstream_auth_failed', message: 'the provider rejected the stored API key; the owner must update it' };
      case 'rate_limited':
        return { status: 429, code: 'upstream_rate_limited', message: 'the provider is rate limiting requests; try again shortly', headers: { 'retry-after': '20' } };
      case 'timeout':
        return { status: 504, code: 'upstream_timeout', message: 'the provider did not answer in time' };
      case 'unreachable':
        return { status: 502, code: 'upstream_unreachable', message: 'the provider could not be reached' };
      case 'rejected':
        return { status: 400, code: 'upstream_rejected', message: 'the provider rejected this request; try a shorter conversation or another model' };
      default:
        return { status: 502, code: 'upstream_error', message: 'the provider failed to answer' };
    }
  }
  return { status: 500, code: 'internal_error', message: 'the request could not be completed' };
}

/**
 * Calls the upstream. Retries once only for a connection failure before any response bytes arrived.
 * A timeout covers the wait for headers; for streams, the caller applies an idle timeout to the body.
 */
async function callUpstream(
  deps: Deps,
  url: string,
  body: Record<string, unknown>,
  key: string | null,
  timeoutMs: number,
  retries: number,
  stream: boolean,
  controller: AbortController,
): Promise<Response> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: stream ? 'text/event-stream' : 'application/json',
  };
  if (key) headers.authorization = `Bearer ${key}`;
  const payload = JSON.stringify(body);
  let attempt = 0;
  for (;;) {
    const timer = setTimeout(() => {
      timeoutFlag.set(controller, true);
      controller.abort();
    }, timeoutMs);
    try {
      const res = await deps.fetch(url, { method: 'POST', headers, body: payload, signal: controller.signal });
      clearTimeout(timer);
      if (res.status === 401 || res.status === 403) {
        await res.body?.cancel().catch(() => undefined);
        throw new UpstreamError('auth', 'auth', res.status);
      }
      if (res.status === 429) {
        await res.body?.cancel().catch(() => undefined);
        throw new UpstreamError('rate_limited', 'rate limited', 429);
      }
      if (res.status >= 500) {
        await res.body?.cancel().catch(() => undefined);
        throw new UpstreamError('server', 'server error', res.status);
      }
      if (!res.ok) {
        await res.body?.cancel().catch(() => undefined);
        throw new UpstreamError('rejected', 'rejected', res.status);
      }
      return res;
    } catch (e) {
      clearTimeout(timer);
      if (e instanceof UpstreamError) throw e;
      if (controller.signal.aborted) {
        if (timeoutFlag.get(controller)) throw new UpstreamError('timeout', 'timeout');
        throw e;
      }
      if (attempt < retries) {
        attempt++;
        continue;
      }
      throw new UpstreamError('unreachable', 'unreachable');
    }
  }
}

/** Set by the timeout timers, so a timeout is reported as such and not as a client cancellation. */
const timeoutFlag = new WeakMap<AbortController, boolean>();

async function readLimited(res: Response, limit: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      throw new UpstreamError('bad_response', 'response too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Relays the upstream SSE stream unchanged and reads usage from the final chunk when the provider reports it. */
async function pipeStream(
  upstream: Response,
  res: ServerResponse,
  started: number,
  controller: AbortController,
): Promise<{ status: 'ok' | 'error' | 'cancelled'; http: number; code: string | null; ttft: number | null; usage: { p: number | null; c: number | null } }> {
  const reader = upstream.body?.getReader();
  if (!reader) throw new UpstreamError('bad_response', 'no stream');
  const idleMs = 120_000;
  let idle: NodeJS.Timeout | undefined;
  const armIdle = () => {
    clearTimeout(idle);
    idle = setTimeout(() => {
      timeoutFlag.set(controller, true);
      controller.abort();
    }, idleMs);
  };
  armIdle();
  let ttft: number | null = null;
  let usage = { p: null as number | null, c: null as number | null };
  let tail = '';
  let started200 = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      armIdle();
      if (ttft === null) ttft = Date.now() - started;
      if (!started200) {
        res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no' });
        started200 = true;
      }
      if (!res.writableEnded && !res.destroyed) res.write(value);
      tail += Buffer.from(value).toString('utf8');
      let nl: number;
      while ((nl = tail.indexOf('\n')) >= 0) {
        const line = tail.slice(0, nl).trim();
        tail = tail.slice(nl + 1);
        if (line.startsWith('data:') && line.includes('"usage"')) {
          try {
            const u = usageOf(JSON.parse(line.slice(5)).usage);
            if (u.p !== null || u.c !== null) usage = u;
          } catch {
            /* a partial or non-JSON line is ignored */
          }
        }
      }
      if (tail.length > 262_144) tail = tail.slice(-65_536);
    }
    clearTimeout(idle);
    if (!started200) {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
    }
    res.end();
    return { status: 'ok', http: 200, code: null, ttft, usage };
  } catch (e) {
    clearTimeout(idle);
    await reader.cancel().catch(() => undefined);
    if (controller.signal.aborted && !timeoutFlag.get(controller)) {
      if (!res.writableEnded) res.end();
      return { status: 'cancelled', http: 499, code: 'client_disconnected', ttft, usage };
    }
    const timed = timeoutFlag.get(controller) === true;
    if (started200) {
      const err = timed ? { code: 'upstream_timeout', message: 'the provider stopped sending data' } : { code: 'upstream_error', message: 'the provider stream was interrupted' };
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify({ error: { message: err.message, type: 'server_error', code: err.code } })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
      }
      return { status: 'error', http: 200, code: err.code, ttft, usage };
    }
    throw timed ? new UpstreamError('timeout', 'timeout') : new UpstreamError('unreachable', 'interrupted');
  }
}

async function writeLog(
  deps: Deps,
  r: {
    requestId: string;
    clientRequestId: string | null;
    deviceId: string;
    modelId: string;
    modelName: string;
    providerId: string;
    providerName: string;
    stream: boolean;
    latencyMs: number;
    status: 'ok' | 'error' | 'cancelled';
    http: number;
    code: string | null;
    ttft: number | null;
    usage: { p: number | null; c: number | null };
  },
): Promise<void> {
  const reported = r.usage.p !== null || r.usage.c !== null;
  const params = [
    r.deviceId,
    r.modelId,
    r.modelName,
    r.providerId,
    r.providerName,
    r.status,
    r.http,
    r.code,
    r.stream,
    Math.max(0, Math.round(r.latencyMs)),
    r.ttft,
    r.usage.p,
    r.usage.c,
    reported ? 'provider_reported' : 'none',
    r.requestId,
    r.clientRequestId,
  ];
  // Usage is written once per request. A short retry covers a brief database hiccup; a duplicate client key is ignored.
  const sql = `INSERT INTO request_logs (device_id, model_id, model_name, provider_id, provider_name, status, http_status, error_code, stream, latency_ms, ttft_ms, prompt_tokens, completion_tokens, usage_source, request_id, client_request_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       ON CONFLICT DO NOTHING`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await deps.db.query(sql, params);
      return;
    } catch (e) {
      if (attempt === 3) {
        log('error', 'could not write request log', { requestId: r.requestId, attempts: attempt, error: errText(e) });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 150 * attempt));
    }
  }
}

