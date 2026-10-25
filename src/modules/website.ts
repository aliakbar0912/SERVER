// The Devora website's companion data, managed from the admin panel. The website keeps its published
// pricing plans (website_pricing), its support-form inbox (website_support_messages) and the Paddle
// webhook audit ledger (website_webhook_events) in the SAME PocketBase that owns Devora accounts.
// This module gives the owner one place to run all of it: create/edit/publish plans (the website
// /pricing page reads them live), read support messages and browse webhook deliveries. Nothing here
// touches regular Devora collections — the helpers refuse any collection outside the website_* trio.
import type { Ctx } from '../context.ts';
import { PbError } from '../pocketbase.ts';
import { bool, fail, int, readJson, rejectUnknown, requireObject, sendJson, str } from '../http/util.ts';
import { guardOwner } from './auth.ts';

const PRICING = 'website_pricing';
const SUPPORT = 'website_support_messages';
const WEBHOOKS = 'website_webhook_events';

/** PocketBase record ids are 15-char alphanumeric strings (not Postgres UUIDs). */
const PB_ID = /^[A-Za-z0-9_]{1,64}$/;

function recordId(value: string | undefined): string {
  if (!value || !PB_ID.test(value)) fail(404, 'not_found', 'not found');
  return value;
}

export const PRICING_LIMITS = {
  planId: 64,
  name: 120,
  tagline: 200,
  priceDisplay: 32,
  currency: 8,
  paddlePriceId: 128,
  feature: 160,
  maxFeatures: 12,
  maxSortOrder: 10_000,
};

const PLAN_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

function requirePb(ctx: Ctx) {
  if (!ctx.deps.pocketbase) fail(503, 'website_store_not_configured', 'the website store is not configured: set POCKETBASE_URL on this server to manage website data');
  return ctx.deps.pocketbase;
}

function pbMessage(e: unknown): string {
  if (e instanceof PbError) {
    if (e.status === 404) return 'the website store was not found — run the website collections setup first (see INTEGRATION.md of the website)';
    if (e.status === 0) return 'the account service cannot be reached right now; try again shortly';
    return e.message;
  }
  return 'the account service returned an unexpected answer';
}

async function wrapAsync<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof PbError) fail(e.status || 502, 'website_store_error', pbMessage(e));
    throw e;
  }
}

// ------------------------------------------------------------------ pricing

function planView(r: any) {
  let features: string[] = [];
  if (Array.isArray(r?.features)) features = r.features.filter((f: unknown) => typeof f === 'string' && f.trim().length > 0).map((f: string) => f.slice(0, PRICING_LIMITS.feature));
  return {
    id: String(r?.id ?? ''),
    planId: String(r?.planId ?? ''),
    name: String(r?.name ?? ''),
    tagline: typeof r?.tagline === 'string' ? r.tagline : '',
    billingPeriod: r?.billingPeriod === 'year' ? 'year' : 'month',
    priceDisplay: typeof r?.priceDisplay === 'string' ? r.priceDisplay : '',
    currency: typeof r?.currency === 'string' ? r.currency : '',
    paddlePriceId: typeof r?.paddlePriceId === 'string' ? r.paddlePriceId : '',
    features,
    highlighted: r?.highlighted === true,
    enabled: r?.enabled === true,
    sortOrder: Number.isFinite(r?.sortOrder) ? Number(r.sortOrder) : 0,
    created: typeof r?.created === 'string' ? r.created : '',
    updated: typeof r?.updated === 'string' ? r.updated : '',
  };
}

function readPlan(body: Record<string, unknown>, partial: boolean): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const planId = str(body, 'planId', { min: 1, max: PRICING_LIMITS.planId, optional: partial });
  if (planId !== undefined) {
    if (!PLAN_ID.test(planId)) fail(400, 'invalid_request', 'planId must be lowercase letters, digits or dashes (e.g. "pro-monthly")');
    out.planId = planId;
  }
  const name = str(body, 'name', { min: 1, max: PRICING_LIMITS.name, optional: partial });
  if (name !== undefined) out.name = name.trim();
  const tagline = str(body, 'tagline', { min: 0, max: PRICING_LIMITS.tagline, optional: true });
  if (tagline !== undefined) out.tagline = tagline.trim();
  if (body.billingPeriod !== undefined) {
    if (body.billingPeriod !== 'month' && body.billingPeriod !== 'year') fail(400, 'invalid_request', 'billingPeriod must be "month" or "year"');
    out.billingPeriod = body.billingPeriod;
  }
  const priceDisplay = str(body, 'priceDisplay', { min: 0, max: PRICING_LIMITS.priceDisplay, optional: true });
  if (priceDisplay !== undefined) out.priceDisplay = priceDisplay.trim();
  const currency = str(body, 'currency', { min: 0, max: PRICING_LIMITS.currency, optional: true });
  if (currency !== undefined) out.currency = currency.trim().toUpperCase();
  const paddlePriceId = str(body, 'paddlePriceId', { min: 0, max: PRICING_LIMITS.paddlePriceId, optional: true });
  if (paddlePriceId !== undefined) out.paddlePriceId = paddlePriceId.trim();
  if (body.features !== undefined) {
    if (!Array.isArray(body.features)) fail(400, 'invalid_request', 'features must be a list of short strings');
    const features = (body.features as unknown[])
      .map((f) => (typeof f === 'string' ? f.trim() : ''))
      .filter((f) => f.length > 0)
      .map((f) => {
        if (f.length > PRICING_LIMITS.feature) fail(400, 'invalid_request', `each feature must be at most ${PRICING_LIMITS.feature} characters`);
        return f;
      });
    if (features.length > PRICING_LIMITS.maxFeatures) fail(400, 'invalid_request', `at most ${PRICING_LIMITS.maxFeatures} features per plan`);
    out.features = features;
  }
  const highlighted = bool(body, 'highlighted', { optional: true });
  if (highlighted !== undefined) out.highlighted = highlighted;
  const enabled = bool(body, 'enabled', { optional: true });
  if (enabled !== undefined) out.enabled = enabled;
  const sortOrder = int(body, 'sortOrder', { min: 0, max: PRICING_LIMITS.maxSortOrder, optional: true });
  if (sortOrder !== undefined) out.sortOrder = sortOrder;
  return out;
}

/** GET /admin/api/website/pricing: every published plan, in display order. */
export async function listWebsitePricing(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const pb = requirePb(ctx);
  const { items } = await wrapAsync(() => pb.listRecords(PRICING, { perPage: 200, sort: 'sortOrder' }));
  sendJson(ctx.res, 200, { plans: items.map(planView), limits: PRICING_LIMITS });
}

/** POST /admin/api/website/pricing: adds a plan. It goes live when `enabled`. */
export async function createWebsitePricing(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const pb = requirePb(ctx);
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['planId', 'name', 'tagline', 'billingPeriod', 'priceDisplay', 'currency', 'paddlePriceId', 'features', 'highlighted', 'enabled', 'sortOrder']);
  const plan = readPlan(body, false);
  if (!plan.billingPeriod) plan.billingPeriod = 'month';
  if (!plan.enabled) plan.enabled = false;
  const record = await wrapAsync(() => pb.createRecord(PRICING, plan));
  sendJson(ctx.res, 200, { plan: planView(record) });
}

/** PATCH /admin/api/website/pricing/:id: edits a plan (or toggles enabled). */
export async function updateWebsitePricing(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const pb = requirePb(ctx);
  const id = recordId(ctx.params.id ?? '');
  const body = requireObject(await readJson(ctx.req, 64 * 1024));
  rejectUnknown(body, ['planId', 'name', 'tagline', 'billingPeriod', 'priceDisplay', 'currency', 'paddlePriceId', 'features', 'highlighted', 'enabled', 'sortOrder']);
  const patch = readPlan(body, true);
  const record = await wrapAsync(() => pb.updateRecord(PRICING, id, patch));
  sendJson(ctx.res, 200, { plan: planView(record) });
}

/** DELETE /admin/api/website/pricing/:id: removes the plan from the website. */
export async function deleteWebsitePricing(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const pb = requirePb(ctx);
  const id = recordId(ctx.params.id ?? '');
  await wrapAsync(() => pb.deleteRecord(PRICING, id));
  sendJson(ctx.res, 200, { deleted: true });
}

// ------------------------------------------------------------------ support inbox

function messageView(r: any) {
  return {
    id: String(r?.id ?? ''),
    name: typeof r?.name === 'string' ? r.name : '',
    email: typeof r?.email === 'string' ? r.email : '',
    subject: typeof r?.subject === 'string' ? r.subject : '',
    category: typeof r?.category === 'string' ? r.category : '',
    message: typeof r?.message === 'string' ? r.message : '',
    status: typeof r?.status === 'string' && r.status.length > 0 ? r.status : 'new',
    created: typeof r?.created === 'string' ? r.created : '',
  };
}

/** GET /admin/api/website/support-messages: the newest 200 messages from the website's support form. */
export async function listWebsiteSupport(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const pb = requirePb(ctx);
  const { items } = await wrapAsync(() => pb.listRecords(SUPPORT, { perPage: 200, sort: '-created' }));
  sendJson(ctx.res, 200, { messages: items.map(messageView) });
}

/** PATCH /admin/api/website/support-messages/:id { status }: mark a message handled/closed. */
export async function updateWebsiteSupport(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const pb = requirePb(ctx);
  const id = recordId(ctx.params.id ?? '');
  const body = requireObject(await readJson(ctx.req, 4 * 1024));
  rejectUnknown(body, ['status']);
  const status = str(body, 'status', { min: 1, max: 20 });
  if (!['new', 'open', 'handled'].includes(status!)) fail(400, 'invalid_request', 'status must be one of: new, open, handled');
  const record = await wrapAsync(() => pb.updateRecord(SUPPORT, id, { status }));
  sendJson(ctx.res, 200, { message: messageView(record) });
}

/** DELETE /admin/api/website/support-messages/:id: removes a message from the inbox. */
export async function deleteWebsiteSupport(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: true });
  const pb = requirePb(ctx);
  const id = recordId(ctx.params.id ?? '');
  await wrapAsync(() => pb.deleteRecord(SUPPORT, id));
  sendJson(ctx.res, 200, { deleted: true });
}

// ------------------------------------------------------------------ webhook ledger

function webhookView(r: any) {
  const payload = typeof r?.payload === 'string' ? r.payload : '';
  return {
    id: String(r?.id ?? ''),
    eventId: typeof r?.eventId === 'string' ? r.eventId : '',
    eventType: typeof r?.eventType === 'string' ? r.eventType : '',
    created: typeof r?.created === 'string' ? r.created : '',
    payloadBytes: payload.length,
    payloadPreview: payload.slice(0, 2_000),
  };
}

/** GET /admin/api/website/webhook-events: the newest 100 Paddle webhook deliveries (audit view). */
export async function listWebsiteWebhookEvents(ctx: Ctx): Promise<void> {
  await guardOwner(ctx, { write: false });
  const pb = requirePb(ctx);
  const { items } = await wrapAsync(() => pb.listRecords(WEBHOOKS, { perPage: 100, sort: '-created' }));
  sendJson(ctx.res, 200, { events: items.map(webhookView) });
}
