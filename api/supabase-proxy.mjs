/**
 * Content OS - Supabase same-origin proxy for Vercel Functions.
 *
 * Security model:
 * - Uses ONLY the publishable key, never the service-role key.
 * - Forwards the signed-in user's Authorization bearer token so Supabase RLS
 *   remains the source of truth.
 * - Restricts forwarding to this project's Auth, REST and Edge Functions paths.
 * - Does not proxy arbitrary external URLs.
 */

const ALLOWED_PREFIXES = ['/auth/v1/', '/rest/v1/', '/functions/v1/'];
const BODYLESS_METHODS = new Set(['GET', 'HEAD']);
const REQUEST_HEADER_ALLOWLIST = new Set([
  'accept',
  'accept-language',
  'authorization',
  'apikey',
  'content-type',
  'prefer',
  'range',
  'if-match',
  'if-none-match',
  'accept-profile',
  'content-profile',
  'x-client-info',
  'x-upsert',
  'x-captcha-token',
  'x-supabase-api-version'
]);
const RESPONSE_HEADER_BLOCKLIST = new Set([
  'connection',
  'content-encoding',
  'content-length',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'set-cookie',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade'
]);

function json(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-os-proxy': 'vercel',
      ...extraHeaders
    }
  });
}

function normalizeBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

export default {
  async fetch(request) {
    const requestUrl = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'allow': 'GET,HEAD,POST,PATCH,PUT,DELETE,OPTIONS',
          'cache-control': 'no-store',
          'x-content-os-proxy': 'vercel'
        }
      });
    }

    if (requestUrl.searchParams.get('health') === '1') {
      return json({
        ok: true,
        service: 'content-os-supabase-proxy',
        region: process.env.VERCEL_REGION || 'unknown',
        configured: Boolean(
          process.env.SUPABASE_URL &&
          (process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY)
        )
      });
    }

    const supabaseUrl = normalizeBaseUrl(process.env.SUPABASE_URL);
    const publishableKey = String(
      process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || ''
    ).trim();

    if (!supabaseUrl || !publishableKey) {
      return json({
        error: 'Vercel 环境变量未配置',
        required: ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY']
      }, 500);
    }

    let supabaseOrigin;
    try {
      supabaseOrigin = new URL(supabaseUrl).origin;
    } catch (_) {
      return json({ error: 'SUPABASE_URL 格式不正确' }, 500);
    }

    const rawPath = String(requestUrl.searchParams.get('path') || '');
    if (!rawPath.startsWith('/') || rawPath.includes('\\') || rawPath.includes('://')) {
      return json({ error: '无效的代理路径' }, 400);
    }
    if (!ALLOWED_PREFIXES.some(prefix => rawPath.startsWith(prefix))) {
      return json({ error: '该 Supabase 路径不允许通过此代理访问' }, 403);
    }

    const targetUrl = new URL(rawPath, `${supabaseUrl}/`);
    if (targetUrl.origin !== supabaseOrigin) {
      return json({ error: '代理目标不合法' }, 403);
    }

    const upstreamHeaders = new Headers();
    for (const [name, value] of request.headers.entries()) {
      const lower = name.toLowerCase();
      if (REQUEST_HEADER_ALLOWLIST.has(lower)) upstreamHeaders.set(lower, value);
    }

    // The API key identifies the application. The user JWT, when present,
    // continues to identify the signed-in user and enforce RLS.
    upstreamHeaders.set('apikey', publishableKey);
    if (!upstreamHeaders.has('authorization')) {
      upstreamHeaders.set('authorization', `Bearer ${publishableKey}`);
    }
    upstreamHeaders.set('x-content-os-proxy', 'vercel');

    const method = String(request.method || 'GET').toUpperCase();
    const abortController = new AbortController();
    const timer = setTimeout(() => abortController.abort('upstream timeout'), 45000);

    try {
      const upstreamInit = {
        method,
        headers: upstreamHeaders,
        signal: abortController.signal,
        redirect: 'manual'
      };
      if (!BODYLESS_METHODS.has(method)) {
        upstreamInit.body = await request.arrayBuffer();
      }

      const upstreamResponse = await fetch(targetUrl, upstreamInit);
      const responseHeaders = new Headers();
      for (const [name, value] of upstreamResponse.headers.entries()) {
        if (!RESPONSE_HEADER_BLOCKLIST.has(name.toLowerCase())) {
          responseHeaders.set(name, value);
        }
      }
      responseHeaders.set('cache-control', 'no-store');
      responseHeaders.set('x-content-os-proxy', 'vercel');

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders
      });
    } catch (error) {
      const isTimeout = error?.name === 'AbortError' || abortController.signal.aborted;
      return json({
        error: isTimeout ? 'Supabase 上游请求超时' : 'Supabase 上游请求失败',
        detail: error?.message || String(error)
      }, isTimeout ? 504 : 502);
    } finally {
      clearTimeout(timer);
    }
  }
};
