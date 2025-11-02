import { NextResponse } from 'next/server';

// Protect HTML routes; let Next assets & common public files pass
export const config = {
  matcher: ['/((?!_next/|favicon.ico|robots.txt|sitemap.xml|public-open/).*)'],
};

function b64decode(b64) {
  try {
    // Edge runtime
    if (typeof atob === 'function') return atob(b64);
  } catch {}
  try {
    // Node runtime (in case middleware runs there)
    if (typeof Buffer !== 'undefined') return Buffer.from(b64, 'base64').toString('utf8');
  } catch {}
  return '';
}

export default function middleware(req) {
  try {
    const user = (process.env.BASIC_AUTH_USER || '').toString();
    const pass = (process.env.BASIC_AUTH_PASS || '').toString();

    if (!user || !pass) {
      return new NextResponse('Authentication misconfigured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS.', { status: 500 });
    }

    const header = req.headers.get('authorization');
    if (!header || !header.startsWith('Basic ')) {
      return new NextResponse('Authentication required', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
      });
    }

    const decoded = b64decode(header.slice(6).trim());
    const sep = decoded.indexOf(':');
    if (sep > -1) {
      const u = decoded.slice(0, sep);
      const p = decoded.slice(sep + 1);
      if (u === user && p === pass) {
        return NextResponse.next();
      }
    }

    // Wrong creds → challenge again
    return new NextResponse('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
    });
  } catch {
    // Never throw from middleware
    return new NextResponse('Auth middleware error', { status: 500 });
  }
}
