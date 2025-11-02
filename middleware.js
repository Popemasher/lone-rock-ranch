import { NextResponse } from 'next/server';

// Protect everything; adjust matcher to leave paths public if desired.
export const config = { matcher: ['/(.*)'] };

export default function middleware(req) {
  try {
    const user = (process.env.BASIC_AUTH_USER || '').toString();
    const pass = (process.env.BASIC_AUTH_PASS || '').toString();

    // If creds missing, fail closed but don't crash
    if (!user || !pass) {
      return new NextResponse(
        'Authentication misconfigured. Set BASIC_AUTH_USER and BASIC_AUTH_PASS.',
        { status: 500 }
      );
    }

    const header = req.headers.get('authorization') || '';

    if (header.startsWith('Basic ')) {
      const base64 = header.slice(6).trim();

      // atob should exist in Edge; guard just in case
      let decoded = '';
      try { decoded = atob(base64); } catch { decoded = ''; }

      const idx = decoded.indexOf(':');
      if (idx > -1) {
        const u = decoded.slice(0, idx);
        const p = decoded.slice(idx + 1);
        if (u === user && p === pass) {
          return NextResponse.next();
        }
      }
      // If decode fails or bad format, fall through to challenge
    }

    // Not authorized → send challenge (no crash)
    return new NextResponse('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
    });
  } catch {
    // Never throw from middleware; return controlled 500 instead
    return new NextResponse('Auth middleware error', { status: 500 });
  }
}
