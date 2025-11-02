import { NextResponse } from 'next/server';

export const config = {
  matcher: ['/((?!_next/|favicon.ico|robots.txt|public/).*)'],
};

// Decode Basic Auth header (works both in Edge and Node runtimes)
function decodeBase64(str) {
  try {
    if (typeof atob === 'function') return atob(str);
  } catch {}
  try {
    return Buffer.from(str, 'base64').toString('utf8');
  } catch {
    return '';
  }
}

export default function middleware(req) {
  try {
    const user = process.env.BASIC_AUTH_USER;
    const pass = process.env.BASIC_AUTH_PASS;

    if (!user || !pass) {
      return new NextResponse('⚠️ Missing BASIC_AUTH_USER or BASIC_AUTH_PASS env vars', { status: 500 });
    }

    const auth = req.headers.get('authorization');
    if (!auth || !auth.startsWith('Basic ')) {
      return new NextResponse('Authentication required', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
      });
    }

    const decoded = decodeBase64(auth.slice(6));
    const [username, password] = decoded.split(':');

    if (username === user && password === pass) {
      return NextResponse.next();
    }

    return new NextResponse('Unauthorized', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="LoneRockRanch"' },
    });
  } catch (err) {
    console.error('Middleware error:', err);
    return new NextResponse('Internal error in auth middleware', { status: 500 });
  }
}
