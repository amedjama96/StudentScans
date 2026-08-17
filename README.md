# StudentScans

StudentScans is a student-built web security project that presents a small set of external domain checks in a simple dashboard.

## v1.0 checks

- DNS A-record lookup
- SPF detection
- DMARC detection and policy reading
- Server-side HTTP security-header inspection
- TLS certificate inspection
- Transparent 0-100 educational score
- Recommendations based on current findings

## Tech stack

React, TypeScript, Vite, Node.js, Express, Google DNS-over-HTTPS and Node.js TLS.

## Run locally

```bash
npm install
node server/index.mjs
```

Open a second terminal:

```bash
npm run dev
```

## Important

The StudentScans score is not a vulnerability assessment, penetration test, compliance certification, or proof that a website is secure.

## Status

v1.0 is the first milestone, not the end of the project. Future versions will expand the checks, improve architecture, add reporting/history and make the scoring model more rigorous.

## Responsible use

Use security-testing functionality only on systems you own or are authorized to assess.
