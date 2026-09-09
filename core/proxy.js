'use strict';
// Platform-agnostic filtering forward-proxy: inspects the Host header on plain
// HTTP and the CONNECT target on HTTPS, and allows/denies by domain using the
// shared verdict logic. No TLS interception (filters by hostname only). Reused
// by every agent; each platform supplies how the OS is pointed at it.
const http = require('http');
const net = require('net');
const { verdict, normHost } = require('./filter');

// opts: { getPolicy(): webPolicy, categories: map, onBlock(host), onLog(msg) }
function createFilterProxy(opts = {}) {
  const getPolicy = opts.getPolicy || (() => ({ mode: 'off' }));
  const categories = opts.categories || {};
  const onBlock = opts.onBlock || (() => {});
  const log = opts.onLog || (() => {});
  let server = null;

  function decide(host) { return verdict(host, getPolicy(), categories); }

  function blockHttp(res, host) {
    onBlock(host);
    res.writeHead(403, { 'content-type': 'text/html' });
    res.end(`<!doctype html><meta charset=utf-8><title>Blocked</title>
      <body style="font:16px system-ui;background:#0e1116;color:#e6edf3;text-align:center;padding:12vh">
      <h1>Access blocked</h1><p><b>${host}</b> is not permitted by your organisation's policy.</p>
      <p style="color:#8b96a5">Whitelist Cloud</p>`);
  }

  function start(port) {
    if (server) return server;
    server = http.createServer((req, res) => {
      const host = normHost(req.headers.host);
      if (decide(host) === 'deny') return blockHttp(res, host);
      const u = new URL(req.url, `http://${req.headers.host}`);
      const pr = http.request({ host: u.hostname, port: u.port || 80, path: u.pathname + u.search, method: req.method, headers: req.headers },
        (up) => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
      pr.on('error', () => { try { res.writeHead(502); res.end('proxy error'); } catch {} });
      req.pipe(pr);
    });
    server.on('connect', (req, clientSocket, head) => {
      const host = normHost(req.url);
      if (decide(host) === 'deny') {
        onBlock(host);
        clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Whitelist Cloud policy');
        return clientSocket.destroy();
      }
      const [h, p] = req.url.split(':');
      const upstream = net.connect(p || 443, h, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.write(head); upstream.pipe(clientSocket); clientSocket.pipe(upstream);
      });
      upstream.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => upstream.destroy());
    });
    server.on('clientError', (e, sock) => { try { sock.end('HTTP/1.1 400\r\n\r\n'); } catch {} });
    server.listen(port, '127.0.0.1', () => log('filtering proxy on 127.0.0.1:' + port));
    return server;
  }

  function stop() { if (server) { server.close(); server = null; } }
  return { start, stop, decide };
}

module.exports = { createFilterProxy };
