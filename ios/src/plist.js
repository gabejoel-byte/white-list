'use strict';
// Minimal Apple plist (XML) serializer — enough to emit .mobileconfig profiles.
// Supports string, boolean, number (integer/real), Date, Buffer (data), array,
// and plain object (dict). Pure and dependency-free so it is easy to test.

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function node(value, indent) {
  const pad = '  '.repeat(indent);
  if (value === null || value === undefined) return `${pad}<string></string>`;
  if (typeof value === 'boolean') return `${pad}<${value ? 'true' : 'false'}/>`;
  if (typeof value === 'number') {
    return Number.isInteger(value) ? `${pad}<integer>${value}</integer>` : `${pad}<real>${value}</real>`;
  }
  if (value instanceof Date) return `${pad}<date>${value.toISOString().replace(/\.\d+Z$/, 'Z')}</date>`;
  if (Buffer.isBuffer(value)) return `${pad}<data>${value.toString('base64')}</data>`;
  if (Array.isArray(value)) {
    if (!value.length) return `${pad}<array/>`;
    return `${pad}<array>\n${value.map((v) => node(v, indent + 1)).join('\n')}\n${pad}</array>`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.length) return `${pad}<dict/>`;
    const body = keys.map((k) => `${'  '.repeat(indent + 1)}<key>${esc(k)}</key>\n${node(value[k], indent + 1)}`).join('\n');
    return `${pad}<dict>\n${body}\n${pad}</dict>`;
  }
  return `${pad}<string>${esc(value)}</string>`;
}

function build(obj) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${node(obj, 0)}
</plist>`;
}

module.exports = { build, esc };
