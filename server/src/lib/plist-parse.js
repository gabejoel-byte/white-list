'use strict';
// Minimal Apple plist (XML) PARSER — devices send plist bodies in the MDM
// check-in and command protocol. Handles the subset Apple uses: dict, array,
// string, integer, real, true/false, data (base64 -> Buffer), date.
// Dependency-free and paired with ../../../ios/src/plist.js (the serializer).

function decodeEntities(s) {
  return String(s)
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n))
    .replace(/&amp;/g, '&');
}

// Build a lightweight tree from the tag stream, then convert to JS values.
function parse(xml) {
  xml = String(xml).replace(/<\?xml[^>]*\?>/g, '').replace(/<!DOCTYPE[^>]*>/g, '');
  const m = xml.match(/<plist[^>]*>([\s\S]*)<\/plist>/i);
  const inner = m ? m[1] : xml;

  const root = { name: '#root', children: [], text: '' };
  const stack = [root];
  const re = /<(\/?)([a-zA-Z]+)([^>]*?)(\/?)>/g;
  let last = 0, tag;
  while ((tag = re.exec(inner))) {
    const [full, slash, name, , selfClose] = tag;
    const text = inner.slice(last, tag.index);
    last = re.lastIndex;
    const top = stack[stack.length - 1];
    if (text.trim()) top.text += text;               // text belongs to open element
    if (selfClose) { top.children.push({ name, children: [], text: '' }); }
    else if (slash) { const node = stack.pop(); stack[stack.length - 1].children.push(node); }
    else { stack.push({ name, children: [], text: '' }); }
  }
  return root.children.length ? toValue(root.children[0]) : null;
}

function toValue(node) {
  switch (node.name) {
    case 'true': return true;
    case 'false': return false;
    case 'string': return decodeEntities(node.text);
    case 'integer': return parseInt(node.text || '0', 10);
    case 'real': return parseFloat(node.text || '0');
    case 'data': return Buffer.from((node.text || '').replace(/\s+/g, ''), 'base64');
    case 'date': return new Date(node.text.trim());
    case 'array': return node.children.map(toValue);
    case 'dict': {
      const o = {};
      for (let i = 0; i + 1 < node.children.length; i += 2) {
        o[decodeEntities(node.children[i].text)] = toValue(node.children[i + 1]);
      }
      return o;
    }
    default: return node.text ? decodeEntities(node.text) : null;
  }
}

module.exports = { parse };
