const fs = require('fs');
const path = require('path');

const dir = 'd:\\Zaghloula\\Career\\Last Dance\\TIBSA\\TIBSA-Platform\\frontend\\src';

const replacements = [
  // Fix anomalies from previous replace
  { regex: /!text-white\s+text-\[var\(--text-primary\)\]/g, replace: '!text-white' },
  { regex: /text-\[var\(--text-primary\)\]\s+!text-white/g, replace: '!text-white' },
  { regex: /bg-\[var\(--primary\)\]\s+!text-white\s+text-\[var\(--text-primary\)\]/g, replace: 'bg-[var(--primary)] !text-white' },
  { regex: /hover:bg-\[var\(--primary\)\]\s+!text-white/g, replace: 'hover:opacity-90' },
  { regex: /hover:bg-purple-700/g, replace: 'hover:opacity-90' },
  { regex: /hover:bg-purple-600\/50/g, replace: 'hover:bg-[var(--primary-soft)]' },
  { regex: /hover:bg-purple-600/g, replace: 'hover:opacity-90' },
  { regex: /shadow-purple-500\/20/g, replace: 'shadow-[var(--primary-soft)]' },
  { regex: /shadow-purple-[0-9]+\/[0-9]+/g, replace: 'shadow-[var(--primary-soft)]' },
  { regex: /text-purple-[0-9]+/g, replace: 'text-[var(--primary)]' },
  { regex: /bg-purple-[0-9]+\/[0-9]+/g, replace: 'bg-[var(--primary-soft)]' },
  { regex: /border-purple-[0-9]+\/[0-9]+/g, replace: 'border-[var(--primary)]' },
  { regex: /border-purple-[0-9]+/g, replace: 'border-[var(--primary)]' },
  { regex: /ring-purple-[0-9]+\/[0-9]+/g, replace: 'ring-[var(--primary)]' },
  { regex: /ring-purple-[0-9]+/g, replace: 'ring-[var(--primary)]' },

  // Remaining dark theme elements
  { regex: /text-white\/[0-9]+/g, replace: 'text-[var(--text-muted)]' },
  { regex: /bg-slate-[0-9]+\/[0-9]+/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /border-slate-[0-9]+\/[0-9]+/g, replace: 'border-[var(--border-soft)]' },
  { regex: /text-slate-[0-9]+\/[0-9]+/g, replace: 'text-[var(--text-muted)]' },
  { regex: /text-slate-[0-9]+/g, replace: 'text-[var(--text-muted)]' },
  { regex: /bg-slate-[0-9]+/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /border-slate-[0-9]+/g, replace: 'border-[var(--border-strong)]' },

  // White text fixes inside buttons (since some were mapped to text-primary incorrectly)
  // Let's replace button text mappings if they have a gradient
  { regex: /from-\[var\(--primary\)\]\s+to-\[var\(--primary-hover\)\]\s+text-\[var\(--text-primary\)\]/g, replace: 'from-[var(--primary)] to-[var(--primary-hover)] !text-white' },

  // Fix !text-white appearing weirdly without spaces or duplicates
  { regex: /!text-white\s+!text-white/g, replace: '!text-white' },
];

function processFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let originalContent = content;
  
  for (const rep of replacements) {
    content = content.replace(rep.regex, rep.replace);
  }
  
  if (content !== originalContent) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log('Updated:', filePath);
  }
}

function traverse(dirPath) {
  const files = fs.readdirSync(dirPath);
  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    if (fs.statSync(fullPath).isDirectory()) {
      traverse(fullPath);
    } else if (fullPath.endsWith('.tsx') || fullPath.endsWith('.ts')) {
      processFile(fullPath);
    }
  }
}

traverse(dir);
