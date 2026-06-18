const fs = require('fs');
const path = require('path');

const dir = 'd:\\Zaghloula\\Career\\Last Dance\\TIBSA\\TIBSA-Platform\\frontend\\src';

const replacements = [
  // Hardcoded dark hex backgrounds
  { regex: /bg-\[#0f1523\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#0d1117\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-\[#151c2e\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-page)]' },
  { regex: /bg-\[#1e293b\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#0D1525\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#020202\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-\[#1e2d4a\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#1a2744\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-\[#263554\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#0b1120\](?:\/[0-9]+)?/gi, replace: 'bg-[var(--bg-elevated)]' },
  
  // Specific blues/purples to emerald for Button
  { regex: /bg-\[#3b82f6\]/gi, replace: 'bg-[var(--primary)]' },
  { regex: /hover:bg-\[#60a5fa\]/gi, replace: 'hover:bg-[var(--primary-hover)]' },
  { regex: /shadow-blue-[0-9]+\/[0-9]+/g, replace: 'shadow-[var(--primary-soft)]' },
  { regex: /focus:ring-blue-[0-9]+/g, replace: 'focus:ring-[var(--primary)]' },
  { regex: /border-blue-[0-9]+\/[0-9]+/g, replace: 'border-[var(--primary)]' },
  { regex: /focus:border-blue-[0-9]+/g, replace: 'focus:border-[var(--primary)]' },
  
  { regex: /text-blue-500/g, replace: 'text-[var(--primary)]' },
  { regex: /text-blue-400/g, replace: 'text-[var(--primary)]' },
  { regex: /text-blue-300/g, replace: 'text-[var(--primary)]' },
  { regex: /bg-blue-500/g, replace: 'bg-[var(--primary)]' },
  { regex: /bg-blue-600/g, replace: 'bg-[var(--primary-hover)]' },
  
  { regex: /hover:bg-\[#2d3f61\]/gi, replace: 'hover:bg-[var(--bg-elevated)]' },
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
