const fs = require('fs');
const path = require('path');

const dir = 'd:\\Zaghloula\\Career\\Last Dance\\TIBSA\\TIBSA-Platform\\frontend\\src';

const replacements = [
  // Backgrounds
  { regex: /bg-\[#0f172a\]/g, replace: 'bg-[var(--bg-main)]' },
  { regex: /bg-\[#020617\]/g, replace: 'bg-[var(--bg-main)]' },
  { regex: /bg-\[#0A101C\]/g, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#050505\]/g, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-\[#050B14\]/g, replace: 'bg-[var(--bg-main)]' },
  { regex: /bg-slate-950/g, replace: 'bg-[var(--bg-page)]' },
  { regex: /bg-slate-900/g, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-slate-800/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-slate-700/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-gray-900/g, replace: 'bg-[var(--bg-card)]' },
  { regex: /bg-gray-800/g, replace: 'bg-[var(--bg-elevated)]' },
  
  // Semi-transparent whites -> Elevated/Card/Page depending on context. Let's just use bg-elevated or bg-page
  { regex: /bg-white\/\[0\.02\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/\[0\.03\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/\[0\.04\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/\[0\.05\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/\[0\.1\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/5/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/10/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /bg-white\/20/g, replace: 'bg-[var(--bg-elevated)]' },
  
  // Text
  { regex: /text-slate-200/g, replace: 'text-[var(--text-primary)]' },
  { regex: /text-slate-300/g, replace: 'text-[var(--text-secondary)]' },
  { regex: /text-slate-400/g, replace: 'text-[var(--text-muted)]' },
  { regex: /text-slate-500/g, replace: 'text-[var(--text-muted)]' },
  { regex: /text-gray-200/g, replace: 'text-[var(--text-primary)]' },
  { regex: /text-gray-300/g, replace: 'text-[var(--text-secondary)]' },
  { regex: /text-gray-400/g, replace: 'text-[var(--text-muted)]' },
  { regex: /text-gray-500/g, replace: 'text-[var(--text-muted)]' },
  
  // Text white (Only match standalone text-white, avoid text-white/50 etc for now, but wait, text-white is common. I will leave text-white where it's part of a button manually, or replace it globally and then manually fix buttons? No, replace globally except if it's right next to a gradient or primary bg. Let's just replace it and fix buttons if they break.)
  { regex: /text-white(?!\/[0-9]+)/g, replace: 'text-[var(--text-primary)]' },

  // Borders
  { regex: /border-white\/5/g, replace: 'border-[var(--border-soft)]' },
  { regex: /border-white\/10/g, replace: 'border-[var(--border-strong)]' },
  { regex: /border-white\/20/g, replace: 'border-[var(--border-strong)]' },
  { regex: /border-white\/\[0\.04\]/g, replace: 'border-[var(--border-soft)]' },
  { regex: /border-white\/\[0\.05\]/g, replace: 'border-[var(--border-soft)]' },
  { regex: /border-white\/\[0\.08\]/g, replace: 'border-[var(--border-soft)]' },
  { regex: /border-white\/\[0\.1\]/g, replace: 'border-[var(--border-strong)]' },
  { regex: /border-slate-800/g, replace: 'border-[var(--border-strong)]' },
  { regex: /border-slate-700/g, replace: 'border-[var(--border-strong)]' },

  // Purple -> Emerald
  { regex: /bg-purple-600(?!\/)/g, replace: 'bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white' },
  { regex: /bg-purple-500(?!\/)/g, replace: 'bg-[var(--primary)] !text-white' },
  { regex: /bg-purple-400(?!\/)/g, replace: 'bg-[var(--primary-hover)]' },
  { regex: /bg-purple-500\/5/g, replace: 'bg-[var(--primary-soft)]' },
  { regex: /bg-purple-500\/10/g, replace: 'bg-[var(--primary-soft)]' },
  { regex: /bg-purple-500\/20/g, replace: 'bg-[var(--primary-soft)]' },
  { regex: /bg-purple-600\/50/g, replace: 'bg-[var(--primary-soft)]' },
  { regex: /text-purple-400/g, replace: 'text-[var(--primary)]' },
  { regex: /text-purple-500/g, replace: 'text-[var(--primary)]' },
  { regex: /border-purple-500\/20/g, replace: 'border-[var(--primary)]' },
  { regex: /border-purple-500\/30/g, replace: 'border-[var(--primary)]' },
  { regex: /border-purple-500\/50/g, replace: 'border-[var(--primary)]' },
  { regex: /border-purple-500/g, replace: 'border-[var(--primary)]' },
  { regex: /shadow-\[0_0_20px_rgba\(147,51,234,0\.3\)\]/g, replace: 'shadow-lg shadow-[var(--primary-soft)]' },
  { regex: /shadow-\[0_0_30px_rgba\(147,51,234,0\.5\)\]/g, replace: 'shadow-xl shadow-[var(--primary-light)]' },
  { regex: /shadow-purple-900\/30/g, replace: 'shadow-lg shadow-[var(--primary-soft)]' },
  { regex: /from-purple-600/g, replace: 'from-[var(--primary)]' },
  { regex: /to-purple-500/g, replace: 'to-[var(--primary-hover)]' },
  { regex: /focus:ring-purple-500\/50/g, replace: 'focus:ring-[var(--primary)]' },
  { regex: /focus:border-purple-500\/50/g, replace: 'focus:border-[var(--primary)]' },
  
  // Cleanups for text-white overriding when inside primary gradient (since I added !text-white)
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
