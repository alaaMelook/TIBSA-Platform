const fs = require('fs');
const path = require('path');

const dir = 'd:\\Zaghloula\\Career\\Last Dance\\TIBSA\\TIBSA-Platform\\frontend\\src';

const replacements = [
  // Transparent whites
  { regex: /bg-white\/\[0\.[0-9]+\]/g, replace: 'bg-[var(--bg-elevated)]' },
  { regex: /border-white\/\[0\.[0-9]+\]/g, replace: 'border-[var(--border-strong)]' },
  
  // Hard shadows
  { regex: /shadow-black\/[0-9]+/g, replace: 'shadow-black/5' },
  { regex: /shadow-\[0_[0-9]+px_[0-9]+px_rgba\(0,0,0,[0-9.]+\)\]/g, replace: 'shadow-sm' },
  
  // Remaining from-blue
  { regex: /from-blue-500 to-blue-700/g, replace: 'from-[var(--primary)] to-[var(--primary-hover)]' },
  
  // Specific auth fixes
  { regex: /text-blue-400/g, replace: 'text-[var(--primary)]' },
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
