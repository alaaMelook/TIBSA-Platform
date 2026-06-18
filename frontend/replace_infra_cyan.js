const fs = require('fs');
const path = require('path');

const targetDir = path.join(__dirname, 'src', 'app', 'dashboard', 'infra-investigations');

const replacements = [
  { regex: /cyan-400/g, replacement: '[var(--primary)]' },
  { regex: /cyan-500\/10/g, replacement: '[var(--primary)]/10' },
  { regex: /cyan-500\/15/g, replacement: '[var(--primary-soft)]' },
  { regex: /cyan-500\/20/g, replacement: '[var(--primary)]/20' },
  { regex: /cyan-500\/25/g, replacement: '[var(--primary)]/25' },
  { regex: /cyan-500\/30/g, replacement: '[var(--primary)]/30' },
  { regex: /cyan-500\/40/g, replacement: '[var(--primary)]/40' },
  { regex: /cyan-500\/50/g, replacement: '[var(--primary)]/50' },
  { regex: /cyan-500\/[0-9.]+/g, replacement: '[var(--primary)]/10' },
  { regex: /cyan-500/g, replacement: 'emerald-500' },
  { regex: /cyan-600/g, replacement: 'emerald-600' },
  { regex: /cyan-950/g, replacement: 'emerald-950' },
  { regex: /bg-gradient-to-r from-cyan-500 to-blue-500/g, replacement: 'bg-gradient-to-r from-[var(--primary)] to-[var(--primary-hover)]' },
  { regex: /bg-blue-400/g, replacement: 'bg-[var(--primary)]' },
];

function processDirectory(directory) {
  const files = fs.readdirSync(directory);
  
  for (const file of files) {
    const fullPath = path.join(directory, file);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      processDirectory(fullPath);
    } else if (file.endsWith('.tsx')) {
      let content = fs.readFileSync(fullPath, 'utf8');
      let modified = false;
      
      for (const { regex, replacement } of replacements) {
        if (regex.test(content)) {
          content = content.replace(regex, replacement);
          modified = true;
        }
      }
      
      if (modified) {
        fs.writeFileSync(fullPath, content, 'utf8');
        console.log(`Updated: ${fullPath}`);
      }
    }
  }
}

processDirectory(targetDir);
console.log('Done!');
