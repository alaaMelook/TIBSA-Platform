const fs = require('fs');
const path = require('path');

const targetFile = path.join(__dirname, 'src', 'components', 'ai-chatbot', 'FloatingChatbot.tsx');
let content = fs.readFileSync(targetFile, 'utf8');

const replacements = [
  // Floating Button
  {
    find: /bg-gradient-to-br from-blue-500 to-indigo-600 text-\[var\(--text-primary\)\] shadow-2xl/g,
    replace: 'bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white shadow-sm'
  },
  {
    find: /focus:ring-\[var\(--primary\)\]\/30/g,
    replace: 'focus:ring-[var(--primary)]/30' // actually fine
  },
  // Panel Container
  {
    find: /bg-\[var\(--bg-elevated\)\] shadow-2xl backdrop-blur-xl/g,
    replace: 'bg-[var(--bg-card)] shadow-md'
  },
  // Header
  {
    find: /bg-gradient-to-br from-slate-900 to-slate-800 p-4/g,
    replace: 'bg-[var(--bg-card)] p-4'
  },
  {
    find: /bg-gradient-to-br from-blue-500 to-indigo-600 text-\[var\(--text-primary\)\] shadow-inner/g,
    replace: 'bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm'
  },
  {
    find: /text-\[var\(--text-muted\)\]">TIBSA AI Assistant/g,
    replace: 'text-[var(--text-primary)]">TIBSA AI Assistant'
  },
  {
    find: /text-\[var\(--primary\)\]\/80">Cybersecurity & Platform Help/g,
    replace: 'text-[var(--text-secondary)]">Cybersecurity & Platform Help'
  },
  // Close / Minimize
  {
    find: /hover:bg-red-500\/10 hover:text-red-400/g,
    replace: 'hover:bg-red-100 hover:text-red-600'
  },
  {
    find: /hover:bg-\[var\(--bg-elevated\)\] hover:text-\[var\(--text-muted\)\]/g,
    replace: 'hover:bg-[var(--bg-page)] hover:text-[var(--text-primary)]'
  },
  // Chat Body
  {
    find: /bg-gradient-to-b from-\[#0b1120\]\/50 to-slate-900\/50/g,
    replace: 'bg-[var(--bg-page)]'
  },
  // Quick Suggestions
  {
    find: /bg-\[var\(--primary\)\]\/10 px-3\.5 py-2 text-sm font-medium text-\[var\(--primary\)\] transition-all hover:bg-\[var\(--primary\)\]\/25 hover:text-blue-200/g,
    replace: 'bg-[var(--bg-card)] px-3.5 py-2 text-sm font-medium text-[var(--primary)] transition-all hover:bg-[var(--primary-soft)] hover:border-[var(--primary-hover)] hover:text-[var(--primary-hover)]'
  },
  // User bubble
  {
    find: /bg-gradient-to-br from-blue-600 to-indigo-600 p-3\.5 text-sm leading-relaxed text-\[var\(--text-primary\)\] shadow-md/g,
    replace: 'bg-[var(--primary)] p-3.5 text-sm leading-relaxed !text-white shadow-sm'
  },
  // Assistant Avatar
  {
    find: /bg-gradient-to-br from-blue-500 to-indigo-600 text-\[var\(--text-primary\)\] shadow-sm mt-1/g,
    replace: 'bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm mt-1'
  },
  // Assistant bubble
  {
    find: /bg-\[var\(--bg-elevated\)\]\/80 p-4 text-sm leading-relaxed text-\[var\(--text-primary\)\] shadow-sm backdrop-blur-sm/g,
    replace: 'bg-[var(--bg-elevated)] p-4 text-sm leading-relaxed text-[var(--text-primary)] shadow-sm'
  },
  // Loading Avatar
  {
    find: /bg-gradient-to-br from-blue-500 to-indigo-600 text-\[var\(--text-primary\)\] shadow-sm mt-1/g,
    replace: 'bg-[var(--primary-soft)] border border-[var(--primary)] text-[var(--primary)] shadow-sm mt-1'
  },
  // Loading Bubble
  {
    find: /bg-\[var\(--bg-elevated\)\]\/80 px-4 py-3 shadow-sm/g,
    replace: 'bg-[var(--bg-elevated)] px-4 py-3 shadow-sm'
  },
  // Markdown Code
  {
    find: /bg-black\/30 px-1\.5 py-0\.5 text-\[13px\] font-mono text-\[var\(--primary\)\]/g,
    replace: 'bg-[var(--bg-page)] border border-[var(--border-soft)] px-1.5 py-0.5 text-[13px] font-mono text-[var(--text-primary)]'
  },
  {
    find: /bg-black\/40 p-3 text-\[13px\] font-mono/g,
    replace: 'bg-[var(--bg-page)] p-3 text-[13px] font-mono text-[var(--text-primary)]'
  },
  // Dots pulse
  {
    find: /bg-blue-400/g,
    replace: 'bg-[var(--primary)]'
  },
  // Error bubbles
  {
    find: /text-amber-200\/90/g,
    replace: 'text-amber-700'
  },
  {
    find: /text-red-200\/90/g,
    replace: 'text-red-700'
  },
  // Input area
  {
    find: /bg-\[var\(--bg-card\)\]\/80 p-4 backdrop-blur-md/g,
    replace: 'bg-[var(--bg-card)] p-4'
  },
  // Textarea
  {
    find: /bg-\[var\(--bg-elevated\)\]\/50 py-3\.5 pl-5 pr-14 text-sm leading-relaxed text-\[var\(--text-muted\)\] placeholder-slate-500/g,
    replace: 'bg-[var(--bg-elevated)] py-3.5 pl-5 pr-14 text-sm leading-relaxed text-[var(--text-primary)] placeholder-[var(--text-muted)]'
  },
  // Stop Button
  {
    find: /bg-red-500\/20 text-red-400/g,
    replace: 'bg-red-100 text-red-600'
  },
  {
    find: /hover:bg-red-500\/30/g,
    replace: 'hover:bg-red-200'
  },
  // Send Button
  {
    find: /bg-gradient-to-br from-blue-500 to-indigo-600 text-\[var\(--text-primary\)\] shadow-md/g,
    replace: 'bg-gradient-to-br from-[var(--primary)] to-[var(--primary-hover)] !text-white shadow-sm'
  }
];

let modified = false;
replacements.forEach(({ find, replace }) => {
  if (find.test(content)) {
    content = content.replace(find, replace);
    modified = true;
  }
});

if (modified) {
  fs.writeFileSync(targetFile, content, 'utf8');
  console.log('Chatbot styles successfully replaced!');
} else {
  console.log('No matches found.');
}
