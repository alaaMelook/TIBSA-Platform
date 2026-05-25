const fs = require('fs');
const path = require('path');

// Get the directory where this script is located
const scriptDir = __dirname;
const appDir = path.join(scriptDir, 'src', 'app');
const suspendedDir = path.join(appDir, 'suspended-account');
const pageFile = path.join(suspendedDir, 'page.tsx');

// Read the suspended-account.tsx file
const sourceFile = path.join(appDir, 'suspended-account.tsx');

try {
    // Create directory if it doesn't exist
    if (!fs.existsSync(suspendedDir)) {
        fs.mkdirSync(suspendedDir, { recursive: true });
    }

    // Copy the content to page.tsx
    if (fs.existsSync(sourceFile)) {
        const content = fs.readFileSync(sourceFile, 'utf8');
        fs.writeFileSync(pageFile, content);
        console.log('✓ Successfully created app/suspended-account/page.tsx');
    } else {
        console.log('Source file not found:', sourceFile);
    }
} catch (error) {
    console.error('Error creating folder structure:', error.message);
    process.exit(1);
}
