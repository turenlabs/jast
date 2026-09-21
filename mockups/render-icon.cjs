// Renders icon.html to icon.png (1024x1024, transparent background).
// Usage: npx --yes --package playwright -c 'node jast/mockups/render-icon.cjs'
// Then: npm run tauri -- icon jast/mockups/icon.png
const path = require('node:path');
let chromium;
for (const bin of process.env.PATH.split(path.delimiter)) {
  try { ({chromium} = require(require.resolve('playwright', {paths:[path.dirname(bin)]}))); break; } catch {}
}
if (!chromium) throw new Error('Run with npx --package playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport: {width: 1024, height: 1024}, deviceScaleFactor: 1});
  await p.goto(`file://${path.join(__dirname, 'icon.html')}`);
  await p.screenshot({path: path.join(__dirname, 'icon.png'), omitBackground: true});
  await b.close();
  console.log(`rendered ${path.join(__dirname, 'icon.png')}`);
})();
