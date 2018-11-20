const fs = require('fs');
const mkdir = require('mk-dirs');
const pkg = require('./package.json');

let data = fs.readFileSync('src/index.js', 'utf8');

mkdir('dist').then(() => {
	// Copy as is for ESM
	fs.writeFileSync(pkg.module, data);

	data = data
		// Mutate ESM imports & exports for CJS
		.replace(/export class (.+?)(?=(\s|\{))/gi, (_, x) => `exports.${x} = class ${x}`)
		.replace(/import ([\s\S]*?) from (.*)/gi, (_, req, dep) => `const ${req} = require(${dep.replace(';', '')});`);

	fs.writeFileSync(pkg.main, data);
});
