import { readFile, writeFile } from 'node:fs/promises';
const schema = JSON.parse(await readFile(new URL('../../docs/v2/schemas/identity-flow.schema.json', import.meta.url), 'utf8'));
const names = ['FlowView', 'StartFlow', 'PrimaryProof', 'TotpProof', 'ChallengeView', 'EmailIssue', 'EmailProof'];
function typeOf(node) {
  if (node.$ref) return node.$ref.startsWith('shared.schema.json') ? 'string' : node.$ref.split('/').at(-1);
  if (node.const !== undefined) return JSON.stringify(node.const);
  if (node.enum) return node.enum.map(value => JSON.stringify(value)).join(' | ');
  if (node.oneOf) return node.oneOf.map(typeOf).join(' | ');
  if (node.type === 'object') return '{\n' + Object.entries(node.properties).map(([name, value]) => `  ${name}${node.required?.includes(name) ? '' : '?'}: ${typeOf(value)};`).join('\n') + '\n}';
  if (['string', 'boolean', 'number'].includes(node.type)) return node.type;
  throw new Error('Unsupported auth wire schema; update the generator explicitly.');
}
const result = '// Generated from docs/v2/schemas/identity-flow.schema.json. Do not edit.\n' + names.map(name => `export type ${name} = ${typeOf(schema.$defs[name])};`).join('\n\n') + '\n';
await writeFile(new URL('auth-src/app/flow-contracts.generated.ts', import.meta.url), result);
