import { fileURLToPath } from 'node:url';
import { DemoError, runDemo } from './e1-run.ts';
const arg = process.argv.slice(2);
try {
  if (arg.length > 1 || (arg.length === 1 && !['--check', '--payments', '--run'].includes(arg[0]))) throw new Error('Invalid arguments');
  const mode = arg[0] === '--run' ? 'full' : arg[0] === '--payments' ? 'payments' : 'check';
  await runDemo(fileURLToPath(new URL('../../', import.meta.url)), process.env, mode);
} catch (error) {
  if (error instanceof DemoError) process.stderr.write(`${error.message}\n`);
  process.stderr.write('E1 stopped. Check the last prerequisite/step and retained run lock. Inspect existing receipts and M1 order records before retrying. No automatic payment retry was attempted.\n');
  process.exitCode = 1;
}
