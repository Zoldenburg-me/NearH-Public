import { preflight, readRpc, report } from './e1-preflight.ts';

try {
  if (process.argv.length > 2) throw new Error('No arguments supported');
  const checks = await preflight(process.env, {
    near: readRpc(process.env.NEAR_RPC || 'https://rpc.testnet.near.org', 'near'),
    base: readRpc(process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org', 'base'),
    fetch,
  });
  process.stdout.write(`${report(checks)}\n`);
  process.exitCode = checks.some(check => check.status === 'fail') ? 2 : 0;
} catch {
  process.stderr.write('Preflight could not start: use no arguments and HTTPS RPC endpoints without credentials or query strings. No payments submitted.\n');
  process.exitCode = 2;
}
