import { buildUpdateHelperApp } from './app.js';

const port = Number.parseInt(process.env.DEPLOY_HELPER_PORT || '9850', 10) || 9850;
const host = (process.env.DEPLOY_HELPER_HOST || '0.0.0.0').trim() || '0.0.0.0';
const token = String(process.env.DEPLOY_HELPER_TOKEN || '').trim();

if (!token) {
  throw new Error('DEPLOY_HELPER_TOKEN is required');
}

const app = await buildUpdateHelperApp({ token });

try {
  await app.listen({ port, host });
  app.log.info(`Deploy helper listening on http://${host}:${port}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
