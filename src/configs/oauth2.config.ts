import { env } from './env.config';

export const GOOGLE_REDIRECT_URL = `http://localhost:${env.PORT}/api/auth/google/callback`;
