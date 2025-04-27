import { env } from './env.config';

export const GOOGLE_REDIRECT_URI = `http://localhost:${env.PORT}/api/auth/google/callback`;
