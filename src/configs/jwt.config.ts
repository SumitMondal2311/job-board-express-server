import { env } from './env.config';

export const ACCESS_TOKEN_EXPIRY = 60 * 15;
export const REFRESH_TOKEN_EXPIRY =
    env.NODE_ENV === 'production' ? 60 * 60 * 24 * 7 : 60 * 60 * 12;
