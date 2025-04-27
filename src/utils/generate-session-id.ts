import { randomBytes } from 'crypto';

export const generateSessionId = (): string => {
    return randomBytes(32).toString('hex');
};
