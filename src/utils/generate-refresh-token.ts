import jwt from 'jsonwebtoken';
import { env } from '../configs/env.config';
import { REFRESH_TOKEN_EXPIRY } from '../configs/jwt.config';

export const generateRefreshToken = (
    sid: string,
    uid: string,
    role: string
): string => {
    return jwt.sign({ sid, uid, role }, env.REFRESH_TOKEN_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRY,
    });
};
