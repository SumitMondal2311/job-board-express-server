import jwt from 'jsonwebtoken';
import { env } from '../configs/env.config';

export const verifyRefreshToken = (token: string): jwt.JwtPayload | string => {
    return jwt.verify(token, env.REFRESH_TOKEN_SECRET);
};
