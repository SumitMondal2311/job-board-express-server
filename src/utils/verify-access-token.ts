import jwt from 'jsonwebtoken';
import { env } from '../configs/env.config';

export const verifyAccessToken = (token: string): jwt.JwtPayload | string => {
    return jwt.verify(token, env.ACCESS_TOKEN_SECRET);
};
