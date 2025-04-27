import jwt from 'jsonwebtoken';
import { env } from '../configs/env.config';
import { ACCESS_TOKEN_EXPIRY } from '../configs/jwt.config';

export const generateAccessToken = (id: string, role: string): string => {
    return jwt.sign({ id, role }, env.ACCESS_TOKEN_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRY,
    });
};
