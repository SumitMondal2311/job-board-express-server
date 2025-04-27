import { Response } from 'express';
import { env } from '../configs/env.config';

export const generateCookie = (
    name: string,
    value: object | string,
    { httpOnly, maxAge }: { httpOnly: boolean; maxAge: number },
    res: Response
) => {
    return res.cookie(name, value, {
        path: '/',
        httpOnly,
        secure: env.NODE_ENV === 'production',
        maxAge,
        sameSite: 'lax',
    });
};
