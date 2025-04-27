import { Request, Response, Router } from 'express';
import { env } from '../configs/env.config';
import { GOOGLE_REDIRECT_URI } from '../configs/oauth2.config';
import {
    googleOAuth,
    login,
    logout,
    refreshToken,
    signup,
} from '../controllers/auth.controllers';
import { authRateLimiter } from '../middlewares/auth-rate-limiter';
import { authMiddleware } from '../middlewares/auth.middleware';
import { handleAsync } from '../utils/handle-async';

export const router = Router();

router.post('/signup', authRateLimiter, handleAsync(signup));
router.post('/login', authRateLimiter, handleAsync(login));
router.get('/google', (_req: Request, res: Response) => {
    res.redirect(
        `https://accounts.google.com/o/oauth2/v2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${GOOGLE_REDIRECT_URI}&response_type=code&scope=email%20profile`
    );
});
router.get('/google/callback', handleAsync(googleOAuth));
router.get('/refresh-token', handleAsync(refreshToken));
router.post('/logout', authMiddleware, handleAsync(logout));
