import { NextFunction, Request, Response } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { SESSION_PREFIX } from '../configs/redis.config';
import { redis } from '../lib/redis-client';
import { AuthenticatedRequest } from '../types/authenticated-request.type';
import { SessionInfo } from '../types/session-info.type';
import { UserInfo } from '../types/user-info.type';
import { cacheUserInfo } from '../utils/cache-user-info';
import { checkJwtError } from '../utils/check-jwt-error';
import { verifyAccessToken } from '../utils/verify-access-token';
import { verifyRefreshToken } from '../utils/verify-refresh-token';

export const authMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        const refreshToken = req.cookies['__refresh_token__'];
        if (!refreshToken) {
            return next({ status: 401, message: 'Missing refresh token' });
        }

        const decodedRefreshToken = verifyRefreshToken(
            refreshToken
        ) as JwtPayload;

        const { sid } = decodedRefreshToken;

        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            return next({ status: 401, message: 'Missing auth header' });
        }

        if (!authHeader?.startsWith('Bearer ')) {
            return next({ status: 400, message: 'Invalid auth header' });
        }

        const accessToken = authHeader.split(' ')[1];
        if (accessToken.split('.').length !== 3) {
            return next({ status: 401, message: 'Malformed access token' });
        }

        const isRevoked = await redis.exists(`blacklist:${accessToken}`);
        if (isRevoked === 1) {
            return next({
                status: 403,
                message: 'Received revoked access token',
            });
        }

        const { id, role } = verifyAccessToken(accessToken) as JwtPayload;
        const user = (await cacheUserInfo(id, role)) as UserInfo;
        if (!user) {
            return next({ status: 404, message: 'User not found' });
        }

        const existingSessionKey = `${SESSION_PREFIX}-${user.id}:${sid}`;
        const sessionInfo = await redis.get<SessionInfo>(existingSessionKey);
        if (!sessionInfo) {
            return next({ status: 404, message: 'Session not found' });
        }

        (req as AuthenticatedRequest).data = {
            decoded: decodedRefreshToken,
            user,
            sessionInfo,
        };

        next();
    } catch (error) {
        if (checkJwtError(error)) {
            return next({ status: 401, message: 'Invalid or expired token' });
        }

        next(error);
    }
};
