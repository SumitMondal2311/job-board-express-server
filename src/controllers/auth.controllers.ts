import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { setTimeout } from 'timers/promises';
import { env } from '../configs/env.config';
import {
    ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_EXPIRY,
} from '../configs/jwt.config';
import { GOOGLE_REDIRECT_URI } from '../configs/oauth2.config';
import { SESSION_PREFIX, USER_CACHE_PREFIX } from '../configs/redis.config';
import { prisma } from '../lib/prisma';
import { redis } from '../lib/redis-client';
import { AuthenticatedRequest } from '../types/authenticated-request.type';
import { SessionInfo } from '../types/session-info.type';
import { UserInfo } from '../types/user-info.type';
import { cacheUserInfo } from '../utils/cache-user-info';
import { checkJwtError } from '../utils/check-jwt-error';
import { compareHash } from '../utils/compare-hash';
import { generateAccessToken } from '../utils/generate-access-token';
import { generateCookie } from '../utils/generate-cookie';
import { generateRefreshToken } from '../utils/generate-refresh-token';
import { generateSessionId } from '../utils/generate-session-id';
import { hashPassword } from '../utils/hash-password';
import { verifyAccessToken } from '../utils/verify-access-token';
import { verifyRefreshToken } from '../utils/verify-refresh-token';
import { loginValidator } from '../validators/login.validator';
import { signupValidator } from '../validators/signup.validator';

export const signup = async (req: Request, res: Response) => {
    const userAgent = req.headers['user-agent'];
    if (!userAgent) {
        return res.status(400).json({ message: 'Missing User-Agent header' });
    }

    const parsed = signupValidator.safeParse(req.body);
    if (!parsed.success) {
        return res
            .status(400)
            .json({ message: parsed.error.issues[0].message });
    }

    const { fullName, role, email, password } = parsed.data;

    const isUserExists = await prisma.user.findUnique({
        where: { email },
        select: { id: true },
    });

    if (isUserExists) {
        await setTimeout(1000);
        return res.status(409).json({ message: 'Email already exists' });
    }

    const hashedPassword = await hashPassword(password);

    const newUser = await prisma.user.create({
        data: { fullName, role, email, password: hashedPassword },
    });

    const accessToken = generateAccessToken(newUser.id, role);

    const sessionId = generateSessionId();
    const refreshToken = generateRefreshToken(sessionId, newUser.id, role);

    await redis.set(
        `${SESSION_PREFIX}-${newUser.id}:${sessionId}`,
        {
            accessToken,
            userAgent,
            createdAt: Date.now(),
        },
        {
            ex: REFRESH_TOKEN_EXPIRY,
        }
    );

    generateCookie(
        '__refresh_token__',
        refreshToken,
        {
            httpOnly: true,
            maxAge: REFRESH_TOKEN_EXPIRY * 1000,
        },
        res
    );

    const { password: _, ...userInfo } = newUser;

    res.status(201).json({
        user: userInfo,
        accessToken,
        message: 'Signed up successfully',
    });
};

export const login = async (req: Request, res: Response) => {
    const userAgent = req.headers['user-agent'];
    if (!userAgent) {
        return res.status(400).json({ message: 'Missing User-Agent header' });
    }

    const parsed = loginValidator.safeParse(req.body);
    if (!parsed.success) {
        return res
            .status(400)
            .json({ message: parsed.error.issues[0].message });
    }

    const { email, password } = parsed.data;

    const user = await prisma.user.findUnique({
        where: { email },
    });

    if (!user) {
        await setTimeout(1000);
        return res.status(401).json({ message: 'Incorrect email or password' });
    }

    const isMatched = await compareHash(password, user.password!);
    if (!isMatched) {
        await setTimeout(1000);
        return res.status(401).json({ message: 'Incorrect email or password' });
    }

    if (user.isAuthByGoogle) {
        return res.status(403).json({
            message: 'This email is registed via Google, Please log via Google',
        });
    }

    const sessionKeys = [];

    const [_cursor, keys] = await redis.scan(0, {
        match: `${SESSION_PREFIX}-${user.id}:*`,
    });

    if (keys.length > 0) {
        for (const key of keys) {
            const sessionInfo = await redis.get<SessionInfo>(key);
            if (!sessionInfo) continue;

            if (sessionInfo.userAgent === userAgent) {
                return res.status(403).json({
                    message: 'Already logged in with same user-agent',
                });
            }

            sessionKeys.push({ key, createdAt: sessionInfo.createdAt });
        }
    }

    if (sessionKeys.length >= 3) {
        const sortedSessionKeys = sessionKeys.sort(
            (a, b) => a.createdAt - b.createdAt
        );

        await redis.del(sortedSessionKeys[0].key);
    }

    const accessToken = generateAccessToken(user.id, user.role);

    const sessionId = generateSessionId();
    const refreshToken = generateRefreshToken(sessionId, user.id, user.role);

    await redis.set(
        `${SESSION_PREFIX}-${user.id}:${sessionId}`,
        {
            accessToken,
            userAgent,
            createdAt: Date.now(),
        },
        {
            ex: REFRESH_TOKEN_EXPIRY,
        }
    );

    generateCookie(
        '__refresh_token__',
        refreshToken,
        {
            httpOnly: true,
            maxAge: REFRESH_TOKEN_EXPIRY * 1000,
        },
        res
    );

    const { password: _, ...userInfo } = user;

    res.status(200).json({
        user: userInfo,
        accessToken,
        message: 'Logged in successfully',
    });
};

export const googleOAuth = async (req: Request, res: Response) => {
    const userAgent = req.headers['user-agent'];
    if (!userAgent) {
        return res.status(400).json({ message: 'Missing User-Agent header' });
    }

    const googleOAuth2Code = req.query.code;
    if (!googleOAuth2Code) {
        return res.status(400).json({ message: 'Missing google OAuth2 Code' });
    }

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            redirect_uri: GOOGLE_REDIRECT_URI,
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            code: googleOAuth2Code,
            grant_type: 'authorization_code',
        }),
    });

    const { access_token } = await tokenResponse.json();

    const userInfoResponse = await fetch(
        'https://www.googleapis.com/oauth2/v2/userinfo',
        {
            method: 'GET',
            headers: { Authorization: `Bearer ${access_token}` },
        }
    );

    const { name, picture, email } = await userInfoResponse.json();

    let user = await prisma.user.findUnique({
        where: { email },
        omit: { password: true },
    });

    if (!user) {
        user = await prisma.user.create({
            data: {
                isAuthByGoogle: true,
                fullName: name,
                email,
                profileImage: picture,
            },
        });
    }

    const sessionKeys = [];

    const match = `${SESSION_PREFIX}-${user.id}:*`;
    const [_cursor, keys] = await redis.scan(0, { match });
    if (keys.length > 0) {
        for (const key of keys) {
            const sessionInfo = await redis.get<SessionInfo>(key);
            if (!sessionInfo) continue;

            if (sessionInfo.userAgent === userAgent) {
                return res.status(403).json({
                    message: 'Already logged in with same user-agent',
                });
            }

            sessionKeys.push({ key, createdAt: sessionInfo.createdAt });
        }
    }

    if (sessionKeys.length >= 3) {
        const sortedSessionKeys = sessionKeys.sort(
            (a, b) => a.createdAt - b.createdAt
        );
        await redis.del(sortedSessionKeys[0].key);
    }

    const accessToken = generateAccessToken(user.id, user.role);

    const sessionId = generateSessionId();
    const refreshToken = generateRefreshToken(sessionId, user.id, user.role);

    generateCookie(
        '__oauth2_payload__',
        JSON.stringify({ user, accessToken }),
        {
            httpOnly: true,
            maxAge: REFRESH_TOKEN_EXPIRY * 1000,
        },
        res
    );

    await redis.set(
        `${SESSION_PREFIX}-${user.id}:${sessionId}`,
        {
            accessToken,
            userAgent,
            createdAt: Date.now(),
        },
        {
            ex: REFRESH_TOKEN_EXPIRY,
        }
    );

    generateCookie(
        '__refresh_token__',
        refreshToken,
        {
            httpOnly: true,
            maxAge: REFRESH_TOKEN_EXPIRY * 1000,
        },
        res
    );

    res.redirect(`${env.FRONTEND_URL}/auth/oauth2`);
};

export const refreshToken = async (req: Request, res: Response) => {
    const refreshToken = req.cookies['__refresh_token__'];
    if (!refreshToken) {
        return res.status(401).json({ message: 'Missing refresh token' });
    }

    let decodedRefreshToken;
    try {
        decodedRefreshToken = verifyRefreshToken(refreshToken);
    } catch (error) {
        if (checkJwtError(error)) {
            return res
                .status(401)
                .json({ message: 'Invalid or expired token' });
        }
    }

    const { sid, uid, role, exp } = decodedRefreshToken as jwt.JwtPayload;
    const user = (await cacheUserInfo(uid, role)) as UserInfo;
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const existingSessionKey = `${SESSION_PREFIX}-${user.id}:${sid}`;
    const sessionInfo = await redis.get<SessionInfo>(existingSessionKey);
    if (!sessionInfo) {
        return res.status(404).json({ message: 'Session not found' });
    }

    let { accessToken } = sessionInfo;

    let decodedAccessToken;
    try {
        decodedAccessToken = verifyAccessToken(accessToken);
    } catch (error) {
        if (!(error instanceof jwt.TokenExpiredError)) {
            return res.status(401).json({ message: 'Invalid access token' });
        }
    }

    let existingAccessTtl = 0;

    if (decodedAccessToken) {
        const { exp } = decodedAccessToken as jwt.JwtPayload;
        existingAccessTtl = exp ? Math.floor(exp - Date.now() / 1000) : 0;
    }

    if (existingAccessTtl > ACCESS_TOKEN_EXPIRY / 3) {
        return res.status(200).json({
            user,
            accessToken,
            message: 'Old access token is still valid',
        });
    }

    accessToken = generateAccessToken(user.id, user.role);

    await redis.set(
        existingSessionKey,
        { ...sessionInfo, accessToken },
        { ex: Math.floor(exp ? exp - Date.now() / 1000 : 0) }
    );

    res.status(200).json({
        user,
        accessToken,
        message: 'Access token refreshed',
    });
};

export const logout = async (req: Request, res: Response) => {
    const refreshToken = req.cookies['__refresh_token__'];

    const { decoded, sessionInfo } = (req as AuthenticatedRequest).data;
    const { sid, uid } = decoded;
    const existingSessionKey = `${SESSION_PREFIX}-${uid}:${sid}`;

    const { accessToken } = sessionInfo;

    const sessionTtl = await redis.ttl(existingSessionKey);

    await Promise.all([
        redis.set(`blacklist:${accessToken}`, 'revoked', {
            ex: ACCESS_TOKEN_EXPIRY,
        }),

        redis.set(`blacklist:${refreshToken}`, 'revoked', { ex: sessionTtl }),
        redis.del(existingSessionKey),
        redis.del(`${USER_CACHE_PREFIX}:${uid}`),
    ]);

    generateCookie(
        '__refresh_token__',
        '',
        {
            httpOnly: true,
            maxAge: 0,
        },
        res
    );

    res.status(200).json({ message: 'Logged out successfully' });
};
