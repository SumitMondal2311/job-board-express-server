import { env } from '../configs/env.config';
import { USER_CACHE_PREFIX } from '../configs/redis.config';
import { prisma } from '../lib/prisma';
import { redis } from '../lib/redis-client';

export const cacheUserInfo = async (id: string, role: string) => {
    const cacheTtl =
        env.NODE_ENV === 'production'
            ? {
                  Job_Seeker: 60 * 60,
                  Recruiter_Head: 60 * 15,
                  Recruiter: 60 * 30,
              }[role] || 60 * 30
            : 60 * 5;

    const userCacheKey = `${USER_CACHE_PREFIX}:${id}`;
    let user = await redis.get(userCacheKey);
    if (user) {
        await redis.expire(userCacheKey, cacheTtl);
        return user;
    }

    user = await prisma.user.findUnique({
        where: { id },
        omit: { password: true },
    });

    if (!user) return null;

    await redis.set(userCacheKey, user, { ex: cacheTtl });

    return user;
};
