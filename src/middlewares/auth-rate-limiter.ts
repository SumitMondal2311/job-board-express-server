import rateLimit from 'express-rate-limit';

export const authRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: {
        status: 429,
        message: 'Too many requests, please try again later',
    },
});
