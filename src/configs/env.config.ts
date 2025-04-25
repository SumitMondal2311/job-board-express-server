import z from 'zod';
import { logger } from '../lib/winston';

const schema = z.object({
    NODE_ENV: z.enum(['development', 'test', 'production']),
    DATABASE_URL: z.string().trim().url(),
    PORT: z
        .string()
        .min(4)
        .transform((str) => parseInt(str, 10)),
    FRONTEND_URL: z.string().trim().url(),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
    const path = parsed.error.issues[0].path;
    logger.error(`Invalid or missing ${path} variable`);
    process.exit(1);
}

export const env = parsed.data;
