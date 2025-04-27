import z from 'zod';
import { appLogger } from '../lib/winston';

const schema = z.object({
    NODE_ENV: z.enum(['development', 'test', 'production']),
    DATABASE_URL: z.string().trim().url(),
    PORT: z
        .string()
        .min(4)
        .transform((str) => parseInt(str, 10)),
    FRONTEND_URL: z.string().trim().url(),
    REFRESH_TOKEN_SECRET: z.string().trim().base64(),
    ACCESS_TOKEN_SECRET: z.string().trim().base64(),
    GOOGLE_CLIENT_ID: z
        .string()
        .trim()
        .nonempty()
        .endsWith('.apps.googleusercontent.com'),
    GOOGLE_CLIENT_SECRET: z.string().trim().nonempty(),
});

const parsed = schema.safeParse(process.env);

if (!parsed.success) {
    appLogger.error(
        `Invalid or missing ${parsed.error.issues[0].path} variable`
    );
    process.exit(1);
}

export const env = parsed.data;
