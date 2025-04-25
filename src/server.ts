import { app } from './app';
import { env } from './configs/env.config';
import { prisma } from './lib/prisma';
import { logger } from './lib/winston';

app.listen(env.PORT, async () => {
    try {
        await prisma.$connect();
        logger.info('🔗 Prisma connected to database');
        logger.info(`🚀 Server is running on port: ${env.PORT}`);
    } catch (error) {
        await prisma.$disconnect();
        logger.error('Error starting server: ' + error);
        process.exit(1);
    }
});
