import { app } from './app';
import { env } from './configs/env.config';
import { prisma } from './lib/prisma';
import { appLogger } from './lib/winston';

app.listen(env.PORT, async () => {
    try {
        await prisma.$connect();
        appLogger.info('Prisma connected to database');
        appLogger.info(`Server is running on port: ${env.PORT}`);
    } catch (error) {
        await prisma.$disconnect();
        appLogger.error('Error starting server: ' + error);
        process.exit(1);
    }
});
