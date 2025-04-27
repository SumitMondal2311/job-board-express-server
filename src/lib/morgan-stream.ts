import { httpLogger } from './winston';

export const morganStream = {
    write: (message: string) => {
        httpLogger.http({
            message: message.trim(),
        });
    },
};
