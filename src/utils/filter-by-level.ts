import winston from 'winston';

export const filterByLevel = (level: string) => {
    return winston.format((info) => {
        return info.level === level ? info : false;
    })();
};
