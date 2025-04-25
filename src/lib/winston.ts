import winston from 'winston';

const { createLogger, format, transports } = winston;
const { combine, colorize, timestamp, printf } = format;

export const logger = createLogger({
    level: 'info',
    format: combine(
        colorize(),
        timestamp(),
        printf(
            ({ timestamp, level, message }) =>
                `${timestamp} ${level}: ${message}`
        )
    ),
    transports: [
        new transports.Console(),
        new transports.File({ filename: 'logs/app.log' }),
    ],
    exitOnError: true,
});
