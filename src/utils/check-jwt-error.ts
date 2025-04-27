import jwt from 'jsonwebtoken';

export const checkJwtError = (error: unknown): boolean => {
    return (
        error instanceof jwt.JsonWebTokenError ||
        error instanceof jwt.TokenExpiredError
    );
};
