import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { SessionInfo } from './session-info.type';
import { UserInfo } from './user-info.type';

export interface AuthenticatedRequest extends Request {
    data: {
        decoded: JwtPayload;
        user: UserInfo;
        sessionInfo: SessionInfo;
    };
}
