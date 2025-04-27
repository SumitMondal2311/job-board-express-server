import { $Enums } from '../../prisma_client';

export interface UserInfo {
    id: string;
    isAuthByGoogle: boolean;
    fullName: string;
    role: $Enums.Role;
    email: string;
    profileImage: string | null;
    bio: string | null;
    createdAt: Date;
}
