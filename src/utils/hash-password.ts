import bcrypt from 'bcryptjs';

export const hashPassword = async (value: string): Promise<string> => {
    return await bcrypt.hash(value, 10);
};
