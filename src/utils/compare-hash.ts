import bcrypt from 'bcryptjs';

export const compareHash = async (
    value: string,
    hashedValue: string
): Promise<boolean> => {
    return await bcrypt.compare(value, hashedValue);
};
