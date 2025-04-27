import z from 'zod';

export const signupValidator = z.object({
    fullName: z.string().trim().nonempty('Full name is required'),
    role: z.enum(['Job_Seeker', 'Recruiter', 'Recruiter_Head']),
    email: z
        .string()
        .trim()
        .email('Invalid email address')
        .transform((str) => str.toLowerCase()),
    password: z
        .string()
        .trim()
        .min(8, 'Password must contains at least 8 characters')
        .max(20, 'Password cannot exceed 20 characters')
        .regex(/[A-Z]/, 'Password must contain at least 1 uppercase letter')
        .regex(/[0-9]/, 'Password must contain at least 1 number')
        .regex(
            /[^A-Za-z0-9]/,
            'Password must contain at least 1 special character'
        ),
});
