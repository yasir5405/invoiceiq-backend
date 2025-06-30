import { z } from "zod";

export const registerSchema = z.object({
  name: z.string({
    description: "Enter your full name.",
    invalid_type_error: "Name should be characters only.",
    required_error: "Please enter your name before continuing.",
  }),
  email: z
    .string({
      description: "Enter your email.",
      invalid_type_error: "Your email should be a valid email.",
      required_error: "Please enter your email before continuing.",
    })
    .email({ message: "Should be a valid email" }),
  password: z
    .string({
      description: "Choose a password.",
      required_error: "Please enter your password before continuing.",
    })
    .min(8, { message: "Password should be at least 8 characters long." })
    .max(100, {
      message: "Password should not be more than 100 characters long.",
    }),
  confirmPassword: z
    .string({
      description: "Confirm your password.",
      required_error: "Please confirm your password before continuing.",
    })
    .min(8, { message: "Password should be at least 8 characters long." })
    .max(100, {
      message: "Password should not be more than 100 characters long.",
    }),
  profileImage: z.string().optional(),
});

export const loginSchema = z.object({
  email: z
    .string({
      required_error: "Email is required to login.",
      description: "Enter your email to login to your invoiceIQ account.",
    })
    .email({ message: "Please enter a valid email." }),
  password: z
    .string({
      required_error: "Password is required to login.",
      description: "Enter your password for your invoiceIQ account.",
    })
    .min(8, { message: "Password should at least be 8 characters long." })
    .max(100, { message: "Password should be less than 100 characters long." }),
});

export const validateRegisterBody = (body) => {
  return registerSchema.safeParse(body);
};

export const validateLoginBody = (body) => {
  return loginSchema.safeParse(body);
};
