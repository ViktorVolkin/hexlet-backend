import z from "zod"
export const userRegistrationSchema = z.object({
	name: z.string(),
	password: z.string().min(6),
	email: z.string(),
})
