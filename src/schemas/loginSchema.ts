import z from "zod"
export const userLoginSchema = z.object({
	email: z.email(),
	password: z.string().min(6),
})
