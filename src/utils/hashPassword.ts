import bcrypt from "bcrypt"

export async function hashPass(pass: string): Promise<string> {
	return await bcrypt.hash(pass, 10)
}

export async function hashSession(session: string): Promise<string> {
	const salt = await bcrypt.genSalt(15)

	return await bcrypt.hash(session, salt)
}
