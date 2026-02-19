import { Router } from "express"
import type { Request, Response } from "express"
import type { LoginBody, RegisterBody } from "../types/auth.types"
import { prisma } from "../db"
import { userRegistrationSchema } from "../schemas/registrationSchema"
import { hashPass } from "../utils/hashPassword"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

const router = Router()

router.post(
	"/register",
	async (req: Request<{}, {}, RegisterBody>, res: Response) => {
		try {
			const { username, password, email } = req.body

			const isValid = await userRegistrationSchema.safeParseAsync(
				req.body,
			)
			if (!isValid.success) {
				return res.status(400).json({
					ok: false,
					error: "Error while validating",
				})
			}
			const existingUser = await prisma.user.findFirst({
				where: {
					email: email,
				},
			})
			if (existingUser) {
				return res.status(400).json({
					ok: false,
					error: "User already exists",
				})
			}
			const hashedPass = await hashPass(password)
			const newUser = await prisma.user.create({
				data: {
					username,
					password: hashedPass,
					email,
				},
			})
			const longLivedToken = jwt.sign(
				{ userId: email },
				process.env.REFRESH_SECRET!,
				{ expiresIn: "90d" },
			)

			const shortLivedToken = jwt.sign(
				{ userId: newUser.id },
				process.env.JWT_SECRET!,
				{ expiresIn: "30m" },
			)

			res.cookie("short-lived-token", shortLivedToken, {
				maxAge: 1800 * 1000,
				httpOnly: true,
			})

			res.cookie("long-lived-token", longLivedToken, {
				maxAge: 60 * 60 * 24 * 90 * 1000,
				httpOnly: true,
			})
			prisma.HashedTokens.create({
				data: {
					userId: newUser.id,
					hashedToken: await hashPass(longLivedToken),
				},
			})

			return res.status(400).json({
				ok: true,
				new_user_id: newUser.id,
			})
		} catch (e) {
			console.error("Something went wrong while creating a user.")
		}
	},
)
router.post(
	"/login",
	async (req: Request<{}, {}, LoginBody>, res: Response) => {
		const { email, password } = req.body
		const find_existing_user = await prisma.user.findUnique({
			where: {
				email: email,
			},
		})
		if (!find_existing_user) {
			return res.status(404).json({
				ok: false,
			})
		}
		const isValidPassword = await bcrypt.compare(
			password,
			find_existing_user.password,
		)
		if (!isValidPassword) {
			return res.status(401).json({ ok: false })
		}

		const shortLivedToken = jwt.sign(
			{ userId: find_existing_user.id },
			process.env.JWT_SECRET!,
			{ expiresIn: "30m" },
		)

		const longLivedToken = jwt.sign(
			{ userId: find_existing_user.id },
			process.env.REFRESH_SECRET!,
			{ expiresIn: "90d" },
		)

		res.cookie("short-lived-token", shortLivedToken, {
			maxAge: 1800 * 1000,
			httpOnly: true,
		})

		res.cookie("long-lived-token", longLivedToken, {
			maxAge: 60 * 60 * 24 * 90 * 1000,
			httpOnly: true,
		})
	},
)
router.post("/logout", () => {})

export default router
