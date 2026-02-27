import { Router } from "express"
import type { Request, Response } from "express"
import type { LoginBody, RegisterBody } from "../types/auth.types"
import { prisma } from "../db"
import { userRegistrationSchema } from "../schemas/registrationSchema"
import { hashPass } from "../utils/hashPassword"
import bcrypt from "bcrypt"
import { cookieVerification } from "../middleware/isLogined"
import { AuthRequest } from "../types/AuthRequest.types"
import {
	releaseLongLivedToken,
	releaseShortLivedToken,
} from "../utils/realeaseJWT"
import { userLoginSchema } from "../schemas/loginSchema"
import jwt from "jsonwebtoken"
import { decode } from "node:punycode"

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

			const userAgent = req.headers["user-agent"]
			const ip = req.ip
			const newSession = await prisma.session.create({
				data: {
					expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 90),
					createdAt: new Date(),
					userId: newUser.id,
					ip,
					userAgent,
				},
			})

			const longLivedToken = releaseLongLivedToken({
				userId: newUser.id,
				sessionId: newSession.id,
			})

			const shortLivedToken = releaseShortLivedToken({
				userId: newUser.id,
			})

			res.cookie("short_lived_token", shortLivedToken, {
				maxAge: 1800 * 1000,
				httpOnly: true,
			})

			res.cookie("long_lived_token", longLivedToken, {
				maxAge: 60 * 60 * 24 * 90 * 1000,
				httpOnly: true,
				path: "/api/auth/refresh",
			})

			return res.status(201).json({
				ok: true,
				message: "User successfully created",
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

		const isValid = await userLoginSchema.safeParseAsync(req.body)
		if (!isValid.success) {
			return res.status(400).json({
				ok: false,
				error: "Error while validating",
			})
		}
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

		const userAgent = req.headers["user-agent"]
		const ip = req.ip
		const newSession = await prisma.session.create({
			data: {
				expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 90),
				createdAt: new Date(),
				userId: find_existing_user.id,
				ip,
				userAgent,
			},
		})
		const shortLivedToken = releaseShortLivedToken({
			userId: find_existing_user.id,
		})

		const longLivedToken = releaseLongLivedToken({
			userId: find_existing_user.id,
			sessionId: newSession.id,
		})

		res.cookie("short_lived_token", shortLivedToken, {
			maxAge: 1800 * 1000,
			httpOnly: true,
		})

		res.cookie("long_lived_token", longLivedToken, {
			maxAge: 60 * 60 * 24 * 90 * 1000,
			httpOnly: true,
			path: "/api/auth/refresh",
		})
	},
)

router.get(
	"/me",
	cookieVerification,
	async (req: AuthRequest, res: Response) => {
		if (!req.user_id) {
			return res.status(401).json({ ok: false })
		}
		const user = await prisma.user.findUnique({
			where: { id: req.user_id },
		})
		if (!user) {
			return res.status(404).json({ ok: false })
		}
		return res.json({ ok: true })
	},
)

router.post("/refresh", async (req: Request, res: Response) => {
	const token = req.cookies.long_lived_token

	if (!token) {
		return res.status(401).json({ ok: false, message: "No refresh token" })
	}

	try {
		const decoded = jwt.verify(token, process.env.REFRESH_SECRET!) as {
			userId: number
			sessionId: string
		}

		const session = await prisma.session.findUnique({
			where: {
				id: decoded.sessionId,
				expiresAt: { gt: new Date() },
			},
		})

		if (!session || session.userId !== decoded.userId) {
			return res
				.status(401)
				.json({ ok: false, message: "Session invalid or expired" })
		}

		const shortLivedToken = releaseShortLivedToken({
			userId: decoded.userId,
		})

		res.cookie("short_lived_token", shortLivedToken, {
			maxAge: 1800 * 1000,
			httpOnly: true,
		})

		return res.json({ ok: true })
	} catch (e) {
		return res.status(401).json({ ok: false, message: "Invalid token" })
	}
})

router.post("/logout", () => {})

export default router
