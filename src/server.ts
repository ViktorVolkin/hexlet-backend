import express from "express"
import cors from "cors"
import authRouter from "./api/auth"
import { prisma } from "./db"

const PORT = 3000
const app = express()

app.use(express.json())
app.use(cors({ origin: "http://localhost:5173", credentials: true }))

app.use("/api/auth", authRouter)

app.listen(PORT, () => {
	try {
		prisma.$connect()
		console.log("Connected to Database succesfully")
	} catch (e) {
		console.log(`The database didnt start correctly ${e}`)
	}
	console.log(`Server running on http://localhost:${PORT}`)
})
