import express, { type Request, type Response } from "express"
import cors from "cors"
import authRouter from "./api/auth"
// import { pool } from "./db";

const app = express()

app.use(express.json())
app.use(cors({ origin: "http://localhost:5173", credentials: true }))

app.use("/api/auth", authRouter)

app.get("/", (req, res) => {
	res.status(200).json({ status: "ok!!!!!!" })
})

const PORT = 3000

app.listen(PORT, () => {
	console.log(`Server running on http://localhost:${PORT}`)
})
