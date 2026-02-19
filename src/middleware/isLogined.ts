import { Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AuthRequest } from "../types/AuthRequest.types";

export const cookieVerification = (req: AuthRequest, res: Response, next: NextFunction) => {
    const token = req.cookies.short_lived_token;
    const JWT_SECRET = process.env.JWT_SECRET!;

    if (!token) {
        return res.status(401).json({ok:false, message: "Токен отсутствует" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
        req.user_id = decoded.userId;

        next();
    } catch (e) {
        return res.status(403).json({ ok:false,message: "Неверный токен" });
    }
};
