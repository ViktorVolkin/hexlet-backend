import jwt from "jsonwebtoken"

export const releaseShortLivedToken = (
	toSaveParam: string | object | Buffer<ArrayBufferLike>,
	hashSecret?: string,
) => {
	return jwt.sign(toSaveParam, hashSecret ?? process.env.JWT_SECRET!, {
		expiresIn: "30m",
	})
}

export const releaseLongLivedToken = (
	toSaveParam: string | object | Buffer<ArrayBufferLike>,
) => {
	return jwt.sign(toSaveParam, process.env.REFRESH_TOKEN!, {
		expiresIn: "90d",
	})
}
