export interface RegisterBody {
	username: string
	password: string
	email: string
}
export interface LoginBody {
	password: string
	email: string
}
export interface Logout {}
