import type { Context, Next } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv, SessionUser } from "./types";

export interface StoredUser {
	username: string;
	role: "admin" | "user";
	salt: string;
	hash: string;
	createdAt: string;
}

const COOKIE_NAME = "r2_drive_session";
const encoder = new TextEncoder();

function toHex(buf: ArrayBuffer | Uint8Array): string {
	const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

export function normalizeUsername(username: string): string {
	return username.trim().toLowerCase();
}

export async function hashPassword(password: string, saltHex?: string) {
	const saltBytes = saltHex
		? new Uint8Array(
				saltHex.match(/.{1,2}/g)!.map((byte) => Number.parseInt(byte, 16)),
			)
		: crypto.getRandomValues(new Uint8Array(16));

	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		encoder.encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);

	const derived = await crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt: saltBytes,
			iterations: 100_000,
			hash: "SHA-256",
		},
		keyMaterial,
		256,
	);

	return {
		salt: toHex(saltBytes),
		hash: toHex(derived),
	};
}

export async function verifyPassword(
	password: string,
	saltHex: string,
	expectedHashHex: string,
): Promise<boolean> {
	const { hash } = await hashPassword(password, saltHex);
	return timingSafeEqual(hash, expectedHashHex);
}

async function signValue(value: string, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
	return toHex(sig);
}

export async function createSessionToken(
	user: SessionUser,
	secret: string,
	maxAgeSeconds = 60 * 60 * 24 * 7,
): Promise<string> {
	const payload = btoa(
		JSON.stringify({
			u: user.username,
			r: user.role,
			exp: Math.floor(Date.now() / 1000) + maxAgeSeconds,
		}),
	);
	const signature = await signValue(payload, secret);
	return `${payload}.${signature}`;
}

export async function verifySessionToken(
	token: string | undefined,
	secret: string | undefined,
): Promise<SessionUser | null> {
	if (!token || !secret) return null;
	const parts = token.split(".");
	if (parts.length !== 2) return null;
	const [payload, sig] = parts;

	const expectedSig = await signValue(payload, secret);
	if (!timingSafeEqual(sig, expectedSig)) return null;

	try {
		const data = JSON.parse(atob(payload)) as {
			u?: string;
			r?: "admin" | "user";
			exp?: number;
		};
		if (!data.u || !data.r || !data.exp) return null;
		if (data.exp < Math.floor(Date.now() / 1000)) return null;
		return { username: data.u, role: data.r };
	} catch {
		return null;
	}
}

export function getSessionCookie(c: Context) {
	return getCookie(c, COOKIE_NAME);
}

export function setSessionCookie(
	c: Context,
	token: string,
	maxAgeSeconds = 60 * 60 * 24 * 7,
) {
	setCookie(c, COOKIE_NAME, token, {
		httpOnly: true,
		secure: true,
		sameSite: "Lax",
		path: "/",
		maxAge: maxAgeSeconds,
	});
}

export function clearSessionCookie(c: Context) {
	deleteCookie(c, COOKIE_NAME, { path: "/" });
}

export async function sessionMiddleware(c: Context, next: Next) {
	const path = new URL(c.req.url).pathname;

	// Rutas públicas necesarias para iniciar sesión, cerrar sesión, consultar sesión o abrir enlaces compartidos
	if (
		path === "/api/auth/login" ||
		path === "/api/auth/logout" ||
		path === "/api/auth/me" ||
		path.startsWith("/share/")
	) {
		await next();
		return;
	}

	const env = c.env as AppEnv;
	const session = await verifySessionToken(
		getSessionCookie(c),
		env.SESSION_SECRET,
	);

	if (!session) {
		return c.json({ error: "No autenticado" }, 401);
	}

	c.set("sessionUser", session);
	c.set("authentication_type", "session-cookie");
	c.set("authentication_username", session.username);
	await next();
}

export async function getUserFromKv(
	kv: KVNamespace,
	username: string,
): Promise<StoredUser | null> {
	const clean = normalizeUsername(username);
	const raw = await kv.get(`user:${clean}`);
	if (!raw) return null;
	return JSON.parse(raw) as StoredUser;
}

export async function listUsersFromKv(
	kv: KVNamespace,
): Promise<Array<Omit<StoredUser, "salt" | "hash">>> {
	const list = await kv.list({ prefix: "user:" });
	const users: Array<Omit<StoredUser, "salt" | "hash">> = [];

	for (const key of list.keys) {
		const raw = await kv.get(key.name);
		if (!raw) continue;
		const parsed = JSON.parse(raw) as StoredUser;
		users.push({
			username: parsed.username,
			role: parsed.role,
			createdAt: parsed.createdAt,
		});
	}

	return users; 
}
