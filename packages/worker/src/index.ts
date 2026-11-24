import { cloudflareAccess } from "@hono/cloudflare-access";
import {
	type OpenAPIObjectConfigV31,
	extendZodWithOpenApi,
	fromHono,
} from "chanfana";
import { type ExecutionContext, Hono } from "hono";
import { basicAuth } from "hono/basic-auth";
import { cors } from "hono/cors";
import { z } from "zod";
import {
	type StoredUser,
	clearSessionCookie,
	createSessionToken,
	getUserFromKv,
	hashPassword,
	listUsersFromKv,
	normalizeUsername,
	sessionMiddleware,
	setSessionCookie,
	verifyPassword,
} from "./auth";
import { readOnlyMiddleware } from "./foundation/middlewares/readonly";
import { settings } from "./foundation/settings";
import { CopyObject } from "./modules/buckets/copyObject";
import { CreateFolder } from "./modules/buckets/createFolder";
import { CreateShareLink } from "./modules/buckets/createShareLink";
import { DeleteObject } from "./modules/buckets/deleteObject";
import { DeleteShareLink } from "./modules/buckets/deleteShareLink";
import { GetObject } from "./modules/buckets/getObject";
import { GetShareLink } from "./modules/buckets/getShareLink";
import { HeadObject } from "./modules/buckets/headObject";
import { ListObjects } from "./modules/buckets/listObjects";
import { ListShares } from "./modules/buckets/listShares";
import { MoveObject } from "./modules/buckets/moveObject";
import { CompleteUpload } from "./modules/buckets/multipart/completeUpload";
import { CreateUpload } from "./modules/buckets/multipart/createUpload";
import { PartUpload } from "./modules/buckets/multipart/partUpload";
import { PutMetadata } from "./modules/buckets/putMetadata";
import { PutObject } from "./modules/buckets/putObject";
import { dashboardIndex, dashboardRedirect } from "./modules/dashboard";
import { receiveEmail } from "./modules/emails/receiveEmail";
import { SendEmail } from "./modules/emails/sendEmail";
import { GetInfo } from "./modules/server/getInfo";
import type {
	AppContext,
	AppEnv,
	AppVariables,
	BasicAuthType,
	R2ExplorerConfig,
} from "./types";

export function R2Explorer(config?: R2ExplorerConfig) {
	extendZodWithOpenApi(z);
	config = config || {};
	if (config.readonly !== false) config.readonly = true;

	const openapiSchema: OpenAPIObjectConfigV31 = {
		openapi: "3.1.0",
		info: {
			title: "R2 Explorer API",
			version: settings.version,
		},
	};

	if (config.basicAuth) {
		openapiSchema["security"] = [
			{
				basicAuth: [],
			},
		];
	}

	const app = new Hono<{ Bindings: AppEnv; Variables: AppVariables }>();
	app.use("*", async (c, next) => {
		c.set("config", config);
		await next();
	});

	const openapi = fromHono(app, {
		schema: openapiSchema,
		raiseUnknownParameters: true,
		generateOperationIds: false,
	});

	if (config.cors === true) {
		app.use("/api/*", cors());
	}

	// Autenticación por cookie de sesión usando USERS_KV + SESSION_SECRET
app.use("/api/*", async (c, next) => {
  if (c.req.path === "/api/auth/setup" || c.req.path === "/api/auth/login") {
    return next();
  }
  return sessionMiddleware(c, next);
});

	// Crear el primer usuario administrador solo cuando USERS_KV está vacío
	app.post("/api/auth/setup", async (c) => {
		const kv = c.env.USERS_KV;
		if (!kv) {
			return c.json({ error: "USERS_KV no configurado" }, 500);
		}

		const existingUsers = await listUsersFromKv(kv);
		if (existingUsers.length > 0) {
			return c.json(
				{ error: "Ya existen usuarios configurados. Setup deshabilitado." },
				403,
			);
		}

		const body = await c.req.json<{ username?: string; password?: string }>();
		const username = normalizeUsername(body.username || "");
		const password = body.password || "";

		if (!username || password.length < 6) {
			return c.json(
				{ error: "Usuario requerido y contraseña de al menos 6 caracteres" },
				400,
			);
		}

		const { salt, hash } = await hashPassword(password);
		const newUser: StoredUser = {
			username,
			role: "admin",
			salt,
			hash,
			createdAt: new Date().toISOString(),
		};

		await kv.put(`user:${username}`, JSON.stringify(newUser));
		return c.json({
			ok: true,
			user: { username: newUser.username, role: newUser.role },
		});
	});

	app.post("/api/auth/login", async (c) => {
		const kv = c.env.USERS_KV;
		const secret = c.env.SESSION_SECRET;
		if (!kv || !secret) {
			return c.json(
				{ error: "Falta configurar USERS_KV o SESSION_SECRET" },
				500,
			);
		}

		const body = await c.req.json<{ username?: string; password?: string }>();
		const username = normalizeUsername(body.username || "");
		const password = body.password || "";

		if (!username || !password) {
			return c.json({ error: "Usuario y contraseña requeridos" }, 400);
		}

		const user = await getUserFromKv(kv, username);
		if (!user) {
			return c.json({ error: "Credenciales inválidas" }, 401);
		}

		const valid = await verifyPassword(password, user.salt, user.hash);
		if (!valid) {
			return c.json({ error: "Credenciales inválidas" }, 401);
		}

		const token = await createSessionToken(
			{ username: user.username, role: user.role },
			secret,
		);
		setSessionCookie(c, token);

		return c.json({
			ok: true,
			user: { username: user.username, role: user.role },
		});
	});

	app.post("/api/auth/logout", (c) => {
		clearSessionCookie(c);
		return c.json({ ok: true });
	});

	app.get("/api/auth/me", async (c) => {
		const session = c.get("sessionUser");
		if (session) {
			return c.json({ authenticated: true, user: session });
		}

		// Permite consultar sesión aunque sessionMiddleware no haya seteado sessionUser
		const { verifySessionToken, getSessionCookie } = await import("./auth");
		const verified = await verifySessionToken(
			getSessionCookie(c),
			c.env.SESSION_SECRET,
		);
		if (!verified) {
			return c.json({ authenticated: false }, 401);
		}
		return c.json({ authenticated: true, user: verified });
	});

	app.get("/api/auth/users", async (c) => {
		const session = c.get("sessionUser");
		if (!session || session.role !== "admin") {
			return c.json({ error: "Acceso denegado: se requiere rol admin" }, 403);
		}
		const kv = c.env.USERS_KV;
		if (!kv) {
			return c.json({ error: "USERS_KV no configurado" }, 500);
		}
		const users = await listUsersFromKv(kv);
		return c.json({ users });
	});

	app.post("/api/auth/users", async (c) => {
		const session = c.get("sessionUser");
		if (!session || session.role !== "admin") {
			return c.json({ error: "Acceso denegado: se requiere rol admin" }, 403);
		}
		const kv = c.env.USERS_KV;
		if (!kv) {
			return c.json({ error: "USERS_KV no configurado" }, 500);
		}

		const body = await c.req.json<{
			username?: string;
			password?: string;
			role?: "admin" | "user";
		}>();
		const username = normalizeUsername(body.username || "");
		const password = body.password || "";
		const role = body.role === "admin" ? "admin" : "user";

		if (!username || password.length < 6) {
			return c.json(
				{ error: "Usuario requerido y contraseña de al menos 6 caracteres" },
				400,
			);
		}

		const existing = await getUserFromKv(kv, username);
		if (existing) {
			return c.json({ error: "El usuario ya existe" }, 409);
		}

		const { salt, hash } = await hashPassword(password);
		const newUser: StoredUser = {
			username,
			role,
			salt,
			hash,
			createdAt: new Date().toISOString(),
		};

		await kv.put(`user:${username}`, JSON.stringify(newUser));
		return c.json(
			{
				ok: true,
				user: {
					username: newUser.username,
					role: newUser.role,
					createdAt: newUser.createdAt,
				},
			},
			201,
		);
	});

	app.delete("/api/auth/users/:username", async (c) => {
		const session = c.get("sessionUser");
		if (!session || session.role !== "admin") {
			return c.json({ error: "Acceso denegado: se requiere rol admin" }, 403);
		}
		const kv = c.env.USERS_KV;
		if (!kv) {
			return c.json({ error: "USERS_KV no configurado" }, 500);
		}

		const targetUsername = normalizeUsername(c.req.param("username") || "");
		if (!targetUsername) {
			return c.json({ error: "Usuario inválido" }, 400);
		}

		const targetUser = await getUserFromKv(kv, targetUsername);
		if (!targetUser) {
			return c.json({ error: "Usuario no encontrado" }, 404);
		}

		if (targetUser.role === "admin") {
			const allUsers = await listUsersFromKv(kv);
			const adminCount = allUsers.filter((u) => u.role === "admin").length;
			if (adminCount <= 1) {
				return c.json(
					{ error: "No se puede eliminar el último usuario administrador" },
					400,
				);
			}
		}

		await kv.delete(`user:${targetUsername}`);
		return c.json({ ok: true, deleted: targetUsername });
	});

	app.post("/api/auth/change-password", async (c) => {
		const session = c.get("sessionUser");
		if (!session) {
			return c.json({ error: "No autenticado" }, 401);
		}
		const kv = c.env.USERS_KV;
		if (!kv) {
			return c.json({ error: "USERS_KV no configurado" }, 500);
		}

		const body = await c.req.json<{
			username?: string;
			currentPassword?: string;
			newPassword?: string;
		}>();

		const targetUsername = normalizeUsername(body.username || session.username);
		const newPassword = body.newPassword || "";

		if (newPassword.length < 6) {
			return c.json(
				{ error: "La nueva contraseña debe tener al menos 6 caracteres" },
				400,
			);
		}

		const isChangingOther = targetUsername !== normalizeUsername(session.username);
		if (isChangingOther && session.role !== "admin") {
			return c.json(
				{ error: "Solo un administrador puede cambiar contraseñas de otros usuarios" },
				403,
			);
		}

		const targetUser = await getUserFromKv(kv, targetUsername);
		if (!targetUser) {
			return c.json({ error: "Usuario no encontrado" }, 404);
		}

		if (!isChangingOther || session.role !== "admin") {
			const currentPassword = body.currentPassword || "";
			const validCurrent = await verifyPassword(
				currentPassword,
				targetUser.salt,
				targetUser.hash,
			);
			if (!validCurrent) {
				return c.json({ error: "La contraseña actual es incorrecta" }, 400);
			}
		}

		const { salt, hash } = await hashPassword(newPassword);
		const updatedUser: StoredUser = {
			...targetUser,
			salt,
			hash,
		};

		await kv.put(`user:${targetUsername}`, JSON.stringify(updatedUser));
		return c.json({ ok: true, username: targetUsername });
	});

	if (config.readonly === true) {
		app.use("/api/*", readOnlyMiddleware);
	}

	if (config.cfAccessTeamName) {
		app.use("/api/*", cloudflareAccess(config.cfAccessTeamName));
		app.use("/api/*", async (c, next) => {
			c.set("authentication_type", "cloudflare-access");
			c.set("authentication_username", c.get("accessPayload").email);
			await next();
		});
	}

	if (config.basicAuth) {
		openapi.registry.registerComponent("securitySchemes", "basicAuth", {
			type: "http",
			scheme: "basic",
		});
		app.use(
			"/api/*",
			basicAuth({
				invalidUserMessage: "Authentication error: Basic Auth required",
				verifyUser: (username, password, c: AppContext) => {
					const users = (
						Array.isArray(c.get("config").basicAuth)
							? c.get("config").basicAuth
							: [c.get("config").basicAuth]
					) as BasicAuthType[];

					for (const user of users) {
						if (user.username === username && user.password === password) {
							c.set("authentication_type", "basic-auth");
							c.set("authentication_username", username);
							return true;
						}
					}

					return false;
				},
			}),
		);
	}

	openapi.get("/api/server/config", GetInfo);

	openapi.get("/api/buckets/:bucket", ListObjects);
	openapi.post("/api/buckets/:bucket/move", MoveObject);
	openapi.post("/api/buckets/:bucket/copy", CopyObject);
	openapi.post("/api/buckets/:bucket/folder", CreateFolder);
	openapi.post("/api/buckets/:bucket/upload", PutObject);
	openapi.post("/api/buckets/:bucket/multipart/create", CreateUpload);
	openapi.post("/api/buckets/:bucket/multipart/upload", PartUpload);
	openapi.post("/api/buckets/:bucket/multipart/complete", CompleteUpload);
	openapi.post("/api/buckets/:bucket/delete", DeleteObject);
	openapi.on("head", "/api/buckets/:bucket/:key", HeadObject);
	openapi.get("/api/buckets/:bucket/:key/head", HeadObject); // There are some issues with calling the head method

	// Share link routes
	openapi.post("/api/buckets/:bucket/:key/share", CreateShareLink);
	openapi.get("/api/buckets/:bucket/shares", ListShares);
	openapi.delete("/api/buckets/:bucket/share/:shareId", DeleteShareLink);

	// These object routes should be defined last
	openapi.get("/api/buckets/:bucket/:key", GetObject);
	openapi.post("/api/buckets/:bucket/:key", PutMetadata);

	openapi.post("/api/emails/send", SendEmail);

	// Public share access (no authentication required)
	openapi.get("/share/:shareId", GetShareLink);

	openapi.get("/", dashboardIndex);
	openapi.get("*", dashboardRedirect);

	app.all("*", () =>
		Response.json({ msg: "404, not found!" }, { status: 404 }),
	);

	return {
		// TODO: improve event type
		async email(
			event: { raw: unknown; rawSize: unknown },
			env: AppEnv,
			context: ExecutionContext,
		) {
			await receiveEmail(event, env, context, config);
		},
		async fetch(request: Request, env: unknown, context: ExecutionContext) {
			return app.fetch(request, env as AppEnv, context);
		},
	};
}
