import { Logtail } from "@logtail/edge";
import {
	type APIWebhookEvent,
	ApplicationIntegrationType,
	ApplicationWebhookEventType,
	ApplicationWebhookType,
} from "discord-api-types/v10";

interface Env {
	PUBLIC_KEY: string;
	BETTER_STACK_TOKEN: string;
}

function hexToUint8Array(hex: string) {
	const uint8 = new Uint8Array(hex.length / 2);

	for (let i = 0; i < hex.length; i += 2) {
		uint8[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16);
	}

	return uint8;
}

export default {
	async fetch(request, env, ctx) {
		if (request.method !== "POST") {
			return new Response("Method not allowed.", { status: 405 });
		}

		const signature = request.headers.get("X-Signature-Ed25519");
		const timestamp = request.headers.get("X-Signature-Timestamp");
		const body = await request.text();

		if (!(signature && timestamp && body)) {
			return new Response("Invalid request.", { status: 401 });
		}

		const encoder = new TextEncoder();
		const message = encoder.encode(timestamp + body);
		const signatureUint8 = hexToUint8Array(signature);
		const publicKeyUint8 = hexToUint8Array(env.PUBLIC_KEY);

		const key = await crypto.subtle.importKey(
			"raw",
			publicKeyUint8,
			{ name: "Ed25519", namedCurve: "Ed25519" },
			true,
			["verify"],
		);

		const verified = await crypto.subtle.verify("Ed25519", key, signatureUint8, message);

		if (!verified) {
			return new Response("Invalid request.", { status: 401 });
		}

		const json = JSON.parse(body) as APIWebhookEvent;
		const logtail = new Logtail(env.BETTER_STACK_TOKEN);
		const logger = logtail.withExecutionContext(ctx);

		if (json.type === ApplicationWebhookType.Ping) {
			logger.info("Ping.", json);
			return new Response(null, { status: 204 });
		}

		if (json.type === ApplicationWebhookType.Event) {
			const { data, timestamp, type } = json.event;

			if (type !== ApplicationWebhookEventType.ApplicationAuthorized) {
				logger.error("Unexpected application webhook event type.", json);
				return new Response("Unexpected application webhook event type.", { status: 403 });
			}

			if (data.integration_type === ApplicationIntegrationType.UserInstall) {
				logger.info("User installed application.", { ...data, timestamp });
			}

			return new Response(null, { status: 204 });
		}

		logger.error("Unexpected application webhook type.", json);
		return new Response("Unexpected application webhook type.", { status: 403 });
	},
} satisfies ExportedHandler<Env>;
