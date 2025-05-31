import { Logtail } from "@logtail/edge";
import type { EdgeWithExecutionContext } from "@logtail/edge/dist/es6/edgeWithExecutionContext.js";
import {
	type APIWebhookEvent,
	type APIWebhookEventBase,
	type APIWebhookEventBody,
	ApplicationIntegrationType,
	ApplicationWebhookEventType,
	ApplicationWebhookType,
} from "discord-api-types/v10";
import { hexToUint8Array } from "./utility/functions.js";

interface Env {
	PUBLIC_KEY: string;
	BETTER_STACK_TOKEN: string;
}

function logWebhookEvent(
	{ event }: APIWebhookEventBase<ApplicationWebhookType.Event, APIWebhookEventBody>,
	logger: EdgeWithExecutionContext,
) {
	const { data, timestamp, type } = event;

	switch (type) {
		case ApplicationWebhookEventType.ApplicationAuthorized: {
			if (data.integration_type === ApplicationIntegrationType.GuildInstall) {
				logger.info("Guild joined.", { event, timestamp });
			}

			if (data.integration_type === ApplicationIntegrationType.UserInstall) {
				logger.info("User installed application.", { event, timestamp });
			}

			return;
		}
		case ApplicationWebhookEventType.ApplicationDeauthorized: {
			logger.info("User deauthorised application.", { event, timestamp });
			return;
		}
		case ApplicationWebhookEventType.EntitlementCreate: {
			logger.info("Entitlement created.", { event, timestamp });
			return;
		}
		case ApplicationWebhookEventType.QuestUserEnrollment: {
			logger.info("Quest user enrollment.", { event, timestamp });
			return;
		}
		default: {
			logger.warn("Received unexpected application webhook event type.", { event, timestamp });
		}
	}
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

		if (json.type !== ApplicationWebhookType.Event) {
			logger.error("Unexpected application webhook type.", json);
			return new Response("Unexpected application webhook type.", { status: 403 });
		}

		logWebhookEvent(json, logger);
		return new Response(null, { status: 204 });
	},
} satisfies ExportedHandler<Env>;
