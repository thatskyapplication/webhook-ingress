import { logger, withSentry } from "@sentry/cloudflare";
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
	SENTRY_DATA_SOURCE_NAME: string;
	CF_VERSION_METADATA: WorkerVersionMetadata;
}

function logWebhookEvent({
	event,
}: APIWebhookEventBase<ApplicationWebhookType.Event, APIWebhookEventBody>) {
	const { data, type } = event;

	switch (type) {
		case ApplicationWebhookEventType.ApplicationAuthorized: {
			if (data.integration_type === ApplicationIntegrationType.GuildInstall) {
				logger.info("Guild joined.", { event });
			}

			if (data.integration_type === ApplicationIntegrationType.UserInstall) {
				logger.info("User installed application.", { event });
			}

			return;
		}
		case ApplicationWebhookEventType.ApplicationDeauthorized: {
			logger.info("User deauthorised application.", { event });
			return;
		}
		case ApplicationWebhookEventType.EntitlementCreate: {
			logger.info("Entitlement created.", { event });
			return;
		}
		case ApplicationWebhookEventType.EntitlementDelete: {
			logger.info("Entitlement deleted.", { event });
			return;
		}
		case ApplicationWebhookEventType.EntitlementUpdate: {
			logger.info("Entitlement updated.", { event });
			return;
		}
		case ApplicationWebhookEventType.QuestUserEnrollment: {
			logger.info("Quest user enrollment.", { event });
			return;
		}
		default: {
			logger.warn("Received unexpected application webhook event type.", { event });
		}
	}
}

export default withSentry(
	(env) => ({
		dsn: env.SENTRY_DATA_SOURCE_NAME,
		enableLogs: true,
		release: env.CF_VERSION_METADATA.id,
		sendDefaultPii: true,
	}),
	{
		async fetch(request, env) {
			if (request.method !== "POST") {
				return new Response(null, { status: 405 });
			}

			const signature = request.headers.get("X-Signature-Ed25519");
			const timestamp = request.headers.get("X-Signature-Timestamp");
			const body = await request.text();

			if (!(signature && timestamp && body)) {
				return new Response(null, { status: 401 });
			}

			const encoder = new TextEncoder();
			const message = encoder.encode(timestamp + body);
			const signatureUint8 = hexToUint8Array(signature);
			const publicKeyUint8 = hexToUint8Array(env.PUBLIC_KEY);

			const key = await crypto.subtle.importKey("raw", publicKeyUint8, { name: "Ed25519" }, false, [
				"verify",
			]);

			const verified = await crypto.subtle.verify("Ed25519", key, signatureUint8, message);

			if (!verified) {
				return new Response(null, { status: 401 });
			}

			const json = JSON.parse(body) as APIWebhookEvent;

			if (json.type === ApplicationWebhookType.Ping) {
				logger.info("Ping.", { json });
				return new Response(null, { status: 204 });
			}

			logWebhookEvent(json);
			return new Response(null, { status: 204 });
		},
	} satisfies ExportedHandler<Env>,
);
