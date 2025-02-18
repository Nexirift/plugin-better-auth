import { createGraphQLError, Plugin } from 'graphql-yoga';
import { BetterAuthClientPlugin, createAuthClient } from 'better-auth/client';
import { adminClient } from 'better-auth/client/plugins';
import { GraphQLError } from 'graphql';
import { BetterAuth } from './class';

export type BetterAuthPluginOptions = BetterAuthPluginOptionsBase;

/**
 * Configuration options for the BetterAuth plugin
 */
export interface BetterAuthPluginOptionsBase {
	/**
	 * Base URL for the authentication service
	 * @default process.env.BETTER_AUTH_URL
	 */
	baseURL?: string;

	/**
	 * Plugins to pass down to the Better Auth client
	 */
	plugins?: BetterAuthClientPlugin[];

	/**
	 * Suppress warning about missing admin client when using roles
	 * @default false
	 */
	suppressRoleWarning?: boolean;

	/**
	 * Field name used to extend GraphQL context with auth data
	 * @default 'auth'
	 */
	extendContextField?: string;

	/**
	 * List of roles allowed to access the API
	 * @default []
	 */
	allowedRoles?: string[];

	/**
	 * Whether authentication is mandatory
	 * @default false
	 */
	requireAuth?: boolean;

	/**
	 * Custom error messages for different auth scenarios
	 */
	messages?: {
		invalidToken: string;
		expiredToken: string;
		invalidPermissions: string;
		authRequired: string;
	};

	/**
	 * Custom token extraction function
	 * @param params Request context parameters
	 * @returns The extracted token or undefined
	 */
	getToken?: (params: {
		request: Request;
		serverContext: object | undefined;
		url: URL;
	}) => Promise<string | undefined> | string | undefined;
}

/**
 * Creates and configures a BetterAuth plugin instance for GraphQL Yoga
 *
 * @param options - Plugin configuration options
 * @returns Configured GraphQL Yoga plugin
 */
export function useBetterAuth(options: BetterAuthPluginOptions): Plugin {
	// Initialize options with defaults
	const {
		baseURL = process.env.BETTER_AUTH_URL,
		plugins,
		suppressRoleWarning = false,
		extendContextField = 'auth',
		allowedRoles = [],
		requireAuth = false,
		messages = {
			invalidToken: 'The provided access token is invalid.',
			expiredToken: 'An invalid or expired access token was provided.',
			invalidPermissions:
				'You do not have the necessary permissions to access this resource.',
			authRequired: 'Authentication is required to access this resource.'
		},
		getToken = defaultGetToken
	} = options;

	// Store auth payloads mapped to their requests for persistence across hooks
	const payloadByRequest = new WeakMap<Request, BetterAuth | string>();

	// Security check: Warn about potential issues when using roles without admin client
	if (
		allowedRoles.length > 0 &&
		!plugins?.find((plugin) => plugin.id === 'better-auth-client') &&
		!suppressRoleWarning
	) {
		console.warn(
			"\x1b[30;43m SECURITY ALERT \x1b[0m \x1b[33mThe 'allowedRoles' feature is enabled in the GraphQL Yoga plugin for Better Auth, but the admin client plugin is missing. This configuration could expose sensitive information. If this setup is intentional (e.g., you've added a custom 'role' field to the schema), you can suppress this warning by setting 'suppressRoleWarning' to true.\x1b[0m"
		);
	}

	return {
		async onRequestParse({ request, serverContext, url }) {
			const token = await getToken({ request, serverContext, url });

			if (token != null) {
				try {
					// Initialize auth client with provided token
					const client = createAuthClient({
						baseURL,
						plugins,
						fetchOptions: {
							auth: {
								type: 'Bearer',
								token: token
							}
						}
					});

					// Fetch and validate current session
					const { data } = await client.getSession();

					if (!data?.session) {
						throw unauthorizedError(messages.invalidToken);
					}

					// Role-based access control check
					if (allowedRoles?.length > 0) {
						type UserWithRole = ReturnType<
							typeof createAuthClient<{
								plugins: [ReturnType<typeof adminClient>];
							}>
						>['$Infer']['Session']['user'];

						const user = data.user as UserWithRole;
						const userRole = user.role || 'user';

						if (!allowedRoles.includes(userRole)) {
							throw unauthorizedError(
								messages.invalidPermissions
							);
						}
					}

					// Store authenticated session for context building
					payloadByRequest.set(
						request,
						new BetterAuth({
							client,
							session: data.session,
							user: data.user
						})
					);
				} catch (ex) {
					if (ex instanceof GraphQLError) {
						throw ex;
					}
					throw unauthorizedError(messages.invalidToken);
				}
			} else if (requireAuth) {
				throw unauthorizedError(messages.authRequired);
			}
		},

		onContextBuilding({ context, extendContext }) {
			if (context.request == null) {
				throw new Error(
					'Request is not available on context! Make sure you use this plugin with GraphQL Yoga.'
				);
			}

			// Extend context with auth data if available
			const payload = payloadByRequest.get(context.request);
			if (payload != null) {
				extendContext({
					[extendContextField]: payload
				});
			}
		}
	};
}

/**
 * Creates a standardized GraphQL unauthorized error with 401 status code
 *
 * @param message - Error message to display
 * @param options - Additional GraphQL error options
 * @returns GraphQL error instance
 */
function unauthorizedError(
	message: string,
	options?: Parameters<typeof createGraphQLError>[1]
) {
	return createGraphQLError(message, {
		extensions: {
			http: {
				status: 401
			}
		},
		...options
	});
}

/**
 * Default token extraction from Authorization header
 * Only supports Bearer token scheme
 *
 * @param request - HTTP request object
 * @returns Extracted token or undefined
 */
const defaultGetToken: NonNullable<BetterAuthPluginOptions['getToken']> = ({
	request
}: any) => {
	const header = request.headers.get('authorization');
	if (!header) return;

	const [type, token] = header.split(' ');
	if (type !== 'Bearer') {
		throw unauthorizedError(`Unsupported token type provided: "${type}"`);
	}

	return token;
};
