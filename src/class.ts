import { User, Session } from 'better-auth';
import { createAuthClient } from 'better-auth/client';

// Type definition for auth client instance
type AuthClient = ReturnType<typeof createAuthClient>;

/**
 * Core authentication class that maintains client, session and user state
 */
export class BetterAuth<U extends User = User> {
	readonly client?: AuthClient;
	readonly session?: Session;
	readonly user: U;

	constructor(params: { client: AuthClient; session: Session; user: U }) {
		this.client = params.client;
		this.session = params.session;
		this.user = params.user;
	}
}
