![NPM Version](https://img.shields.io/npm/v/%40nexirift%2Fplugin-better-auth)
![NPM License](https://img.shields.io/npm/l/%40nexirift%2Fplugin-better-auth)
![NPM Downloads](https://img.shields.io/npm/dt/%40nexirift%2Fplugin-better-auth)

# plugin-better-auth

**Requires the Bearer plugin to be enabled in the authentication server.**

A GraphQL Yoga plugin that provides seamless user authorization using the Better Auth solution.

## How does it work?

This plugin implements the official Better Auth client to handle session and user authentication. It:

1. Extracts the auth token from the request header
2. Creates a new client instance with the token
3. Retrieves session and user data via getSession()
4. Returns an authenticated class instance with the user context

## Features

- Integrated Better Auth client methods
- Role-based access control via allowedRoles configuration
- Optional authentication requirements with requireAuth flag
- Automatic session handling and user context management
- Optional Redis caching support for improved performance

## Redis Configuration

Redis can be optionally used for token caching, which improves performance by reducing the number of API calls to the Better Auth server.

```typescript
import { createClient } from 'redis';
import { useBetterAuth } from '@nexirift/plugin-better-auth';

// With Redis (for improved performance)
const redis = createClient({ url: 'redis://localhost:6379' });
await redis.connect();

const yogaServer = createYoga({
  plugins: [
    useBetterAuth({
      redis,                  // Optional: Redis client for caching
      cachePrefix: 'tokens',  // Optional: Prefix for cache keys (default: 'tokens')
      cacheExpiration: 5,     // Optional: Cache TTL in seconds (default: 5)
      // Other configuration...
    })
  ]
});

// Without Redis (simpler setup)
const yogaServer = createYoga({
  plugins: [
    useBetterAuth({
      // Redis client is not provided, so no caching is used
      // Other configuration...
    })
  ]
});
```

## Example

For a complete implementation example, see the [demo repository](https://github.com/Nexirift/plugin-better-auth-example).

## Credits

- [GraphQL Yoga](https://github.com/dotansimha/graphql-yoga)
- [plugin-oidc](https://github.com/Nexirift/plugin-oidc)
