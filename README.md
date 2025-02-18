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

## Example

For a complete implementation example, see the [demo repository](https://github.com/Nexirift/plugin-better-auth-example).

## Credits

- [GraphQL Yoga](https://github.com/dotansimha/graphql-yoga)
- [plugin-oidc](https://github.com/Nexirift/plugin-oidc)
