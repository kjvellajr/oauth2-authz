# oauth2-authz

> A Traefik middleware plugin that inspects OAuth2 Bearer tokens and rejects requests if a required group is not present in the JWT claims.

## 🚨 What This Plugin Does

This plugin performs **authorization**, not authentication.

- ✅ **Authorization**: Inspects the `Authorization: Bearer <token>` header, parses the JWT, and checks for group membership.
- ❌ **Authentication**: It does **not** validate the JWT signature or authenticate the token. This must be handled upstream (e.g., by [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) or an ingress gateway).

## ✨ Features

- 🛡️ Validates group membership from the `Authorization: Bearer <token>` header.
- 🔍 Inspects JWT claims (e.g., `groups`, `realm_access.roles`, etc.).
- ❌ Rejects requests with `403 Forbidden` if the required group is missing.
- ⚙️ Configurable claim name and required group via Traefik middleware configuration.
- 🔐 Assumes the token has already been validated by upstream (e.g., oauth2-proxy).

## 📦 Installation

Add the plugin to your Traefik static configuration (`traefik.yml`):

```yaml
experimental:
  localPlugins:
    oauth2-authz:
      moduleName: "github.com/kjvellajr/oauth2-authz"
```

## ⚙️ Configuration

Define the middleware in your dynamic configuration (file provider or CRDs):

```yaml
http:
  middlewares:
    require-admin-group:
      plugin:
        oauth2-authz:
          groupsClaim: custom_groups
          groups:
            - "admin"
            - "devops"
```
