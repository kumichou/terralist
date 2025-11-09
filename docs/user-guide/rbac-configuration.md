# RBAC Configuration

The RBAC feature enables restrictions of access to Terralist resources. Terralist does not have its own user management system, delegating this job to one (or more) OAuth 2.0 providers. If the provider authenticates the user, Terralist asks the provider for some metadata and takes the user as being authenticated under those claims. Depending on the provider implementation, those claims can differ.

There are two main components where RBAC configuration can be defined:

- The server-side (global) RBAC configuration;
- The API Key RBAC configuration; (Not yet implemented)

## Basic Built-in Roles

Terralist has three pre-defined roles. Not all of them support expansion, but you are free to define new roles as you please (see below).

- `role:anonymous`: has access to no resources (unless specified otherwise in the server-side configuration);
- `role:readonly`<sup>*</sup>: read-only access to all resources;
- `role:admin`<sup>*</sup>: unrestricted access to all resources;

<sup>*</sup> This role cannot be extended.

The `role:anonymous` is a special role that is assigned to unauthenticated users. This role can be customized from the server-side configuration and through those modifications users are able to expose (publicly) resources from the registry. By default, this role has no grant attached.

## Default Policy for Authenticated Users

When a user is authenticated in Terralist, it will be granted the role specified by the `rbac-default-role` configuration option, if there is no other role specified for the given user.

## RBAC Model Structure

The model syntax is based on [Casbin](https://casbin.org/docs/overview) and highly inspired from the [ArgoCD](https://argo-cd.readthedocs.io/en/stable/) implementation. There are two different types of syntax: one of assigning policies, and another one for assigning users to internal roles.

**Group**: Used to assign users or groups to internal roles.

Syntax: `g, <username/useremail/group>, <role>`

- `<username/useremail/group>`: The entity to whom the role will be assigned. Depending on the OAuth provider implementation those values can represent different things; Usually, the `username` refers to the `sub` claim, while the `useremail` and `group` refers to a custom claims, which might not even be supported by the provider you are using. Check the OAuth provider documentation for more details.
- `<role>`: The internal role to which the entity will be assigned.

<!-- TODO: Add proper oauth provider docs -->

Below is a table that defines claims meaning for each OAuth provider.

| Provider\Claim | `username`  | `useremail`    | `group`                                                                                                      |
| -------------- | ----------- | -------------- | ------------------------------------------------------------------------------------------------------------ |
| BitBucket      | Username    | User E-mail    | Not supported.                                                                                               |
| GitHub         | Username    | User E-mail    | GitHub Organization Teams slugs that the user is part of (if `gh-organization` configuration option is set). |
| GitLab         | Username    | User E-mail    | GitLab User Group names.                                                                                     |
| OIDC           | `sub` claim | Not supported. | Not supported.                                                                                               |

**Policy**: Allows to assign permissions to an entity.

Syntax: `p, <role/username/useremail/group>, <resource>, <action>, <object>, <effect>`

- `<role/username/useremail/group>`: The entity to whom the policy will be assigned
- `<resource>`<sup>*</sup>: The type of resource on which the action is performed. Can be one of: `modules`, `providers`, `authorities`, `settings`. Supports glob matching (e.g. )
- `<action>`<sup>*</sup>: The operation that is being performed on the resource. Can be one of: `get`, `create`, `update`, `delete`. Supports glob matching.
- `<object>`<sup>*</sup>: The object identifier representing the resource on which the action is performed. Supports glob matching. Depending on the resource, the object's format will vary. 
- `<effect>`: Whether this policy should grant or restrict the operation on the target object. One of `allow` or `deny`.

<sup>*</sup> This attribute supports glob matching. For example, for resources `*` will match all 3 resources, `mod*` will match only `modules`, while for objects `my-authority/my-module/aws` will match only one module, while `my-authority/*/*` will match all modules within the authority `my-authority`.

Below is a table that defines the correct object syntax for each resource group.

| Resource Group | Object Syntax                                    |
| -------------- | ------------------------------------------------ |
| `authorities`  | `<authority-name>`                               |
| `modules`      | `<authority-name>/<module-name>/<provider-name>` |
| `providers`    | `<authority-name>/<provider-name>`               |
| `settings`     | `*`                                              |

## Settings Access Control

The `settings` resource controls access to the Terralist Settings UI page. This includes viewing user information and managing authorities.

**Example policies:**

```
# Allow admin users to access settings
p, role:admin, settings, get, *, allow

# Allow specific users to access settings
p, alice@example.com, settings, get, *, allow
p, bob, settings, get, *, allow

# Allow a specific group to access settings
g, devops-team, settings-managers
p, settings-managers, settings, get, *, allow
```

**Note:** If no RBAC policies are defined for the `settings` resource, the system falls back to the legacy `TERRALIST_AUTHORIZED_USERS` configuration for backward compatibility.

## Case Sensitivity in RBAC Matching

**Important:** All RBAC string matching is **case-sensitive**. This affects usernames, email addresses, group names, resource names, actions, and object patterns.

### Group Name Casing from OAuth Providers

OAuth providers (including SAML implementations) **preserve the original casing** of group names from the identity provider. Group names are not normalized to lowercase.

**Examples of group name casing:**
- **GitHub**: Team slugs are typically lowercase (e.g., `developers`, `admins`)
- **GitLab**: Group names preserve original casing (e.g., `AdminGroup`, `PowerUsers`)
- **SAML**: Group names maintain whatever casing the SAML assertion provides (e.g., `ADMIN_USERS`, `Domain Admins`, `PowerUsers`)

### Case Sensitivity Implications

When writing RBAC policies, you must match the **exact casing** used by your OAuth provider:

**❌ This will NOT work:**
```
# SAML provides group: "ADMIN_USERS"
# Policy written in lowercase:
p, role:admin_users, settings, get, *, allow
```

**✅ These WILL work:**
```
# Match exact casing from SAML:
p, role:ADMIN_USERS, settings, get, *, allow

# Use glob patterns for case variations:
p, role:ADMIN_*, settings, get, *, allow
p, role:*USERS, settings, get, *, allow
```

### Recommendations

1. **Check your OAuth provider's group naming** by examining JWT tokens or session data
2. **Use exact casing** in RBAC policies to match your provider's output
3. **Consider glob patterns** if group names vary in casing
4. **Document group naming conventions** used by your identity provider

### Complete Example with Case Sensitivity

```
# GitHub teams (typically lowercase)
g, developers, dev-role
p, dev-role, modules, get, my-org/*, allow

# SAML groups (preserve original casing)
g, ADMIN_USERS, admin-role
g, PowerUsers, power-role
p, admin-role, settings, get, *, allow
p, power-role, modules, *, *, allow
```

For more information about your OAuth provider's group naming behavior, consult your identity provider's documentation.

For example, an object c
