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

## RBAC Model Structure

The model syntax is based on [Casbin](https://casbin.org/docs/overview) and highly inspired from the [ArgoCD](https://argo-cd.readthedocs.io/en/stable/) implementation. There are two different types of syntax: one of assigning policies, and another one for assigning users to internal roles.

**Group**: Used to assign users or groups to internal roles.

Syntax: `g, <username/useremail/group>, <role>`

- `<username/useremail/group>`: The entity to whom the role will be assigned. Depending on the OAuth provider implementation those values can represent different things; Usually, the `username` refers to the `sub` claim, while the `useremail` and `group` refers to a custom claims, which might not even be supported by the provider you are using. Check the OAuth provider documentation for more details.
- `<role>`: The internal role to which the entity will be assigned.

Below is a table that defines claims meaning for each OAuth provider.

| Provider\Claim | `username`  | `useremail`    | `group`                                                                                                      |
| -------------- | ----------- | -------------- | ------------------------------------------------------------------------------------------------------------ |
| BitBucket      | Username    | User E-mail    | Not supported.                                                                                               |
| GitHub         | Username    | User E-mail    | GitHub Organization Teams slugs that the user is part of (if `gh-organization` configuration option is set). |
| GitLab         | Username    | User E-mail    | GitLab User Group names.                                                                                     |
| OIDC           | `sub` claim | Not supported. | Not supported.                                                                                               |
| SAML           | SAML attribute specified by `saml-name-attribute` (default: `displayName`) | SAML attribute specified by `saml-email-attribute` (default: `email`) | SAML attribute specified by `saml-groups-attribute` (must be configured to enable group-based RBAC). |

**Policy**: Allows to assign permissions to an entity.

Syntax: `p, <role/username/useremail/group>, <resource>, <action>, <object>, <effect>`

- `<role/username/useremail/group>`: The entity to whom the policy will be assigned
- `<resource>`<sup>*</sup>: The type of resource on which the action is performed. Can be one of: `modules`, `providers`, `authorities`. Supports glob matching (e.g. )
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

## Creating Custom Roles

You can create custom roles by defining policies for them. Custom roles allow you to create fine-grained access control tailored to your organization's needs:

```bash
# Define a custom role for developers
p, role:developer, modules, get, *, allow
p, role:developer, modules, create, my-org/*, allow
p, role:developer, providers, get, *, allow

# Define a custom role for testers
p, role:tester, modules, get, *, allow
p, role:tester, providers, get, *, allow
p, role:tester, modules, update, test-org/*, allow
```

## Default Policy for Authenticated Users

When a user is authenticated in Terralist, it will be granted the role specified by the `rbac-default-role` configuration option, if there is no other role specified for the given user.

## Examples

Here are some practical examples of RBAC configurations using different OAuth providers.

### User-Based Access Control (Email Addresses)

Assign specific users admin access using their email addresses:

```bash
# Assign admin role to specific users by email
g, admin@company.com, role:admin
g, devops@company.com, role:admin

# Assign contributor role to developers
g, alice@company.com, role:contributor
g, bob@company.com, role:contributor

# Default role for all other authenticated users
p, role:readonly, *, get, *, allow
```

### Group-Based Access Control

Use groups from your OAuth provider for role assignment:

#### GitHub Teams Example
```bash
# Assign roles based on GitHub team membership
g, my-org/admins, role:admin
g, my-org/devops, role:contributor
g, my-org/developers, role:developer

# Define permissions for each role
p, role:admin, *, *, *, allow
p, role:contributor, modules, create, *, allow
p, role:contributor, modules, update, *, allow
p, role:developer, modules, get, *, allow
p, role:developer, providers, get, *, allow
```

#### GitLab Groups Example
```bash
# Assign roles based on GitLab group membership
g, admin-group, role:admin
g, developers, role:contributor

# Permissions for contributors
p, role:contributor, modules, create, my-org/*, allow
p, role:contributor, providers, create, my-org/*, allow
```

#### SAML Groups Example
```bash
# First configure SAML to use groups attribute
# --saml-groups-attribute memberOf

# Then assign roles based on SAML groups
g, CN=Administrators,DC=company,DC=com, role:admin
g, CN=Developers,DC=company,DC=com, role:contributor
g, CN=Users,DC=company,DC=com, role:readonly
```

### Combined User and Group Policies

Mix individual user assignments with group-based policies:

```bash
# Specific user overrides
g, ceo@company.com, role:admin
g, security@company.com, role:admin

# Group-based assignments
g, engineering-team, role:contributor
g, qa-team, role:tester

# Permissions
p, role:admin, *, *, *, allow
p, role:contributor, modules, *, company-org/*, allow
p, role:tester, modules, get, company-org/*, allow
p, role:tester, providers, get, company-org/*, allow

# Deny specific actions if needed
p, role:contributor, modules, delete, company-org/production/*, deny
```

### Module-Specific Permissions

Control access to specific modules or authorities:

```bash
# Allow all authenticated users to view public modules
# (You would need to create a custom role:authenticated and assign it to all users)
p, role:authenticated, modules, get, public-org/*, allow

# Restrict production modules to admins only
p, role:admin, modules, *, production-org/*, allow

# Allow developers to manage their team's modules
p, role:contributor, modules, *, my-team-org/my-team-*, allow

# Provider management permissions
p, role:admin, providers, *, *, allow
p, role:contributor, providers, create, my-team-org/*, allow
```

### Authority-Level Permissions

Control access at the authority (organization) level:

```bash
# Admin access to entire authority
p, role:admin, *, *, my-company/*, allow

# Read-only access to specific authority
p, role:readonly, *, get, public-org/*, allow

# Contributor access with restrictions
p, role:contributor, modules, create, my-team-org/*, allow
p, role:contributor, modules, update, my-team-org/*, allow
p, role:contributor, providers, create, my-team-org/*, allow
```

### Testing RBAC Policies

To test your RBAC configuration:

1. Create a test user account
2. Assign the user to appropriate groups in your OAuth provider
3. Attempt to access different resources in Terralist
4. Verify that permissions are correctly granted or denied
5. Check Terralist logs for RBAC policy evaluation details
