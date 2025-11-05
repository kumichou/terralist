# GitLab OAuth Configuration

Terralist supports GitLab OAuth for user authentication and authorization. This guide covers configuring GitLab OAuth with Terralist, including basic setup, group restrictions, and GitLab self-hosted support.

## Overview

GitLab OAuth integration allows users to authenticate with Terralist using their GitLab accounts. The integration supports:

- **Basic Authentication**: Allow any GitLab user to authenticate
- **Group Membership**: Restrict access to members of specific GitLab groups
- **GitLab Self-Hosted**: Support for self-hosted GitLab instances
- **RBAC Integration**: Automatic group membership extraction for role-based access control
- **OpenID Connect**: Uses GitLab's OpenID Connect provider for authentication

### Authentication Flow

1. User clicks "Login with GitLab" on Terralist
2. User is redirected to GitLab for authorization
3. User grants permission to Terralist
4. GitLab redirects back to Terralist with authorization code
5. Terralist exchanges code for access token
6. Terralist fetches user profile and validates group membership
7. User is authenticated and assigned appropriate roles

## Basic Configuration

### GitLab OAuth App Setup

Before configuring Terralist, you need to create a GitLab OAuth Application:

1. **Go to GitLab Settings**:
   - GitLab.com: [User Settings → Applications](https://gitlab.com/-/profile/applications)
   - Self-hosted: `https://your-gitlab-instance.com/-/profile/applications`

2. **Create New Application**:
   - **Name**: Terralist (or your preferred name)
   - **Redirect URI**: `https://your-terralist-instance.com/v1/api/auth/redirect`
   - **Scopes**: Check `openid`, `email`
   - **Confidential**: Yes (keep checked)

3. **Get Credentials**:
   - Copy the **Application ID** (this is your Client ID)
   - Copy the **Secret** (this is your Client Secret)

### Terralist Configuration

#### Basic Setup (Any GitLab User)

```bash
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-application-id" \
  --gl-client-secret "your-gitlab-secret"
```

#### Environment Variables

```bash
export TERRALIST_OAUTH_PROVIDER="gitlab"
export TERRALIST_GL_CLIENT_ID="your-gitlab-application-id"
export TERRALIST_GL_CLIENT_SECRET="your-gitlab-secret"
```

#### YAML Configuration

```yaml
oauth-provider: gitlab
gl-client-id: "your-gitlab-application-id"
gl-client-secret: "your-gitlab-secret"
token-signing-secret: "your-signing-secret"
```

## Group-Based Access Control

Restrict Terralist access to members of specific GitLab groups.

### Single Group

```bash
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-application-id" \
  --gl-client-secret "your-gitlab-secret" \
  --gl-groups "my-group"
```

This configuration:
- Only allows users who are members of the `my-group` group
- Validates group membership using GitLab's OpenID Connect userinfo endpoint
- Extracts all user groups for RBAC integration

### Multiple Groups

```bash
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-application-id" \
  --gl-client-secret "your-gitlab-secret" \
  --gl-groups "developers,platform-team,security-team"
```

This allows access for users in any of the specified groups. Users only need to be a member of one of the listed groups.

!!! note "Group Names"
    GitLab group names are case-sensitive and should match exactly. For example:
    - `MyGroup` ≠ `mygroup`
    - Use the full group path for subgroups: `parent-group/child-group`

## GitLab Self-Hosted Support

For self-hosted GitLab instances:

```bash
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-application-id" \
  --gl-client-secret "your-gitlab-secret" \
  --gl-host "gitlab.yourcompany.com"
```

### Self-Hosted OAuth App Setup

For self-hosted GitLab:

1. **Access GitLab**: Go to `https://your-gitlab-instance.com/-/profile/applications`
2. **Create Application**:
   - **Name**: Terralist
   - **Redirect URI**: `https://your-terralist-instance.com/v1/api/auth/redirect`
   - **Scopes**: `openid`, `email`
3. **Configure Terralist**: Use `--gl-host` with your GitLab hostname

!!! note "Host Format"
    The `--gl-host` parameter accepts hostname with optional port:
    - `gitlab.company.com`
    - `gitlab.company.com:8443`

## RBAC Integration

GitLab OAuth automatically integrates with Terralist's RBAC system by extracting group memberships.

### Automatic Group Extraction

When `gl-groups` is configured, Terralist automatically:
- Validates user is a member of at least one required group
- Fetches all user's group memberships
- Provides group names as groups for RBAC policies

### RBAC Policy Examples

#### Group-Level Access

```bash
# Allow all members of specific groups
g, developers, role:contributor
g, platform-team, role:contributor
g, security-team, role:admin

# Read-only access for other groups
g, external-users, role:readonly
```

#### Multi-Group Policies

```bash
# Different permissions based on group membership
p, role:admin, *, *, *, allow

p, role:contributor, modules, create, developers/*, allow
p, role:contributor, modules, update, developers/*, allow
p, role:contributor, providers, create, platform-team/*, allow

p, role:tester, modules, get, qa-team/*, allow
p, role:tester, providers, get, qa-team/*, allow
p, role:tester, modules, update, qa-team/test-modules/*, allow
```

#### Cross-Group Permissions

```bash
# Platform team can manage infrastructure modules
p, role:contributor, modules, create, platform-team/infrastructure/*, allow
p, role:contributor, modules, update, platform-team/infrastructure/*, allow

# Security team can review all modules
p, role:security, modules, get, *, allow
p, role:security, modules, update, security-reviewed/*, allow

# Developers have limited access
p, role:developer, modules, create, developers/my-project/*, allow
p, role:developer, modules, get, *, allow
```

## Advanced Configuration

### Self-Hosted with Groups

```bash
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "self-hosted-app-id" \
  --gl-client-secret "self-hosted-secret" \
  --gl-host "gitlab.company.com:8443" \
  --gl-groups "engineering,platform,security"
```

### Environment-Based Configuration

```bash
export TERRALIST_OAUTH_PROVIDER=gitlab
export TERRALIST_GL_CLIENT_ID="your-gitlab-application-id"
export TERRALIST_GL_CLIENT_SECRET="your-gitlab-secret"
export TERRALIST_GL_HOST="gitlab.company.com"
export TERRALIST_GL_GROUPS="developers,platform"
```

### OAuth Scopes

Terralist requests the following GitLab OAuth scopes:

- `openid` - OpenID Connect authentication
- `email` - Access to user email addresses

!!! note "Scope Requirements"
    The `openid` and `email` scopes are required for GitLab OAuth integration. These enable access to the OpenID Connect userinfo endpoint which provides user profile information and group memberships.

## Troubleshooting

### Common Issues

1. **"Application must be configured for OpenID Connect"**
   - **Cause**: OAuth app doesn't have required scopes
   - **Solution**: Ensure `openid` and `email` scopes are checked when creating the GitLab application

2. **"User is not a member of the required groups"**
   - **Cause**: User is not a member of any specified groups
   - **Solution**: Check group membership or adjust `gl-groups` configuration

3. **"Invalid redirect URI"**
   - **Cause**: Redirect URI in GitLab app doesn't match Terralist callback URL
   - **Solution**: Ensure redirect URI is: `https://your-terralist-instance.com/v1/api/auth/redirect`

4. **"Unable to connect to GitLab host"**
   - **Cause**: Self-hosted GitLab is not accessible or hostname is incorrect
   - **Solution**: Verify GitLab instance is accessible and hostname is correct in `gl-host`

5. **"User data has no groups"**
   - **Cause**: GitLab user has no group memberships or API issue
   - **Solution**: Check GitLab user permissions and group memberships

### Debugging

Enable debug logging to troubleshoot authentication issues:

```bash
terralist server --log-level debug
```

Check logs for:
- OAuth callback processing
- GitLab API responses
- Group membership validation
- RBAC policy evaluation

### Testing Configuration

1. **Test Basic Authentication**:
   ```bash
   # Remove group restrictions first
   terralist server --oauth-provider gitlab --gl-client-id "..." --gl-client-secret "..."
   ```

2. **Test Group Access**:
   ```bash
   terralist server --gl-groups "your-group"
   # Try logging in with a group member
   ```

3. **Test Self-Hosted**:
   ```bash
   terralist server --gl-host "your-gitlab.com"
   # Verify the OAuth flow redirects to your instance
   ```

4. **Verify RBAC**:
   - Check that group memberships appear in user groups
   - Test that RBAC policies work as expected

## Security Considerations

- **Always use HTTPS**: GitLab OAuth requires HTTPS for security
- **Regular token rotation**: Rotate OAuth application secrets regularly
- **Principle of least privilege**: Use group restrictions when possible
- **Monitor access**: Review authentication logs regularly
- **RBAC validation**: Test RBAC policies regularly to ensure proper access control

## API Endpoints

GitLab OAuth integration adds the following endpoints:

- `GET /v1/api/auth/gitlab/login` - Initiate GitLab OAuth flow
- `GET /v1/api/auth/redirect` - Handle GitLab OAuth callback

These endpoints are automatically configured when `oauth-provider` is set to `gitlab`.

## Migration from Other Providers

### From No Authentication

```bash
# Before (no auth)
terralist server --port 5758

# After (GitLab auth)
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-app-id" \
  --gl-client-secret "your-secret"
```

### From Other OAuth Providers

```bash
# From GitHub
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-app-id" \
  --gl-client-secret "your-gitlab-secret"

# From BitBucket
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-gitlab-app-id" \
  --gl-client-secret "your-gitlab-secret" \
  --gl-groups "developers"  # If you had BitBucket team restrictions
```

### From SAML

```bash
# SAML configuration
terralist server \
  --oauth-provider saml \
  --saml-idp-metadata-url "https://..."

# GitLab equivalent
terralist server \
  --oauth-provider gitlab \
  --gl-client-id "your-app-id" \
  --gl-client-secret "your-secret" \
  --gl-groups "engineering-team"
```

## Support

For additional help with GitLab OAuth configuration:

- Check the [configuration reference](../configuration.md) for all GitLab options
- Review GitLab's [OAuth documentation](https://docs.gitlab.com/ee/integration/oauth_provider.html)
- Check GitLab's [OpenID Connect documentation](https://docs.gitlab.com/ee/integration/openid_connect_provider.html)
- Test with GitLab's OAuth applications page
- Check Terralist logs for detailed error information
