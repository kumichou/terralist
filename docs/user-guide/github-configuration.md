# GitHub OAuth Configuration

Terralist supports GitHub OAuth for user authentication and authorization. This guide covers configuring GitHub OAuth with Terralist, including basic setup, organization/team restrictions, and GitHub Enterprise support.

## Overview

GitHub OAuth integration allows users to authenticate with Terralist using their GitHub accounts. The integration supports:

- **Basic Authentication**: Allow any GitHub user to authenticate
- **Organization Membership**: Restrict access to members of specific GitHub organizations
- **Team-Based Access**: Further restrict access to specific teams within organizations
- **GitHub Enterprise**: Support for GitHub Enterprise Server installations
- **RBAC Integration**: Automatic team membership extraction for role-based access control

### Authentication Flow

1. User clicks "Login with GitHub" on Terralist
2. User is redirected to GitHub for authorization
3. User grants permission to Terralist
4. GitHub redirects back to Terralist with authorization code
5. Terralist exchanges code for access token
6. Terralist fetches user profile and validates organization/team membership
7. User is authenticated and assigned appropriate roles

## Basic Configuration

### GitHub OAuth App Setup

Before configuring Terralist, you need to create a GitHub OAuth App:

1. **Go to GitHub Settings**:
   - Personal account: [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
   - Organization account: [Organization Settings → Developer settings → OAuth Apps](https://github.com/organizations/{org}/settings/applications)

2. **Create New OAuth App**:
   - **Application name**: Terralist (or your preferred name)
   - **Homepage URL**: `https://your-terralist-instance.com`
   - **Authorization callback URL**: `https://your-terralist-instance.com/v1/api/auth/github/callback`
   - **Description**: Terraform Module Registry

3. **Get Credentials**:
   - Copy the **Client ID**
   - Generate and copy the **Client Secret**

### Terralist Configuration

#### Basic Setup (Any GitHub User)

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret"
```

#### Environment Variables

```bash
export TERRALIST_OAUTH_PROVIDER="github"
export TERRALIST_GH_CLIENT_ID="your-github-client-id"
export TERRALIST_GH_CLIENT_SECRET="your-github-client-secret"
```

#### YAML Configuration

```yaml
oauth-provider: github
gh-client-id: "your-github-client-id"
gh-client-secret: "your-github-client-secret"
token-signing-secret: "your-signing-secret"
```

## Organization-Based Access Control

Restrict Terralist access to members of specific GitHub organizations.

### Single Organization

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret" \
  --gh-organization "my-company"
```

This configuration:
- Only allows users who are members of `my-company` organization
- Grants `read:org` scope to validate organization membership
- Extracts team memberships for RBAC integration

### Multiple Organizations

To support multiple organizations, use RBAC policies to control access:

```bash
# Configuration
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret"

# RBAC Policy File
g, my-company/*, role:contributor    # Allow all members of my-company
g, partner-org/*, role:readonly      # Read-only access for partners
```

## Team-Based Access Control

Further restrict access to specific teams within organizations.

### Single Team

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret" \
  --gh-organization "my-company" \
  --gh-teams "devops"
```

This configuration:
- Only allows users who are members of the `devops` team in `my-company`
- Team names must use **team slugs** (lowercase, hyphenated)

### Multiple Teams

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret" \
  --gh-organization "my-company" \
  --gh-teams "devops,platform,security"
```

This allows access for users in any of the specified teams.

!!! warning "Team slugs are required"
    GitHub team names in configuration must use the **slug format** (lowercase with hyphens), not the display name. For example:
    - Display name: "DevOps Team"
    - Slug: `devops-team`

    You can find the team slug in the GitHub team URL or API responses.

## GitHub Enterprise Support

For GitHub Enterprise Server installations:

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-enterprise-client-id" \
  --gh-client-secret "your-github-enterprise-client-secret" \
  --gh-domain "github.enterprise.com" \
  --gh-organization "my-org"
```

### Enterprise OAuth App Setup

For GitHub Enterprise:

1. **Access GitHub Enterprise**: Go to `https://your-github-enterprise.com/settings/developers`
2. **Create OAuth App**:
   - **Application name**: Terralist
   - **Homepage URL**: `https://your-terralist-instance.com`
   - **Authorization callback URL**: `https://your-terralist-instance.com/v1/api/auth/github/callback`
3. **Use Enterprise Domain**: Set `--gh-domain` to your GitHub Enterprise domain

!!! note "HTTPS Requirement"
    GitHub Enterprise OAuth apps require HTTPS for the callback URL, just like GitHub.com.

## RBAC Integration

GitHub OAuth automatically integrates with Terralist's RBAC system by extracting team memberships.

### Automatic Team Extraction

When `gh-organization` is configured, Terralist automatically:
- Validates user is a member of the organization
- Fetches user's team memberships
- Provides team slugs as groups for RBAC policies

### RBAC Policy Examples

#### Organization-Level Access

```bash
# Allow all organization members read access
g, my-org/*, role:readonly

# Grant admin access to specific teams
g, my-org/admins, role:admin
g, my-org/devops, role:admin

# Grant contributor access to development teams
g, my-org/backend, role:contributor
g, my-org/frontend, role:contributor
g, my-org/platform, role:contributor
```

#### Team-Specific Permissions

```bash
# Fine-grained permissions by team
p, role:admin, *, *, *, allow

p, role:contributor, modules, create, my-org/backend/*, allow
p, role:contributor, modules, update, my-org/backend/*, allow
p, role:contributor, providers, create, my-org/backend/*, allow

p, role:tester, modules, get, my-org/*, allow
p, role:tester, providers, get, my-org/*, allow
p, role:tester, modules, update, my-org/qa/*, allow
```

#### Multi-Organization Setup

```bash
# Different permissions for different organizations
g, company-org/*, role:contributor
g, partner-org/*, role:readonly
g, contractor-org/dev-team, role:contributor
g, contractor-org/qa-team, role:tester

# Organization-specific resource access
p, role:contributor, *, *, company-org/*, allow
p, role:readonly, *, get, partner-org/*, allow
p, role:tester, modules, update, contractor-org/qa-projects/*, allow
```

## Advanced Configuration

### Custom Domain with Organization

```bash
terralist server \
  --oauth-provider github \
  --gh-client-id "enterprise-client-id" \
  --gh-client-secret "enterprise-client-secret" \
  --gh-domain "github.company.com" \
  --gh-organization "engineering" \
  --gh-teams "platform,devops,security"
```

### Environment-Based Configuration

```bash
export TERRALIST_OAUTH_PROVIDER=github
export TERRALIST_GH_CLIENT_ID="your-github-client-id"
export TERRALIST_GH_CLIENT_SECRET="your-github-client-secret"
export TERRALIST_GH_ORGANIZATION="my-organization"
export TERRALIST_GH_TEAMS="devops,platform"
```

### OAuth Scopes

Terralist requests the following GitHub OAuth scopes:

- `read:user` - Access to user profile information
- `user:email` - Access to user email addresses
- `read:org` - Access to organization membership (when `gh-organization` is set)

!!! note "Scope Requirements"
    The `read:org` scope is only requested when organization validation is enabled. Team validation requires organization validation to be enabled first.

## Troubleshooting

### Common Issues

1. **"Application must be installed in organization"**
   - **Cause**: Trying to access organization resources without organization approval
   - **Solution**: Organization admin must approve the OAuth app for organization access

2. **"User is not a member of required teams"**
   - **Cause**: User is in organization but not in specified teams
   - **Solution**: Check team membership or adjust `gh-teams` configuration

3. **"Invalid team slug"**
   - **Cause**: Using team display name instead of slug
   - **Solution**: Use team slug (lowercase, hyphenated) from GitHub team URL

4. **"OAuth app not authorized for organization"**
   - **Cause**: Organization hasn't approved the OAuth app
   - **Solution**: Organization admin must go to Organization Settings → Third-party access → OAuth App access and approve the app

5. **"Redirect URI mismatch"**
   - **Cause**: Callback URL in GitHub OAuth app doesn't match Terralist URL
   - **Solution**: Ensure callback URL is: `https://your-terralist-instance.com/v1/api/auth/github/callback`

### Debugging

Enable debug logging to troubleshoot authentication issues:

```bash
terralist server --log-level debug
```

Check logs for:
- OAuth callback processing
- GitHub API responses
- Organization/team membership validation
- RBAC policy evaluation

### Testing Configuration

1. **Test Basic Authentication**:
   ```bash
   # Remove organization/team restrictions first
   terralist server --oauth-provider github --gh-client-id "..." --gh-client-secret "..."
   ```

2. **Test Organization Access**:
   ```bash
   terralist server --gh-organization "your-org"
   # Try logging in with an organization member
   ```

3. **Test Team Access**:
   ```bash
   terralist server --gh-organization "your-org" --gh-teams "your-team"
   # Try logging in with a team member
   ```

4. **Verify RBAC**:
   - Check that team memberships appear in user groups
   - Test that RBAC policies work as expected

## Security Considerations

- **Always use HTTPS**: GitHub OAuth requires HTTPS for security
- **Regular token rotation**: Rotate OAuth client secrets regularly
- **Principle of least privilege**: Use organization/team restrictions when possible
- **Monitor access**: Review authentication logs regularly
- **RBAC validation**: Test RBAC policies regularly to ensure proper access control

## API Endpoints

GitHub OAuth integration adds the following endpoints:

- `GET /v1/api/auth/github/login` - Initiate GitHub OAuth flow
- `GET /v1/api/auth/github/callback` - Handle GitHub OAuth callback

These endpoints are automatically configured when `oauth-provider` is set to `github`.

## Migration from Other Providers

### From No Authentication

```bash
# Before (no auth)
terralist server --port 5758

# After (GitHub auth)
terralist server \
  --oauth-provider github \
  --gh-client-id "your-client-id" \
  --gh-client-secret "your-client-secret"
```

### From Other OAuth Providers

```bash
# From BitBucket
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret"

# From GitLab
terralist server \
  --oauth-provider github \
  --gh-client-id "your-github-client-id" \
  --gh-client-secret "your-github-client-secret" \
  --gh-organization "your-org"  # If you had GitLab group restrictions
```

## Support

For additional help with GitHub OAuth configuration:

- Check the [configuration reference](../configuration.md) for all GitHub options
- Review GitHub's [OAuth documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- Test with GitHub's [OAuth debugger](https://github.com/settings/developers) if needed
- Check Terralist logs for detailed error information
