# Examples

The following provided scenarios provide examples of how to configure Terralist for different use cases. This is not meant to be exhaustive but provide a starting place for you to deploy Terralist in your hosting environment.

## Google OAUTH2 / OIDC

Setting up Terralist for Google OIDC is a multi-step process. The example covers a scenario where you have an existing Google Group defined (eg., `developers@your-company.com`) that you want to use to limit access to Terralist. Out of that group may be a few specific members who are the only ones that will have access to the 'Settings' page in the UI (eg., `team-lead1@your-company.com,team-lead2@your-company.com`) For the example, we will assume that Terralist is deployed to `terralist.your-company.com`

### Configure a new Google OAuth2 Client

1. In your Google Cloud Console go to the APIs & Services > Library page.
2. Search for "Admin SDK API" and select it.
3. Click Enable.
4. In your Google Cloud Console go to the APIs & Services > Credentials page.
5. Create a new OAuth2 Client naming it `Terralist`
6. Add an Authorized Javascript Origin: `https://terralist.your-company.com`
7. Add an Authorized redirect URI: `https://terralist.your-company.com/oauth/callback`
8. Click `Save` and download the resulting JSON file so you have a record of the `client_id` and `client_secret` as you will need to configure Terralist with that information.
9. In your Google Cloud Console go to the APIs & Services > Data Access page.
10. Click Add or remove scopes
11. In the textbox Manually add scopes, paste the following value in: `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
12. Click Update.

### Configure Terralist

Configure Terralist with the following environment variables:

- `TERRALIST_URL=https://terralist.your-company.com`
- `TERRALIST_OAUTH_PROVIDER=oidc`
- `TERRALIST_OI_CLIENT_ID=<your-client-id>`
- `TERRALIST_OI_CLIENT_SECRET=<your-client-secret>`
- `TERRALIST_OI_AUTHORIZE_URL=https://accounts.google.com/o/oauth2/v2/auth`
- `TERRALIST_OI_TOKEN_URL=https://oauth2.googleapis.com/token`
- `TERRALIST_OI_USERINFO_URL=https://openidconnect.googleapis.com/v1/userinfo`
- `TERRALIST_OIDC_CLAIM_NAME=groups`
- `TERRALIST_OIDC_CLAIM_VALUES=developers`
- `TERRALIST_SETTINGS_CLAIM_NAME=email`
- `TERRALIST_SETTINGS_CLAIM_VALUES=team-lead1@your-company.com,team-lead2@your-company.com`

