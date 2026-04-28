# pleme-io/github-app-installation-token

Issue a GitHub App installation access token from App credentials. Auth primitive consumed by any workflow that needs to act as a GitHub App identity (cross-repo dispatch, attestation signing, protected-branch writes).

```yaml
- id: token
  uses: pleme-io/github-app-installation-token@v1
  with:
    app-id: ${{ secrets.MY_APP_ID }}
    installation-id: ${{ secrets.MY_APP_INSTALLATION_ID }}
    private-key: ${{ secrets.MY_APP_PRIVATE_KEY }}
- run: gh api repos/me/repo/dispatches -f event_type=run-thing
  env:
    GITHUB_TOKEN: ${{ steps.token.outputs.token }}
```

The token is masked via `::add-mask::` so it doesn't appear in subsequent step output.

## Inputs

| Name | Required | Description |
|---|---|---|
| `app-id` | yes | App numeric ID |
| `installation-id` | yes | Installation ID |
| `private-key` | yes | Full PEM private key |
| `repositories` | no | Comma-separated `owner/repo` slugs to scope the token |
| `permissions` | no | JSON permissions object |

## Outputs

| Name | Description |
|---|---|
| `token` | Installation access token (masked) |
| `expires-at` | Token expiration timestamp |

## Part of the pleme-io action library

This action is one of 11 in [`pleme-io/pleme-actions`](https://github.com/pleme-io/pleme-actions) — discovery hub, version compat matrix, contributing guide, and reusable SDLC workflows shared across the library.
