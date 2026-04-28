{
  description = "pleme-io/github-app-installation-token — issue an installation access token from GitHub App credentials";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crate2nix = { url = "github:nix-community/crate2nix"; inputs.nixpkgs.follows = "nixpkgs"; };
    flake-utils.url = "github:numtide/flake-utils";
    substrate = { url = "github:pleme-io/substrate"; inputs.nixpkgs.follows = "nixpkgs"; };
  };

  outputs = inputs @ { self, nixpkgs, crate2nix, flake-utils, substrate, ... }:
    (import "${substrate}/lib/rust-action-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils;
    }) {
      toolName = "github-app-installation-token";
      src = self;
      repo = "pleme-io/github-app-installation-token";
      action = {
        description = "Issue a GitHub App installation access token from App credentials. Auth primitive for cross-repo dispatch, attestation signing, write access to protected branches. Token is masked in the runner log via ::add-mask:: so it never leaks to subsequent step output.";
        inputs = [
          { name = "app-id"; description = "GitHub App numeric ID"; required = true; }
          { name = "installation-id"; description = "Installation ID"; required = true; }
          { name = "private-key"; description = "App private key (full PEM)"; required = true; }
          { name = "repositories"; description = "Optional comma-separated owner/repo slugs to scope the token"; }
          { name = "permissions"; description = "Optional permissions JSON object"; }
        ];
        outputs = [
          { name = "token"; description = "Installation access token (already masked)"; }
          { name = "expires-at"; description = "Token expiration timestamp"; }
        ];
      };
    };
}
