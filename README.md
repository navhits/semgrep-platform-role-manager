# Semgrep Platform Role Manager

Use GitHub and GitHub Actions to manage and track role updates to your users on Semgrep Platform.

## Why?

Having just 2 roles Admin and Member does not make sense. Because,

1. Members cannot view the policy settings or access the playground
2. Admin has just all the permissions on the platform

Beside these limitations, there are many other day to day usage problems. Having everyone as admin would be chaotic.

There is not audit log available. Changes are not tracked. So if anyone just goes around changing the policy board, its bad.

## What this one does?

1. Use GitHub Actions to automatically update roles
2. Time based admin provision. Set a time until someone can be an admin
3. Use Git revisions to know when a role was updated and who updated it.

### Note

1. This definitely is not the best way. But I like writing some automations like this
2. You cannout use `SEMGREP_APP_TOKEN` sadly. You will have to copy the JWT token from any API call from the Semgrep Platform
    * We can think about another automation with Selenium for this. But I'd honestly be happy if Semgrep folks just allow the using the regular token.
    * Beyond happy if you just solve the role and audit log problem
3. Make sure only select folks can run the GitHub workflows or set approvals for these
4. Make sure to protect the branch where the data will be. So only a specific user can make changes to that branch and no one else
5. Create a GitHub PAT with repo write and workflow permissions. Make sure this user is added to the bypass list of the protected branch. Its even better if this token is from a non human account.
