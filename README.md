# dependabot-bot

A bot for GitHub that automatically merges PRs from dependabot when they meet certain criteria:

- All the checks are passing
- The package is on a safe-list

## Configuration

In your repository, create a file `.github/dependabot-bot.yml` after installing the dependabot-bot application.

The `safe` property should be a list of packages allowed to be merged automatically.

```yaml
safe:
 - package-1
 - package-2 
```