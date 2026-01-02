# Branch Protection & Repository Security Setup

This document provides step-by-step instructions for configuring enterprise-grade repository security settings.

## 1. Branch Protection Rules

### Setup Instructions

1. Go to your repository: `https://github.com/28sunanda/secure-sdlc-automation`
2. Click **Settings** → **Branches**
3. Under "Branch protection rules", click **Add rule**

### Main Branch Protection

Configure these settings for the `main` branch:

**Branch name pattern:** `main`

**Protect matching branches:**

| Setting | Value | Why |
|---------|-------|-----|
| ☑️ Require a pull request before merging | Enabled | No direct pushes to main |
| ☑️ Require approvals | 1 (or more in enterprise) | Peer review requirement |
| ☑️ Dismiss stale pull request approvals when new commits are pushed | Enabled | Re-review after changes |
| ☑️ Require review from Code Owners | Enabled | Security team must approve |
| ☑️ Require status checks to pass before merging | Enabled | Security gate enforcement |
| ☑️ Require branches to be up to date before merging | Enabled | Prevent merge conflicts |
| ☑️ Require conversation resolution before merging | Enabled | Address all feedback |
| ☑️ Do not allow bypassing the above settings | Enabled | Even admins follow rules |

**Required status checks:**
- `🚦 Security Gate`
- `🔑 Secret Detection`
- `🔍 SAST - Semgrep`
- `📦 SCA - Dependency Scanning`

### Develop Branch Protection (Optional)

Similar settings but with fewer restrictions for development workflow.

---

## 2. Repository Security Settings

### Enable Security Features

1. Go to **Settings** → **Code security and analysis**
2. Enable these features:

| Feature | Status | Purpose |
|---------|--------|---------|
| Dependency graph | ✅ Enable | Visualize dependencies |
| Dependabot alerts | ✅ Enable | Vulnerability notifications |
| Dependabot security updates | ✅ Enable | Auto-fix vulnerabilities |
| Code scanning | ✅ Enable | SARIF upload support |
| Secret scanning | ✅ Enable | Detect leaked secrets |
| Secret scanning push protection | ✅ Enable | Block secret commits |

---

## 3. Required Secrets

Add these secrets in **Settings** → **Secrets and variables** → **Actions**:

| Secret Name | Required | How to Get |
|-------------|----------|------------|
| `SLACK_SECURITY_WEBHOOK` | Optional | [Slack API](https://api.slack.com/apps) → Incoming Webhooks |
| `SNYK_TOKEN` | Optional | [Snyk](https://snyk.io) → Account Settings → API Token |

---

## 4. Repository Variables

Add these variables in **Settings** → **Secrets and variables** → **Actions** → **Variables**:

| Variable Name | Value | Purpose |
|---------------|-------|---------|
| `ENABLE_SLACK_NOTIFICATIONS` | `true` or `false` | Toggle Slack alerts |

---

## 5. Verification Checklist

After setup, verify:

- [ ] Cannot push directly to `main` branch
- [ ] PRs require status checks to pass
- [ ] Security tab shows alerts (if any)
- [ ] Dependabot creates PRs for updates
- [ ] CODEOWNERS file triggers review requests
- [ ] Slack notifications work (if configured)

---

## 6. Testing Branch Protection

Create a test PR to verify everything works:

```bash
git checkout -b test/branch-protection
echo "# Test" >> TEST.md
git add TEST.md
git commit -m "test: Verify branch protection"
git push origin test/branch-protection
```

Then:
1. Create PR on GitHub
2. Verify security pipeline runs
3. Verify CODEOWNERS review is requested
4. Verify you cannot merge until checks pass
5. Delete the test branch after verification

---

## Enterprise Considerations

In a real enterprise environment, you would also:

1. **Require signed commits** - Verify commit authenticity
2. **Enable audit log streaming** - SIEM integration
3. **Configure SAML SSO** - Enterprise identity
4. **Set up IP allow lists** - Network restrictions
5. **Enable deploy keys** - Secure CI/CD access
6. **Configure environments** - Staging/Production gates
