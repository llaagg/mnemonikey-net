# NuGet Publishing Guide

This guide explains how to publish the MnemonikeyCs packages to NuGet.org.

## Prerequisites

1. **NuGet API Key**: You need to create an API key on NuGet.org
   - Go to https://www.nuget.org/account/apikeys
   - Click "Create" to generate a new API key
   - Give it a descriptive name (e.g., "GitHub Actions - MnemonikeyCs")
   - Select appropriate permissions (usually "Push" is sufficient)
   - Set the glob pattern to match your packages: `MnemonikeyCs*`

2. **GitHub Secret**: Add the API key to your repository secrets
   - Go to your repository on GitHub
   - Navigate to Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `NUGET_API_KEY`
   - Value: Paste your NuGet API key
   - Click "Add secret"

## Publishing Methods

### Method 1: Create a GitHub Release (Recommended)

This is the most common approach for stable releases:

1. **Tag your release**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **Create a release on GitHub**:
   - Go to your repository → Releases → "Draft a new release"
   - Choose the tag you just created (v1.0.0)
   - Add release notes describing changes
   - Click "Publish release"

3. The workflow will automatically:
   - Build the project
   - Run tests
   - Pack both MnemonikeyCs and MnemonikeyCs.Cli packages
   - Push them to NuGet.org

### Method 2: Manual Workflow Dispatch

For testing or hotfixes:

1. Go to Actions → "Publish to NuGet" workflow
2. Click "Run workflow"
3. Select the branch
4. Enter the version number (e.g., `1.0.1-hotfix`)
5. Click "Run workflow"

## Version Numbering

Follow semantic versioning (SemVer):

- **Major.Minor.Patch** (e.g., `1.0.0`) for stable releases
- **Major.Minor.Patch-preview.N** (e.g., `1.0.0-preview.1`) for preview releases
- **Major.Minor.Patch-beta.N** (e.g., `1.0.0-beta.2`) for beta releases

## Package Details

The workflow publishes two packages:

1. **MnemonikeyCs** - The core library
   - Package ID: `MnemonikeyCs`
   - Contains the main Mnemonikey functionality

2. **MnemonikeyCs.Cli** - The command-line tool
   - Package ID: `MnemonikeyCs.Cli`
   - Can be installed as a .NET tool: `dotnet tool install -g MnemonikeyCs.Cli`

## Workflow Details

The `nuget-publish.yml` workflow:

1. ✅ Checks out the code
2. ✅ Sets up .NET 9.0
3. ✅ Determines the version from the release tag or manual input
4. ✅ Restores dependencies
5. ✅ Builds in Release configuration
6. ✅ Runs all tests to ensure quality
7. ✅ Packs both projects
8. ✅ Publishes to NuGet.org
9. ✅ Uploads artifacts for verification

## Verification

After publishing:

1. Check the workflow run for any errors
2. Visit https://www.nuget.org/packages/MnemonikeyCs/
3. Verify the new version appears (may take a few minutes)
4. Test installation:
   ```bash
   dotnet add package MnemonikeyCs --version 1.0.0
   dotnet tool install -g MnemonikeyCs.Cli --version 1.0.0
   ```

## Troubleshooting

### "Package already exists"
- The version number must be unique
- Increment the version or use a different prerelease suffix

### "API key is invalid"
- Verify the `NUGET_API_KEY` secret is set correctly
- Check that the API key hasn't expired

### Build or test failures
- The workflow will not publish if tests fail
- Fix the issues and create a new release

## Local Testing

Before publishing, test package creation locally:

```bash
# Build and pack
dotnet pack src/MnemonikeyCs/MnemonikeyCs.csproj -c Release -o ./packages

# Inspect the package
dotnet nuget push ./packages/MnemonikeyCs.1.0.0.nupkg --source https://api.nuget.org/v3/index.json --api-key YOUR_KEY --dry-run
```

## Security Notes

- Never commit API keys to the repository
- Use GitHub secrets for sensitive data
- Regularly rotate your API keys
- Limit API key permissions to only what's needed
