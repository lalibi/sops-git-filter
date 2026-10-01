# Transparent Git encryption with SOPS + age

> **Windows-first reference implementation**
>
> This guide implements a `git-crypt`-like workflow in which protected files are **plaintext in the local working tree**, while Git stores **SOPS ciphertext in the index, commits, and remote repository**.
>
> It uses **SOPS + age + Git clean/smudge filters**, a local pre-commit guard, and repository tooling for fresh clones and linked worktrees.

## Quick start

### Initialize a repository

Run the initializer from the root of the repository you want to protect:

```powershell
pwsh `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File .\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -RepoPath . `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json',
        'src/Web/appsettings.Production.json'
    )
```

`ProtectedPath` accepts exact file or directory paths relative to the repository root.

For example:

- `secrets/` protects every tracked file under that directory.
- `appsettings.json` protects only the file at the repository root.
- `src/Web/appsettings.Production.json` protects only that specific nested file.
- Other files in `src/Web/`, such as `src/Web/appsettings.json`, remain unencrypted unless explicitly included.

After initialization:

- protected files remain plaintext in the local working tree;
- the Git index and commits contain SOPS ciphertext;
- the Git clean/smudge filter handles encryption and decryption transparently;
- a pre-commit validator prevents plaintext protected files from being committed.

Review the staged changes before committing:

```powershell
git status
git diff --cached
git hook run pre-commit
```

### Set up an existing repository on a new machine

After cloning a repository that has already been configured with `sops-git-filter`, the protected files initially appear encrypted because Git filter configuration is local and is not transferred by `git clone`.

PowerShell 7.4+ must already be installed to run the script; Git, SOPS and age are installed automatically when missing.

If the machine already has an authorized age private key, run:

```powershell
pwsh `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File .\.githooks\Initialize-SopsGit.ps1 `
    -Mode Join `
    -RepoPath .
```

The command configures the local Git filter and validation hook, decrypts the protected files into the working tree, and preserves the existing encrypted blobs in the Git index.

After setup:

```powershell
git status --short
git hook run pre-commit
```

`git status --short` should be empty and the validation hook should report:

```text
SOPS index validation passed.
```

The working tree now contains plaintext files, while Git continues to store their encrypted SOPS representation.

If the private key is in a secure backup instead, import it during setup by adding `-AgeKeySource`:

```powershell
pwsh `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File .\.githooks\Initialize-SopsGit.ps1 `
    -Mode Join `
    -RepoPath . `
    -AgeKeySource 'E:\secure-backup\age-keys.txt'
```

The key is copied to `%APPDATA%\sops\age\keys.txt`. The backup file contains private key material and must be handled accordingly.

### Add a collaborator

Each collaborator should use their own age identity. Private age keys must never be committed to the repository or shared through Git.

If a collaborator clones the repository and has no local age identity yet, running `-Mode Join` generates one, prints the **public** `age1...` recipient, and exits without pretending that the new key can decrypt the repository.

To generate the identity manually instead, run on the collaborator's machine:

```powershell
$AgeDir = Join-Path $env:APPDATA 'sops\age'
$AgeKeyFile = Join-Path $AgeDir 'keys.txt'

New-Item -ItemType Directory -Force -Path $AgeDir | Out-Null
age-keygen -o $AgeKeyFile

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $AgeKeyFile /inheritance:r
icacls $AgeKeyFile /grant:r "${Identity}:(F)"
```

Then print the public recipient:

```powershell
age-keygen -y $AgeKeyFile
```

The output is an `age1...` public recipient. The private key stays in `%APPDATA%\sops\age\keys.txt`. See [Creating an age identity](#5-creating-an-age-identity) for details.

The collaborator sends only that public recipient to a maintainer. Never send or commit an `AGE-SECRET-KEY-...` value. The maintainer then runs:

```powershell
pwsh `
    -NoLogo `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File .\.githooks\Initialize-SopsGit.ps1 `
    -Mode AddRecipient `
    -RepoPath . `
    -AdditionalAgeRecipient 'age1...'
```

This adds the recipient to `.sops.yaml`, re-encrypts all tracked protected files for the updated recipient set, keeps the maintainer's working-tree files as plaintext, and validates the Git index. Review and commit the result:

```powershell
git status
git diff --cached
git hook run pre-commit

git commit -m "Add SOPS recipient"
git push
```

After the maintainer pushes the re-encrypted files, the collaborator pulls and runs `-Mode Join` again.

See [Collaborator onboarding with an independent age key](#18-collaborator-onboarding-with-an-independent-age-key) for the complete flow.

### Windows execution policy note

The examples use `-ExecutionPolicy Bypass` only for the launched `pwsh` process; they do not change the machine or user execution policy.

If a trusted copy of the script was downloaded through a browser and Windows marked it as originating from the Internet, you may remove that mark after verifying the file:

```powershell
Unblock-File .\Initialize-SopsGit.ps1
```

Do not weaken the global execution policy just to run this utility.

---

# 1. Goals and design

The technique is intended for repositories that need to keep a limited set of sensitive files in Git while allowing applications, editors and build tools to use those files normally on a trusted developer machine.

The desired model is:

```text
Working tree                        Git index / commits / remote
-------------                       ----------------------------
appsettings.json      clean ────►   SOPS encrypted JSON
secrets/secrets.txt   clean ────►   SOPS encrypted binary blob

                      ◄──── smudge

plaintext locally                    ciphertext in Git
```

The solution deliberately separates four responsibilities:

1. **SOPS** encrypts and decrypts file content.
2. **age** supplies the public/private identities used by SOPS.
3. **Git clean/smudge filters** transparently convert between local plaintext and repository ciphertext.
4. **Validation** prevents plaintext protected files from being committed accidentally.

This gives a workflow close to `git-crypt`, but without depending on `git-crypt`'s repository-specific state.

---

## 2. Important security properties

### What is protected

For a protected file:

- the working-tree copy is plaintext;
- the Git index contains SOPS ciphertext;
- commits contain SOPS ciphertext;
- a remote repository receives only SOPS ciphertext;
- a fresh clone that has **not** been configured yet initially checks out the encrypted representation;
- after local setup, the encrypted working-tree copies are replaced with plaintext.

### What is not protected

This technique does **not** encrypt:

- filenames;
- directory names;
- commit messages;
- branch names;
- Git metadata;
- the fact that a protected file exists;
- the `.gitattributes` patterns that identify protected files.

For structured SOPS formats such as JSON/YAML, SOPS normally preserves the key structure and encrypts leaf values. If key names themselves are sensitive, treat the file as binary instead of structured data.

### The private age key

The age private identity is **never committed**.

The standard SOPS location used by this setup on Windows is:

```text
%APPDATA%\sops\age\keys.txt
```

A line beginning with:

```text
AGE-SECRET-KEY-
```

is private. Never place it in Git, a ticket, chat, wiki, CI log or email.

A recipient beginning with:

```text
age1...
```

is public and is safe to store in `.sops.yaml`.

---

# 3. Prerequisites

The reference setup is Windows-first and expects:

- Windows 10/11 or Windows Server;
- PowerShell 7.4 or newer;
- Git 2.55 or newer;
- SOPS;
- age / age-keygen.

The accompanying `Initialize-SopsGit.ps1` script checks these prerequisites and installs missing tools when possible.

Current reference versions used while this document was written:

- **SOPS 3.13.3**
- **age 1.3.2**

The setup script does not rely on those versions being permanently current; they are configurable parameters.

---

# 4. Manual installation

The automation script later in this guide can do this for you. This section documents the manual process so the system remains understandable and recoverable.

## 4.1 PowerShell

Verify:

```powershell
$PSVersionTable.PSVersion
```

Recommended:

```text
7.4+
```

The implementation was tested with PowerShell 7.6.

If PowerShell 7 is missing, install it with Windows Package Manager:

```powershell
winget install --id Microsoft.PowerShell -e
```

Open a new `pwsh` session afterwards.

## 4.2 Git

Verify:

```powershell
git --version
```

The reference implementation uses Git's configured/named hook support:

```text
hook.<name>.command
hook.<name>.event
```

and therefore requires Git 2.55+.

Install/update with:

```powershell
winget install --id Git.Git -e
```

or:

```powershell
winget upgrade --id Git.Git -e
```

## 4.3 age

Install:

```powershell
winget install --id FiloSottile.age -e
```

Verify:

```powershell
age --version
age-keygen --version
```

## 4.4 SOPS

SOPS publishes native Windows binaries in its GitHub releases.

A typical local install location is:

```text
%LOCALAPPDATA%\Programs\SOPS\sops.exe
```

For SOPS 3.13.3 on Windows x64, the official binary is:

```text
sops-v3.13.3.amd64.exe
```

After copying/renaming it to `sops.exe`, add the directory to the user `PATH`.

Verify:

```powershell
sops --version
```

The automation script downloads the selected SOPS release from GitHub, verifies the release asset SHA-256 when GitHub exposes the digest, installs it under `%LOCALAPPDATA%\Programs\SOPS`, and updates the user PATH.

---

# 5. Creating an age identity

## 5.1 Generate the private key

```powershell
$AgeDir = Join-Path $env:APPDATA 'sops\age'
$AgeKeyFile = Join-Path $AgeDir 'keys.txt'

New-Item -ItemType Directory -Force -Path $AgeDir | Out-Null

age-keygen -o $AgeKeyFile
```

Restrict the ACL:

```powershell
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

icacls $AgeKeyFile /inheritance:r
icacls $AgeKeyFile /grant:r "${Identity}:(F)"
```

## 5.2 Obtain the public recipient

```powershell
age-keygen -y $AgeKeyFile
```

Example:

```text
age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Only the public `age1...` recipient goes into the repository.

---

# 6. Repository layout

A typical repository after setup looks like this:

```text
repo/
├── .gitattributes
├── .sops.yaml
├── .githooks/
│   ├── Initialize-SopsGit.ps1
│   ├── Setup-SopsGit.ps1
│   ├── Test-SopsIndex.ps1
│   └── git-sops-filter.ps1
├── appsettings.json                  # optionally protected
├── src/
│   └── Web/
│       ├── appsettings.Production.json  # optionally protected
│       └── normal-source-file.cs
└── secrets/
    └── secrets.txt                   # optionally protected
```

Only files explicitly selected by `.gitattributes` are passed through the SOPS filter.

---

# 7. `.gitattributes`: deciding what Git encrypts

Git's `filter` attribute activates a named clean/smudge filter for a path.

A protected directory:

```gitattributes
/secrets/** filter=sops -text
```

A protected file in the repository root:

```gitattributes
/appsettings.json filter=sops -text
```

A protected file inside a directory that also contains normal unencrypted files:

```gitattributes
/src/Web/appsettings.Production.json filter=sops -text
```

These rules do **not** encrypt sibling files.

For example:

```text
src/Web/
├── appsettings.Production.json    encrypted
├── Program.cs                     normal
├── Web.csproj                     normal
└── README.md                      normal
```

with:

```gitattributes
/src/Web/appsettings.Production.json filter=sops -text
```

Only the single JSON file is filtered.

## 7.1 Protecting every appsettings file

If that is genuinely desired:

```gitattributes
**/appsettings.json filter=sops -text
**/appsettings.*.json filter=sops -text
```

Be careful: broad patterns may encrypt files that were intended to remain public.

## 7.2 Why `-text`

`-text` disables Git EOL normalization for protected paths. The filter owns the exact transformation between working-tree bytes and repository bytes.

---

# 8. `.sops.yaml`: deciding which age recipients can encrypt/decrypt

`.gitattributes` tells Git **which files use the filter**.

`.sops.yaml` tells SOPS **which encryption keys apply to those paths**.

Both must agree.

For a `secrets/` directory:

```yaml
creation_rules:
  - path_regex: '^secrets[\\/].*$'
    age:
      - age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

For a root `appsettings.json`:

```yaml
creation_rules:
  - path_regex: '^appsettings\.json$'
    age:
      - age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

For one nested file:

```yaml
creation_rules:
  - path_regex: '^src[\\/]Web[\\/]appsettings\.Production\.json$'
    age:
      - age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

A single combined rule is also valid:

```yaml
creation_rules:
  - path_regex: '^(?:secrets[\\/].*|appsettings\.json|src[\\/]Web[\\/]appsettings\.Production\.json)$'
    age:
      - age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

The Windows-compatible separator expression `[\\/]` allows both `/` and `\`.

---

# 9. File formats

The reference filter chooses a SOPS format from the original filename.

| Extension       | Plaintext input | Repository representation |
| --------------- | --------------- | ------------------------- |
| `.json`         | JSON            | SOPS JSON                 |
| `.yaml`, `.yml` | YAML            | SOPS YAML                 |
| `.env`          | dotenv          | SOPS dotenv               |
| `.ini`          | INI             | SOPS INI                  |
| anything else   | binary          | SOPS JSON binary envelope |

## 9.1 JSON / appsettings.json

For JSON, SOPS preserves the JSON tree and encrypts leaf values.

Example local working tree:

```json
{
  "ConnectionStrings": {
    "Default": "Server=...;Password=secret"
  },
  "ApiKey": "secret"
}
```

The committed representation contains values similar to:

```json
{
  "ConnectionStrings": {
    "Default": "ENC[AES256_GCM,...]"
  },
  "ApiKey": "ENC[AES256_GCM,...]",
  "sops": {
    ...
  }
}
```

This is ideal for `appsettings.json` / `appsettings.Production.json`.

### JSON limitations

A top-level JSON array cannot carry the normal SOPS metadata structure. If a JSON file has a top-level array or otherwise cannot be handled as structured SOPS JSON, treat it as binary instead.

## 9.2 Arbitrary text and binary files

A file such as:

```text
secrets/secrets.txt
```

that is not JSON/YAML/ENV/INI is treated as **binary**.

The working tree remains the original plaintext text/binary bytes.

The Git blob becomes a SOPS JSON envelope such as:

```json
{
  "data": "ENC[AES256_GCM,...]",
  "sops": {
    ...
  }
}
```

The filename can remain `.txt`; the filter explicitly tells SOPS that plaintext input is binary and encrypted input is JSON.

This also works for many other opaque files, for example `.pem`, `.key`, `.pfx`, `.bin`, provided the application can safely use the decrypted local file.

---

# 10. How the Git filter works

Git filter drivers receive file content on **stdin** and must emit transformed content on **stdout**.

The repository config contains:

```text
filter.sops.clean
filter.sops.smudge
filter.sops.required=true
```

Conceptually:

```text
git add
  │
  ├─ plaintext from working tree
  │
  └─ clean filter
       │
       └─ SOPS encrypt
            │
            └─ ciphertext enters Git index
```

and:

```text
checkout / restore
  │
  ├─ ciphertext from Git blob
  │
  └─ smudge filter
       │
       └─ SOPS decrypt
            │
            └─ plaintext working-tree file
```

The filter must **never read the file directly from disk as its primary input**. Git supplies the content through stdin.

---

# 11. Avoiding random-ciphertext churn

SOPS encryption is randomized. Encrypting identical plaintext twice normally produces different ciphertext.

A naïve clean filter would therefore make Git believe a file changed every time it was inspected or added.

The reference filter prevents that:

1. read the existing ciphertext blob from the current Git index;
2. decrypt that blob;
3. compare the decrypted bytes to the incoming working-tree plaintext;
4. if they are identical, return the **existing ciphertext unchanged**;
5. only run fresh SOPS encryption if plaintext actually changed.

Therefore:

```powershell
$Blob1 = git rev-parse ':secrets/secrets.txt'

git add -- secrets/secrets.txt

$Blob2 = git rev-parse ':secrets/secrets.txt'

$Blob1 -eq $Blob2
```

should return:

```text
True
```

when the plaintext was not modified.

This is also important for `git status` performance and for stable worktree behaviour.

---

# 12. Idempotent clean behaviour

The clean filter additionally accepts the exact ciphertext already present in the index.

This matters during bootstrap and certain checkout operations:

```text
clean(ciphertext already in index) = same ciphertext
```

A well-behaved Git clean filter should be idempotent.

---

# 13. Pre-commit protection

`.gitattributes` is versioned, but Git filter configuration is local.

A collaborator could theoretically clone a repository, fail to configure the filter and accidentally stage plaintext.

The repository therefore contains:

```text
.githooks/Test-SopsIndex.ps1
```

The validator:

1. lists tracked files;
2. asks Git which ones have `filter=sops`;
3. reads the **index blob**, not the working-tree file;
4. runs `sops filestatus`;
5. aborts the commit if any protected blob is not SOPS encrypted.

Typical failure:

```text
ERROR: plaintext or invalid SOPS data found in the Git index:
  - secrets/secrets.txt

Commit aborted to prevent plaintext secrets from being committed.
```

The configured named hook is:

```text
hook.sops-index.command
hook.sops-index.event=pre-commit
```

Verify:

```powershell
git hook list --show-scope pre-commit
```

Expected:

```text
local   sops-index
```

## Important limitation

Local hooks can be bypassed, for example with:

```text
git commit --no-verify
```

For an important repository, also add server-side/CI validation and make it a required merge check.

---

# 14. Automated initial setup

The accompanying script is:

```text
Initialize-SopsGit.ps1
```

It performs the work that was otherwise done manually:

- checks PowerShell;
- checks/install/upgrades Git;
- checks/installs age;
- checks/installs SOPS;
- verifies downloaded GitHub release asset hashes when available;
- creates/imports an age identity;
- restricts private-key ACLs;
- creates `.gitattributes`;
- creates `.sops.yaml`;
- creates the filter/helper/validator/bootstrap scripts;
- configures local Git filter settings;
- configures the named pre-commit hook;
- stages protected files through the clean filter;
- runs validation.

## 14.1 Basic repository

From the repository root:

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -ProtectedPath 'secrets/'
```

## 14.2 Folder plus root appsettings

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json'
    )
```

## 14.3 Selected files among normal files

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json',
        'src/Web/appsettings.Production.json'
    )
```

`ProtectedPath` intentionally accepts **exact files or directories**, not wildcard expressions. This makes automatic `.sops.yaml` generation deterministic.

If a directory does not exist yet, add a trailing slash (for example `secrets/`) so the script can distinguish it from a file path.

For advanced glob patterns, edit `.gitattributes` and `.sops.yaml` manually.

## 14.4 Additional recipient during initialization

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json'
    ) `
    -AdditionalAgeRecipient @(
        'age1publicrecipientforcollaborator...'
    )
```

---

# 15. Recommended first commit

After `-Mode Initialize`, the safest default is to commit the SOPS integration and the newly encrypted protected blobs together.

Review everything first:

```powershell
git status
git diff --cached
git hook run pre-commit
```

Then commit:

```powershell
git commit -m "Enable transparent SOPS encryption"
```

### Using `-NoStage`

`-NoStage` leaves staging under your control. When introducing SOPS protection to files that are **already tracked as plaintext**, stage the repository tooling **and the protected files before committing**:

```powershell
git add `
    .gitattributes `
    .sops.yaml `
    .githooks `
    secrets `
    appsettings.json

git hook run pre-commit

git commit -m "Protect secrets with SOPS"
```

Do not commit a new `.gitattributes` rule that marks an already-tracked plaintext file as `filter=sops` while leaving that file's plaintext blob in the index. The validator intentionally treats that as unsafe and rejects the commit.

If you require separate infrastructure and secret-history commits, introduce the infrastructure before activating the protection rules, rather than bypassing validation.

---

# 16. Verification before the first push

For every important protected file, perform both views.

## Working tree — must be plaintext

```powershell
Get-Content .\appsettings.json
```

or:

```powershell
Get-Content .\secrets\secrets.txt
```

## Git index — must be encrypted

Before commit:

```powershell
git show :appsettings.json
git show :secrets/secrets.txt
```

After commit:

```powershell
git show HEAD:appsettings.json
git show HEAD:secrets/secrets.txt
```

For binary-mode files the committed representation should contain:

```text
"data": "ENC[AES256_GCM,...
```

For JSON values:

```text
ENC[AES256_GCM,...
```

Also verify:

```powershell
git hook run pre-commit
git status --short
```

---

# 17. Fresh clone / new machine

A fresh clone does **not** inherit local Git filter configuration.

That is intentional.

Before setup, protected files will normally appear in their encrypted repository form.

## 17.1 Same user, new machine: reuse the private identity

Securely transfer the age private key file from the old trusted machine:

```text
%APPDATA%\sops\age\keys.txt
```

Do not transfer it through Git.

After cloning:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 `
    -Mode Join `
    -AgeKeySource 'E:\secure\sops-age-keys.txt'
```

The script:

- installs missing executables;
- imports the private identity;
- configures the local filter;
- configures the pre-commit hook;
- decrypts encrypted working-tree copies;
- verifies that re-adding plaintext maps to exactly the same index ciphertext;
- runs the validator.

Final checks:

```powershell
git status --short
git hook list --show-scope pre-commit
```

`git status --short` should be empty.

## 17.2 Same user, key already installed

If `%APPDATA%\sops\age\keys.txt` is already present:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode Join
```

---

# 18. Collaborator onboarding with an independent age key

Using a different age identity for each collaborator is preferable to sharing one private key.

## Step 1 — collaborator generates an identity

The collaborator clones the repository and runs:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode Join
```

If no local age identity exists, the script generates one and prints the **public** recipient:

```text
age1...
```

At this stage the collaborator cannot decrypt existing files yet, and the script exits with code `2`.

They send only that public recipient to the maintainer. Never send or commit an `AGE-SECRET-KEY-...` value.

Alternatively, generate the identity manually with `age-keygen` and send the output of `age-keygen -y`, as described in [Creating an age identity](#5-creating-an-age-identity).

## Step 2 — maintainer adds the recipient

On a machine that already has access:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 `
    -Mode AddRecipient `
    -AdditionalAgeRecipient 'age1...'
```

The tracked working tree must be clean, and `.sops.yaml` must have been generated by `Initialize-SopsGit.ps1`; a hand-written `.sops.yaml` is rejected.

The script:

- adds the public recipient to the managed `.sops.yaml`;
- freshly re-encrypts every tracked protected file for the updated recipient set;
- preserves the plaintext files in the maintainer's working tree;
- directly updates the Git index with the new ciphertext;
- confirms that normal clean-filter processing preserves that ciphertext;
- runs the pre-commit validator.

Review:

```powershell
git status
git diff --cached
git hook run pre-commit
```

Then commit and push:

```powershell
git commit -m "Grant SOPS access to collaborator"
git push
```

## Step 3 — collaborator pulls and joins again

```powershell
git pull

pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode Join
```

The existing collaborator private key can now decrypt the new SOPS metadata.

Verify as in the Quick start: `git status --short` should be empty and `git hook run pre-commit` should report `SOPS index validation passed.`

---

# 19. Adding a new protected file later

Suppose the repository already uses the system and you decide to protect:

```text
src/Worker/service-secrets.txt
```

The safest approach is to rerun initialization with the complete intended path set:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 `
    -Mode Initialize `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json',
        'src/Worker/service-secrets.txt'
    )
```

The generated managed path configuration is replaced with the new complete set.

Existing recipients from a script-managed `.sops.yaml` are preserved when `Initialize` is rerun, so adding a protected path does not silently remove collaborators previously added with `AddRecipient`.

Then verify:

```powershell
git check-attr -a -- src/Worker/service-secrets.txt
```

Expected:

```text
filter: sops
text: unset
```

Stage and inspect the index:

```powershell
git add -- src/Worker/service-secrets.txt
git show :src/Worker/service-secrets.txt
git hook run pre-commit
```

---

# 20. Git worktrees

The design avoids storing repository encryption state in a fixed `.git/git-crypt`-style directory.

The local Git configuration is shared appropriately by linked worktrees, while each worktree has its own index.

Test:

```powershell
git worktree add ..\repo-feature -b feature/example

Set-Location ..\repo-feature

Get-Content .\secrets\secrets.txt
git status --short
```

The protected working-tree file should be plaintext and the status clean.

Check the committed blob:

```powershell
git show HEAD:secrets/secrets.txt
```

It should be encrypted.

---

# 21. Why fresh-clone bootstrap does not use checkout-index

A fresh clone has ciphertext in the working tree because the local filter is not configured yet.

After configuring the filter, the bootstrap explicitly:

1. reads the ciphertext blob from the current Git index;
2. decrypts it with SOPS to a temporary file;
3. atomically replaces the working-tree file with plaintext;
4. runs a normal `git add` through the clean filter;
5. verifies that the resulting index blob hash is unchanged.

This is intentional.

The normal `git add` refresh is necessary because a metadata-only `git add --refresh` does not perform the clean transformation required to establish the canonical comparison.

---

# 22. Migration from git-crypt

This section describes migration of the **current branch/tip** from git-crypt to SOPS.

## Critical historical fact

Migration does **not** automatically convert old commits.

After migration:

- new/current commits use SOPS;
- old historical commits that were encrypted by git-crypt remain git-crypt encrypted;
- keep the old git-crypt key securely if you need to inspect those historical versions.

Fully converting every historical commit requires a deliberate history rewrite and is a separate operation.

---

## 22.1 Preparation

Before changing anything:

```powershell
git status
```

The tracked working tree must be clean.

Create a safety reference:

```powershell
git branch backup/pre-sops-migration
```

Ensure the repository is unlocked:

```powershell
git-crypt status
```

List the protected files:

```powershell
git-crypt status -e
```

Use this as a migration checklist.

Do **not** run `git-crypt lock` during the conversion: the goal is to keep the current working-tree copies plaintext so they can be re-added through the SOPS clean filter.

---

## 22.2 Automated migration

Pass the actual protected files/directories explicitly:

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode MigrateGitCrypt `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json'
    )
```

Optional removal of tracked `.git-crypt` recipient metadata:

```powershell
pwsh .\Initialize-SopsGit.ps1 `
    -Mode MigrateGitCrypt `
    -ProtectedPath @(
        'secrets/',
        'appsettings.json'
    ) `
    -RemoveGitCryptMetadata
```

The migration mode:

1. requires a clean tracked working tree;
2. verifies that `git-crypt` is installed;
3. displays `git-crypt status -e`;
4. generates/imports an age identity;
5. rewrites git-crypt filter attributes to `filter=sops -text`;
6. creates `.sops.yaml`;
7. installs the repository SOPS tooling;
8. configures the local SOPS filter;
9. stages the currently plaintext protected files through SOPS;
10. runs the SOPS index validator.

---

## 22.3 Manual migration

If the old `.gitattributes` contains:

```gitattributes
/secrets/** filter=git-crypt diff=git-crypt
/appsettings.json filter=git-crypt diff=git-crypt
```

replace it with:

```gitattributes
/secrets/** filter=sops -text
/appsettings.json filter=sops -text
```

Create the corresponding `.sops.yaml`.

Then configure the SOPS helper before staging the plaintext:

```powershell
pwsh .\.githooks\Setup-SopsGit.ps1
```

Stage:

```powershell
git add .gitattributes .sops.yaml .githooks
git add secrets appsettings.json
```

Verify that the index is now SOPS ciphertext:

```powershell
git show :appsettings.json
git show :secrets/secrets.txt
git hook run pre-commit
```

Only then commit.

---

## 22.4 Removing git-crypt remnants

After the migration commit has been verified and backed up:

- remove tracked `.git-crypt/` metadata if it is no longer needed;
- inspect local git-crypt filter configuration:

```powershell
git config --local --get-regexp '^filter\.git-crypt'
git config --local --get-regexp '^diff\.git-crypt'
```

You may remove those local sections once you no longer need git-crypt for the current checkout.

Do not delete your old git-crypt key if historical commits may still need to be decrypted.

---

# 23. Recovery and troubleshooting

## `error loading config: no matching creation rules found`

The filename supplied through `--filename-override` did not match a `.sops.yaml` `path_regex`.

Check both:

```powershell
Get-Content .sops.yaml
git check-attr -a -- path/to/file
```

On Windows, use `[\\/]` in regex path separators.

---

## Working tree contains ciphertext after clone

The repository has not been bootstrapped locally yet.

Run:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode Join
```

with a usable local age identity.

---

## `git status` shows a protected file modified immediately after bootstrap

Check whether a normal clean-filter pass produces the same blob:

```powershell
$Before = git rev-parse ':path/to/file'

git add -- path/to/file

$After = git rev-parse ':path/to/file'

$Before -eq $After
```

Expected:

```text
True
```

The supplied bootstrap already performs this check automatically.

---

## Repeated `git add` changes the blob hash

That indicates the stable-ciphertext logic is not functioning.

Test:

```powershell
$Blob1 = git rev-parse ':path/to/file'
git add -- path/to/file
$Blob2 = git rev-parse ':path/to/file'

$Blob1 -eq $Blob2
```

Expected for unchanged plaintext:

```text
True
```

---

## SOPS cannot find the age key

Check:

```powershell
Test-Path (Join-Path $env:APPDATA 'sops\age\keys.txt')
```

Then:

```powershell
age-keygen -y (Join-Path $env:APPDATA 'sops\age\keys.txt')
```

The output should be a recipient listed in the encrypted file's SOPS metadata.

---

## Filter executable is missing

Verify:

```powershell
Get-Command sops
Get-Command age
Get-Command age-keygen
Get-Command git
Get-Command pwsh
```

Rerun:

```powershell
pwsh .\.githooks\Initialize-SopsGit.ps1 -Mode Join
```

---

# 24. CI validation

The local pre-commit hook is useful but not authoritative.

A CI job should run the repository validator directly on the committed/index content.

The CI environment does **not** need the private age key merely to verify that protected blobs are SOPS-encrypted.

At minimum:

1. checkout repository;
2. install SOPS;
3. run:

```powershell
pwsh .\.githooks\Test-SopsIndex.ps1
```

Make that CI check required before merging.

Do not put the age private identity into CI unless the build genuinely needs plaintext secrets. If CI needs secret material, prefer the CI platform's secret store or a cloud KMS rather than a long-lived developer age key.

---

# 25. Key rotation and access removal

SOPS supports multiple age public recipients.

Adding a new recipient does not require sharing an existing private key.

Removing access is more subtle:

- remove the recipient from `.sops.yaml`;
- re-encrypt / rotate the protected files;
- commit the new ciphertext;
- rotate the actual application credentials if the removed user may have learned them.

Remember that a user who previously had access may still possess:

- old repository commits;
- old ciphertext;
- old decrypted values.

Cryptographic rekeying cannot make previously disclosed plaintext unknown again.

---

# 26. Operational checklist

Before pushing a newly protected repository:

```powershell
git status
git hook run pre-commit
git hook list --show-scope pre-commit
git config --local --get-regexp '^filter\.sops\.'
```

For each critical file:

```powershell
# Local application view
Get-Content .\path\to\secret

# Repository/index view
git show :path/to/secret
```

After commit:

```powershell
git show HEAD:path/to/secret
```

On a disposable fresh clone:

```powershell
git clone <repo> fresh-test
Set-Location fresh-test

# Before setup: encrypted
Get-Content .\path\to\secret

pwsh .\.githooks\Initialize-SopsGit.ps1 `
    -Mode Join `
    -AgeKeySource 'X:\secure\keys.txt'

# After setup: plaintext
Get-Content .\path\to\secret

# No artificial modifications
git status --short
```

A final fresh-clone test is strongly recommended before relying on the system.

---

# 27. Reference commands

## Show which files have the SOPS filter

```powershell
git ls-files ':(attr:filter=sops)'
```

## Show effective attributes

```powershell
git check-attr -a -- appsettings.json
```

## Validate all protected index blobs

```powershell
pwsh .\.githooks\Test-SopsIndex.ps1
```

or:

```powershell
git hook run pre-commit
```

## Inspect the encrypted index representation

```powershell
git show :appsettings.json
```

## Inspect committed representation

```powershell
git show HEAD:appsettings.json
```

## Check worktrees

```powershell
git worktree list
```

---

# 28. Files created by the automation

`Initialize-SopsGit.ps1` places these files in the repository:

```text
.gitattributes
.sops.yaml
.githooks/
├── Initialize-SopsGit.ps1
├── Setup-SopsGit.ps1
├── Test-SopsIndex.ps1
└── git-sops-filter.ps1
```

### `Initialize-SopsGit.ps1`

Owner/collaborator orchestrator:

- prerequisites;
- downloads/installations;
- identity management;
- repository initialization;
- join/new-machine flow;
- collaborator recipient addition;
- git-crypt migration.

### `Setup-SopsGit.ps1`

Local clone/worktree bootstrap:

- configures clean/smudge filters;
- configures the named pre-commit hook;
- decrypts fresh-clone ciphertext into the working tree;
- confirms that plaintext maps back to the same index blob.

### `git-sops-filter.ps1`

Binary-safe clean/smudge filter.

### `Test-SopsIndex.ps1`

Fail-closed check that every protected Git index blob is actually SOPS-encrypted.

---

# 29. Upstream references

- SOPS documentation: https://getsops.io/docs/
- SOPS installation: https://getsops.io/docs/installation/
- SOPS advanced/stdin usage: https://getsops.io/docs/usage/advanced/
- SOPS key management: https://getsops.io/docs/usage/key-management/
- SOPS reference / `.sops.yaml`: https://getsops.io/docs/reference/
- SOPS releases: https://github.com/getsops/sops/releases
- age: https://github.com/FiloSottile/age
- Git attributes / filters: https://git-scm.com/docs/gitattributes
- Git hooks: https://git-scm.com/docs/git-hook
- git-crypt: https://github.com/AGWA/git-crypt

---

# 30. Final model

Once configured, normal day-to-day work is deliberately boring:

```text
edit plaintext file
        │
        ▼
     git add
        │
        ▼
SOPS clean filter
        │
        ▼
encrypted Git index
        │
        ▼
      commit
        │
        ▼
encrypted remote
```

and:

```text
clone / checkout
        │
        ▼
encrypted Git blob
        │
        ▼
SOPS smudge/bootstrap
        │
        ▼
plaintext local file
```

That is the intended outcome: **normal application files locally, encrypted repository blobs remotely, with explicit validation around the boundary.**

---

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
