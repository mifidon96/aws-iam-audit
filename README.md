# aws-iam-audit

A Python script that audits AWS IAM users for common security issues.

## What it checks

- Users without MFA enabled
- Access keys older than 90 days
- Console users inactive for 90+ days

## Architecture
```
Local machine → boto3 → AWS IAM API → stdout report
```

## Requirements

- Python 3.8+
- AWS CLI configured (`aws configure`)
- IAM permissions (see below)

## Setup
```bash
git clone https://github.com/mifidon96/aws-iam-audit.git
cd aws-iam-audit
pip install -r requirements.txt
```

## Usage
```bash
python3 audit.py
```

## Required IAM permissions
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:ListUsers",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "iam:GetLoginProfile",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

## Lessons learned

- IAM pagination is required for accounts with many users — `list_users` returns max 100 at a time
- `PasswordLastUsed` is not present on all users (e.g. no console access), so must handle `KeyError`
- Access keys have a `Status` field (`Active`/`Inactive`) — useful for filtering

## Stretch goals

- [ ] Export report to CSV
- [ ] Check for users in AdministratorAccess group
- [ ] Coloured terminal output with `colorama`
- [ ] GitHub Actions scheduled run
