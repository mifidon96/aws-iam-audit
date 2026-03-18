import boto3
from datetime import datetime, timezone

iam = boto3.client('iam')


def get_all_users():
    """Fetch all IAM users using pagination."""
    paginator = iam.get_paginator('list_users')
    users = []
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users


def check_mfa(username):
    """Returns True if user has MFA enabled."""
    response = iam.list_mfa_devices(UserName=username)
    return len(response['MFADevices']) > 0


def check_access_keys(username):
    """Returns list of access keys older than 90 days."""
    response = iam.list_access_keys(UserName=username)
    old_keys = []
    for key in response['AccessKeyMetadata']:
        age_days = (datetime.now(timezone.utc) - key['CreateDate']).days
        if age_days > 90:
            old_keys.append({
                'KeyId': key['AccessKeyId'],
                'AgeDays': age_days,
                'Status': key['Status']
            })
    return old_keys


def check_last_login(user):
    """Returns days since last console login, or None if never logged in."""
    if 'PasswordLastUsed' not in user:
        return None
    days_since = (datetime.now(timezone.utc) - user['PasswordLastUsed']).days
    return days_since


def print_section(title):
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print('=' * 50)


def run_audit():
    print("\n🔍 Starting IAM Audit...")
    print(f"Account: ", end="")

    # Print account ID
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(identity['Account'])
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    users = get_all_users()
    print(f"Total IAM users found: {len(users)}")

    no_mfa = []
    old_keys_report = []
    inactive_users = []

    for user in users:
        name = user['UserName']

        # MFA check
        if not check_mfa(name):
            no_mfa.append(name)

        # Access key age check
        old_keys = check_access_keys(name)
        if old_keys:
            old_keys_report.append({'user': name, 'keys': old_keys})

        # Last login check
        days = check_last_login(user)
        if days is not None and days > 90:
            inactive_users.append({'user': name, 'days_since_login': days})

    # --- Report ---
    print_section(f"❌ Users WITHOUT MFA ({len(no_mfa)})")
    if no_mfa:
        for u in no_mfa:
            print(f"  - {u}")
    else:
        print("  ✅ All users have MFA enabled")

    print_section(f"⚠️  Access Keys Older Than 90 Days ({len(old_keys_report)})")
    if old_keys_report:
        for entry in old_keys_report:
            for key in entry['keys']:
                print(f"  - {entry['user']}: key {key['KeyId']} "
                      f"({key['AgeDays']} days old, status: {key['Status']})")
    else:
        print("  ✅ No access keys older than 90 days")

    print_section(f"💤 Inactive Console Users 90+ Days ({len(inactive_users)})")
    if inactive_users:
        for u in inactive_users:
            print(f"  - {u['user']}: last login {u['days_since_login']} days ago")
    else:
        print("  ✅ No inactive console users found")

    print("\n====== AUDIT COMPLETE ======\n")


if __name__ == "__main__":
    run_audit()
