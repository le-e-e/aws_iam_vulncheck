import boto3
from datetime import datetime, timedelta

def lambda_handler(event, context):
    # AWS 서비스 객체 생성
    iam = boto3.client('iam')
    cloudtrail = boto3.client('cloudtrail')
    sts = boto3.client('sts')

    # 현재 날짜
    today = datetime.now().date()

    # 1. ROOT 계정에 Access key ID / Secret access key를 발급한 이력이 있는가?
    access_keys = iam.list_access_keys(UserName='root')
    access_key_result = 'O' if access_keys['AccessKeyMetadata'] else 'X'

    # 2. ROOT 계정 사용 이력이 있는가?
    events = cloudtrail.lookup_events(LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}])['Events']
    root_usage_result = 'O' if events else 'X'

    # 3. 30일 이상 사용하지 않은 Access key가 있는가?
    inactive_keys = []
    all_users = iam.list_users()['Users']
    for user in all_users:
        access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for key in access_keys:
            last_used = key.get('LastUsedDate')
            if last_used and (today - last_used.date()) > timedelta(days=30):
                inactive_keys.append(user['UserName'])

    # 4. Access key 변경 주기를 지정하지 않고, 주기적으로 Access key를 변경하지 않은 경우
    no_rotation_keys = []
    for user in all_users:
        policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
        for policy in policies:
            if 'IAMUserChangePassword' not in policy['PolicyName']:
                no_rotation_keys.append(user['UserName'])

    # 5. 권한 그룹에 속해있지 않는 IAM 계정이 있는가?
    users_not_in_group = []
    for user in all_users:
        groups = iam.list_groups_for_user(UserName=user['UserName'])['Groups']
        if not groups:
            users_not_in_group.append(user['UserName'])

    # 6. 영문ㆍ숫자ㆍ특수문자 3종류를 조합하여 8자리 이상의 길이로 비밀번호를 구성하지 않거나,
    #    분기별 1회 이상 비밀번호를 변경하지 않은 계정이 있는가?
    non_compliant_passwords = []
    for user in all_users:
        login_profile = iam.get_login_profile(UserName=user['UserName'])
        password_policy = iam.get_account_password_policy()
        if 'PasswordLastUsed' not in login_profile and password_policy['PasswordPolicy']['MinimumPasswordLength'] < 8:
            non_compliant_passwords.append(user['UserName'])

    # 7. 오늘 STS를 활용하지 않고 IAM 계정 또는 그룹에 직접 권한을 부여하여 AWS 리소스를 핸들링 한 기록이 있는가?
    sts_usage_events = cloudtrail.lookup_events(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'AssumeRole'}]
    )['Events']
    iam_direct_access = any(event['Username'] == 'root' or event['UserIdentity']['type'] == 'IAMUser' for event in sts_usage_events)

    # 8. 어떠한 태그도 설정되어있지 않은 IAM 계정이 있는가?
    users_without_tags = []
    for user in all_users:
        tags = iam.list_user_tags(UserName=user['UserName'])['Tags']
        if not tags:
            users_without_tags.append(user['UserName'])

    # 결과 출력
    print(f"ROOT 계정 Access key ID/Secret access key 발급여부: {access_key_result}")
    print(f"ROOT 계정 사용 이력: {root_usage_result}")
    print(f"30일 이상 미사용 Access key: {', '.join(inactive_keys)}")
    print(f"Access key 변경 주기 미지정 또는 주기적 변경하지 않은 계정: {', '.join(no_rotation_keys)}")
    print(f"그룹에 속해있지 않은 계정: {', '.join(users_not_in_group)}")
    print(f"비밀번호 정책 위배 계정: {', '.join(non_compliant_passwords)}")
    print(f"IAM 계정이 직접 AWS 리소스를 이용한 기록: {'O' if iam_direct_access else 'X'}")
    print(f"태그가 없는 계정: {', '.join(users_without_tags)}")

    # 디스코드 알림으로 결과 전송 (예시)
    send_discord_notification(
        f"ROOT 계정 Access key ID/Secret access key 발급여부: {access_key_result}\n"
        f"ROOT 계정 사용 이력: {root_usage_result}\n"
        f"30일 이상 미사용 Access key: {', '.join(inactive_keys)}\n"
        f"Access key 변경 주기 미지정 또는 주기적 변경하지 않은 계정: {', '.join(no_rotation_keys)}\n"
        f"그룹에 속해있지 않은 계정: {', '.join(users_not_in_group)}\n"
        f"비밀번호 정책 위배 계정: {', '.join(non_compliant_passwords)}\n"
        f"IAM 계정이 직접 AWS 리소스를 이용한 기록: {'O' if iam_direct_access else 'X'}\n"
        f"태그가 없는 계정: {', '.join(users_without_tags)}"
    )

def send_discord_notification(message):
    # 디스코드 웹훅 URL과 채널을 설정하여 알림 전송
    import requests
    discord_webhook_url = 'https://discord.com/api/webhooks/1198931990494322758/8CXXpAz9iWa5jKZ_0CJc0jtekrwj1Hf5rTS60t7wzkivwRek-sCJVdX2rLCgoz__UuJQ'
    headers = {'Content-Type': 'application/json'}
    payload = {'content': message}
    response = requests.post(discord_webhook_url, headers=headers, json=payload)
    print(response.text)