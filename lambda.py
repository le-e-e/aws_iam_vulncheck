import boto3
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # AWS 서비스 객체 생성
    iam = boto3.client('iam')
    cloudtrail = boto3.client('cloudtrail')
    sts = boto3.client('sts')

    # 현재 날짜
    today = datetime.now().date()

    # 1. ROOT 계정에 Access key ID / Secret access key를 발급한 이력이 있는가?
    try:
        # CloudTrail로 ROOT의 access key 생성 이력 확인
        root_key_events = cloudtrail.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'CreateAccessKey'}],
            MaxResults=50
        )['Events']
        access_key_result = 'X'
        for event in root_key_events:
            if 'root' in str(event.get('Username', '')).lower():
                access_key_result = 'O'
                break
    except:
        access_key_result = 'X'

    # 2. ROOT 계정 사용 이력이 있는가?
    try:
        events = cloudtrail.lookup_events(
            LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': 'root'}],
            MaxResults=50
        )['Events']
        root_usage_result = 'O' if events else 'X'
    except:
        root_usage_result = 'X'

    # 3. 30일 이상 사용하지 않은 Access key가 있는가?
    inactive_keys = []
    all_users = iam.list_users()['Users']
    for user in all_users:
        try:
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in access_keys:
                try:
                    # get_access_key_last_used로 마지막 사용 시간 확인
                    last_used_info = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    last_used = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    
                    if last_used:
                        if (today - last_used.date()) > timedelta(days=30):
                            inactive_keys.append(f"{user['UserName']}({key['AccessKeyId']})")
                    else:
                        # 한 번도 사용하지 않은 키도 생성일로 확인
                        create_date = key.get('CreateDate')
                        if create_date and (today - create_date.date()) > timedelta(days=30):
                            inactive_keys.append(f"{user['UserName']}({key['AccessKeyId']})")
                except:
                    pass
        except:
            pass

    # 4. Access key 변경 주기를 지정하지 않고, 주기적으로 Access key를 변경하지 않은 경우
    no_rotation_keys = []
    for user in all_users:
        try:
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in access_keys:
                create_date = key.get('CreateDate')
                # 90일 이상 된 Access key 검출
                if create_date and (today - create_date.date()) > timedelta(days=90):
                    no_rotation_keys.append(f"{user['UserName']}({key['AccessKeyId']})")
        except:
            pass

    # 5. IAM 계정에 직접 권한을 부여한 경우
    users_with_direct_policy = []
    for user in all_users:
        try:
            groups = iam.list_groups_for_user(UserName=user['UserName'])['Groups']
            # 직접 연결된 정책 확인
            attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
            
            # 그룹에 속하지 않거나, 직접 정책이 연결된 경우
            if not groups or attached_policies or inline_policies:
                users_with_direct_policy.append(user['UserName'])
        except:
            pass

    # 6. 영문ㆍ숫자ㆍ특수문자 중 2종류 10자리 이상 OR 3종류 8자리 이상으로 비밀번호를 구성하지 않거나,
    #    분기별 1회 이상 비밀번호를 변경하지 않은 경우
    non_compliant_passwords = []
    try:
        password_policy = iam.get_account_password_policy()['PasswordPolicy']
        min_length = password_policy.get('MinimumPasswordLength', 0)
        require_symbols = password_policy.get('RequireSymbols', False)
        require_numbers = password_policy.get('RequireNumbers', False)
        require_uppercase = password_policy.get('RequireUppercaseCharacters', False)
        require_lowercase = password_policy.get('RequireLowercaseCharacters', False)
        max_password_age = password_policy.get('MaxPasswordAge', None)
        
        # 복잡도 검증: (2종류 10자 이상) OR (3종류 8자 이상)
        char_types = sum([require_symbols, require_numbers, require_uppercase or require_lowercase])
        policy_compliant = (char_types >= 2 and min_length >= 10) or (char_types >= 3 and min_length >= 8)
        
        # 분기별 변경: 90일 이하
        age_compliant = max_password_age and max_password_age <= 90
        
        for user in all_users:
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
                password_last_used = user.get('PasswordLastUsed')
                
                # 정책 미준수 또는 비밀번호 나이 미준수
                if not policy_compliant or not age_compliant:
                    non_compliant_passwords.append(user['UserName'])
            except ClientError as e:
                # NoSuchEntity: 콘솔 로그인이 없는 사용자는 제외
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    pass
    except:
        # 계정 비밀번호 정책이 없는 경우
        for user in all_users:
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
                non_compliant_passwords.append(user['UserName'])
            except:
                pass

    # 7. IAM 계정 관리 Life-Cycle을 수립하지 않은 경우 (90일 이상 미사용 계정)
    no_lifecycle_users = []
    for user in all_users:
        try:
            password_last_used = user.get('PasswordLastUsed')
            
            # Access key 마지막 사용 확인
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            key_last_used = None
            for key in access_keys:
                try:
                    last_used_info = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    last_used = last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    if last_used:
                        if not key_last_used or last_used > key_last_used:
                            key_last_used = last_used
                except:
                    pass
            
            # 비밀번호와 Access key 모두 90일 이상 미사용
            latest_activity = None
            if password_last_used:
                latest_activity = password_last_used.date() if hasattr(password_last_used, 'date') else password_last_used
            if key_last_used:
                key_date = key_last_used.date() if hasattr(key_last_used, 'date') else key_last_used
                if not latest_activity or key_date > latest_activity:
                    latest_activity = key_date
            
            if not latest_activity:
                # 생성 후 한 번도 사용 안한 경우
                create_date = user.get('CreateDate')
                if create_date:
                    latest_activity = create_date.date() if hasattr(create_date, 'date') else create_date
            
            if latest_activity and (today - latest_activity) > timedelta(days=90):
                no_lifecycle_users.append(user['UserName'])
        except:
            pass

    # 8. STS를 활용하지 않고 IAM 계정 또는 그룹에 직접 권한을 부여하여 AWS 리소스를 핸들링 하는 경우
    try:
        # IAM User가 직접 API를 호출한 이벤트 확인 (STS AssumeRole 사용하지 않은 경우)
        all_events = cloudtrail.lookup_events(MaxResults=50)['Events']
        iam_direct_access_events = []
        for event in all_events:
            try:
                user_identity = event.get('Username', '')
                # root나 IAMUser가 직접 호출한 경우 (AssumeRole이 아닌)
                if user_identity and user_identity != 'root' and event.get('EventName') != 'AssumeRole':
                    iam_direct_access_events.append(user_identity)
            except:
                pass
        iam_direct_access = 'O' if iam_direct_access_events else 'X'
    except:
        iam_direct_access = 'X'

    # 9. 어떠한 태그도 설정되어있지 않은 IAM 계정이 있는가?
    users_without_tags = []
    for user in all_users:
        try:
            tags = iam.list_user_tags(UserName=user['UserName'])['Tags']
            if not tags:
                users_without_tags.append(user['UserName'])
        except:
            pass

    # 10. MFA가 설정되지 않은 IAM 계정이 있는가?
    users_without_mfa = []
    for user in all_users:
        try:
            mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            # 콘솔 로그인이 가능한 사용자인지 확인
            try:
                iam.get_login_profile(UserName=user['UserName'])
                # 콘솔 로그인 가능하지만 MFA가 없는 경우
                if not mfa_devices:
                    users_without_mfa.append(user['UserName'])
            except ClientError as e:
                # 콘솔 로그인이 없는 사용자는 제외
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    pass
        except:
            pass

    # 결과 데이터 구조화
    results_data = {
        'access_key_result': access_key_result,
        'root_usage_result': root_usage_result,
        'inactive_keys': inactive_keys,
        'no_rotation_keys': no_rotation_keys,
        'users_with_direct_policy': users_with_direct_policy,
        'non_compliant_passwords': non_compliant_passwords,
        'no_lifecycle_users': no_lifecycle_users,
        'iam_direct_access': iam_direct_access,
        'users_without_tags': users_without_tags,
        'users_without_mfa': users_without_mfa
    }
    
    # 콘솔 출력
    print(f"1. ROOT 계정 Access key ID/Secret access key 발급여부: {access_key_result}")
    print(f"2. ROOT 계정 사용 이력: {root_usage_result}")
    print(f"3. 30일 이상 미사용 Access key: {', '.join(inactive_keys) if inactive_keys else 'X'}")
    print(f"4. Access key 변경 주기 미지정 또는 주기적 변경하지 않은 계정: {', '.join(no_rotation_keys) if no_rotation_keys else 'X'}")
    print(f"5. IAM 계정에 직접 권한을 부여한 계정: {', '.join(users_with_direct_policy) if users_with_direct_policy else 'X'}")
    print(f"6. 비밀번호 정책 위배 계정: {', '.join(non_compliant_passwords) if non_compliant_passwords else 'X'}")
    print(f"7. IAM 계정 관리 Life-Cycle 미수립 (90일 이상 미사용): {', '.join(no_lifecycle_users) if no_lifecycle_users else 'X'}")
    print(f"8. STS 미사용 IAM 계정의 직접 리소스 핸들링: {iam_direct_access}")
    print(f"9. 태그가 없는 계정: {', '.join(users_without_tags) if users_without_tags else 'X'}")
    print(f"10. MFA 미설정 계정: {', '.join(users_without_mfa) if users_without_mfa else 'X'}")
    
    # Discord 임베드 알림 전송
    send_discord_notification(results_data)
    
    # 이메일 보고서 전송 (선택사항 - 환경 변수로 이메일 주소 지정)
    import os
    recipient_email = os.environ.get('RECIPIENT_EMAIL')
    if recipient_email:
        send_email_report(results_data, recipient_email)
    
    return {
        'statusCode': 200,
        'body': results_data
    }

def send_discord_notification(results_data):
    """Discord 임베드 메시지로 가시성 높은 보고서 전송"""
    import requests
    from datetime import datetime
    
    discord_webhook_url = 'https://discord.com/api/webhooks/1433667978322382879/dHVQCRzingJGjAKpGHG-kc5HXF4-Bg75yavSyCGk5_CR0szjBBIqbmmPAuqPbMtuNOHs'
    
    # 취약점 개수 계산
    vulnerable_count = sum([
        1 if results_data['access_key_result'] == 'O' else 0,
        1 if results_data['root_usage_result'] == 'O' else 0,
        1 if results_data['inactive_keys'] else 0,
        1 if results_data['no_rotation_keys'] else 0,
        1 if results_data['users_with_direct_policy'] else 0,
        1 if results_data['non_compliant_passwords'] else 0,
        1 if results_data['no_lifecycle_users'] else 0,
        1 if results_data['iam_direct_access'] == 'O' else 0,
        1 if results_data['users_without_tags'] else 0,
        1 if results_data['users_without_mfa'] else 0,
    ])
    
    # 색상 결정 (취약점 개수에 따라)
    if vulnerable_count == 0:
        color = 0x00FF00  # 녹색 - 안전
    elif vulnerable_count <= 3:
        color = 0xFFFF00  # 노란색 - 경고
    else:
        color = 0xFF0000  # 빨간색 - 위험
    
    # Discord Embed 메시지 구성
    embed = {
        "title": "AWS IAM 보안 취약점 진단 보고서",
        "description": f"**진단 시간**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**발견된 취약점**: {vulnerable_count}/10개",
        "color": color,
        "fields": [
            {
                "name": "[1] ROOT 계정 Access Key 발급",
                "value": f"{'[취약]' if results_data['access_key_result'] == 'O' else '[양호]'}",
                "inline": True
            },
            {
                "name": "[2] ROOT 계정 사용 이력",
                "value": f"{'[취약]' if results_data['root_usage_result'] == 'O' else '[양호]'}",
                "inline": True
            },
            {
                "name": "[3] 30일 미사용 Access Key",
                "value": f"{'[취약] ' + str(len(results_data['inactive_keys'])) + '개' if results_data['inactive_keys'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[4] Access Key 미변경 (90일+)",
                "value": f"{'[취약] ' + str(len(results_data['no_rotation_keys'])) + '개' if results_data['no_rotation_keys'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[5] 직접 권한 부여 계정",
                "value": f"{'[취약] ' + str(len(results_data['users_with_direct_policy'])) + '개' if results_data['users_with_direct_policy'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[6] 비밀번호 정책 위배",
                "value": f"{'[취약] ' + str(len(results_data['non_compliant_passwords'])) + '개' if results_data['non_compliant_passwords'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[7] Life-Cycle 미수립 (90일)",
                "value": f"{'[취약] ' + str(len(results_data['no_lifecycle_users'])) + '개' if results_data['no_lifecycle_users'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[8] STS 미사용 직접 핸들링",
                "value": f"{'[권고]' if results_data['iam_direct_access'] == 'O' else '[양호]'}",
                "inline": True
            },
            {
                "name": "[9] 태그 미설정 계정",
                "value": f"{'[권고] ' + str(len(results_data['users_without_tags'])) + '개' if results_data['users_without_tags'] else '[양호]'}",
                "inline": True
            },
            {
                "name": "[10] MFA 미설정 계정",
                "value": f"{'[취약] ' + str(len(results_data['users_without_mfa'])) + '개' if results_data['users_without_mfa'] else '[양호]'}",
                "inline": True
            }
        ],
        "footer": {
            "text": "AWS IAM Vulnerability Check"
        },
        "timestamp": datetime.now().isoformat()
    }
    
    # 상세 정보 추가 (취약한 항목만)
    details = []
    if results_data['inactive_keys']:
        details.append(f"**30일 미사용 Key**: {', '.join(results_data['inactive_keys'][:5])}" + 
                      (f" 외 {len(results_data['inactive_keys'])-5}개" if len(results_data['inactive_keys']) > 5 else ""))
    if results_data['no_rotation_keys']:
        details.append(f"**미변경 Key**: {', '.join(results_data['no_rotation_keys'][:5])}" + 
                      (f" 외 {len(results_data['no_rotation_keys'])-5}개" if len(results_data['no_rotation_keys']) > 5 else ""))
    if results_data['users_with_direct_policy']:
        details.append(f"**직접 권한 계정**: {', '.join(results_data['users_with_direct_policy'][:5])}" + 
                      (f" 외 {len(results_data['users_with_direct_policy'])-5}개" if len(results_data['users_with_direct_policy']) > 5 else ""))
    if results_data['non_compliant_passwords']:
        details.append(f"**비밀번호 위배**: {', '.join(results_data['non_compliant_passwords'][:5])}" + 
                      (f" 외 {len(results_data['non_compliant_passwords'])-5}개" if len(results_data['non_compliant_passwords']) > 5 else ""))
    if results_data['users_without_mfa']:
        details.append(f"**MFA 미설정**: {', '.join(results_data['users_without_mfa'][:5])}" + 
                      (f" 외 {len(results_data['users_without_mfa'])-5}개" if len(results_data['users_without_mfa']) > 5 else ""))
    
    if details:
        embed["fields"].append({
            "name": "상세 내역",
            "value": "\n".join(details[:5]),  # 최대 5개만 표시
            "inline": False
        })
    
    payload = {"embeds": [embed]}
    
    try:
        response = requests.post(discord_webhook_url, json=payload)
        print(f"Discord 알림 전송: {response.status_code}")
    except Exception as e:
        print(f"Discord 알림 전송 실패: {str(e)}")


def send_email_report(results_data, recipient_email):
    """AWS SES를 사용하여 HTML 보고서를 이메일로 전송"""
    import boto3
    from datetime import datetime
    
    ses = boto3.client('ses', region_name='us-east-1')  # SES 리전 설정
    
    # HTML 이메일 본문 생성
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; }}
            .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .summary-item {{ display: inline-block; margin: 10px 20px; text-align: center; }}
            .summary-number {{ font-size: 36px; font-weight: bold; color: #667eea; }}
            .summary-label {{ font-size: 14px; color: #666; }}
            .section {{ margin: 25px 0; }}
            .check-item {{ background: white; border-left: 4px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .check-item.vulnerable {{ border-left-color: #dc3545; background: #fff5f5; }}
            .check-item.warning {{ border-left-color: #ffc107; background: #fffbf0; }}
            .check-item.safe {{ border-left-color: #28a745; background: #f0fff4; }}
            .check-title {{ font-weight: bold; font-size: 16px; margin-bottom: 8px; }}
            .status {{ display: inline-block; padding: 5px 12px; border-radius: 15px; font-size: 12px; font-weight: bold; }}
            .status.vulnerable {{ background: #dc3545; color: white; }}
            .status.warning {{ background: #ffc107; color: #333; }}
            .status.safe {{ background: #28a745; color: white; }}
            .details {{ font-size: 14px; color: #666; margin-top: 8px; }}
            .footer {{ text-align: center; padding: 20px; color: #999; font-size: 12px; border-top: 1px solid #eee; margin-top: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #667eea; color: white; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>AWS IAM 보안 취약점 진단 보고서</h1>
            <p>진단 시간: {datetime.now().strftime('%Y년 %m월 %d일 %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number">{sum([
                    1 if results_data['access_key_result'] == 'O' else 0,
                    1 if results_data['root_usage_result'] == 'O' else 0,
                    1 if results_data['inactive_keys'] else 0,
                    1 if results_data['no_rotation_keys'] else 0,
                    1 if results_data['users_with_direct_policy'] else 0,
                    1 if results_data['non_compliant_passwords'] else 0,
                    1 if results_data['no_lifecycle_users'] else 0,
                    1 if results_data['iam_direct_access'] == 'O' else 0,
                    1 if results_data['users_without_tags'] else 0,
                    1 if results_data['users_without_mfa'] else 0,
                ])}</div>
                <div class="summary-label">발견된 취약점</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">10</div>
                <div class="summary-label">전체 점검 항목</div>
            </div>
        </div>
        
        <div class="section">
            <h2>상세 진단 결과</h2>
            
            <div class="check-item {'vulnerable' if results_data['access_key_result'] == 'O' else 'safe'}">
                <div class="check-title">
                    1. ROOT 계정 Access Key 발급 여부
                    <span class="status {'vulnerable' if results_data['access_key_result'] == 'O' else 'safe'}">
                        {'취약' if results_data['access_key_result'] == 'O' else '양호'}
                    </span>
                </div>
                <div class="details">
                    ROOT 계정에 Access Key가 발급되어 있으면 보안상 매우 위험합니다.
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['root_usage_result'] == 'O' else 'safe'}">
                <div class="check-title">
                    2. ROOT 계정 사용 이력
                    <span class="status {'vulnerable' if results_data['root_usage_result'] == 'O' else 'safe'}">
                        {'취약' if results_data['root_usage_result'] == 'O' else '양호'}
                    </span>
                </div>
                <div class="details">
                    ROOT 계정은 긴급한 경우를 제외하고 사용하지 않는 것을 권장합니다.
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['inactive_keys'] else 'safe'}">
                <div class="check-title">
                    3. 30일 이상 미사용 Access Key
                    <span class="status {'vulnerable' if results_data['inactive_keys'] else 'safe'}">
                        {'취약 (' + str(len(results_data['inactive_keys'])) + '개)' if results_data['inactive_keys'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join(results_data['inactive_keys'][:10]) if results_data['inactive_keys'] else '미사용 키가 없습니다.'}
                    {'...' if len(results_data['inactive_keys']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['no_rotation_keys'] else 'safe'}">
                <div class="check-title">
                    4. Access Key 변경 주기 미준수 (90일 이상)
                    <span class="status {'vulnerable' if results_data['no_rotation_keys'] else 'safe'}">
                        {'취약 (' + str(len(results_data['no_rotation_keys'])) + '개)' if results_data['no_rotation_keys'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join(results_data['no_rotation_keys'][:10]) if results_data['no_rotation_keys'] else 'Access Key가 주기적으로 변경되고 있습니다.'}
                    {'...' if len(results_data['no_rotation_keys']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['users_with_direct_policy'] else 'safe'}">
                <div class="check-title">
                    5. IAM 계정 직접 권한 부여
                    <span class="status {'vulnerable' if results_data['users_with_direct_policy'] else 'safe'}">
                        {'취약 (' + str(len(results_data['users_with_direct_policy'])) + '개)' if results_data['users_with_direct_policy'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join(results_data['users_with_direct_policy'][:10]) if results_data['users_with_direct_policy'] else '모든 계정이 그룹을 통해 권한을 부여받고 있습니다.'}
                    {'...' if len(results_data['users_with_direct_policy']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['non_compliant_passwords'] else 'safe'}">
                <div class="check-title">
                    6. 비밀번호 정책 위배
                    <span class="status {'vulnerable' if results_data['non_compliant_passwords'] else 'safe'}">
                        {'취약 (' + str(len(results_data['non_compliant_passwords'])) + '개)' if results_data['non_compliant_passwords'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    권장: 2종류 조합 10자 이상 또는 3종류 조합 8자 이상, 90일마다 변경
                    <br>{', '.join(results_data['non_compliant_passwords'][:10]) if results_data['non_compliant_passwords'] else '비밀번호 정책이 준수되고 있습니다.'}
                    {'...' if len(results_data['non_compliant_passwords']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['no_lifecycle_users'] else 'safe'}">
                <div class="check-title">
                    7. IAM Life-Cycle 미수립 (90일 미사용)
                    <span class="status {'vulnerable' if results_data['no_lifecycle_users'] else 'safe'}">
                        {'취약 (' + str(len(results_data['no_lifecycle_users'])) + '개)' if results_data['no_lifecycle_users'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join(results_data['no_lifecycle_users'][:10]) if results_data['no_lifecycle_users'] else '모든 계정이 활발히 사용되고 있습니다.'}
                    {'...' if len(results_data['no_lifecycle_users']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'warning' if results_data['iam_direct_access'] == 'O' else 'safe'}">
                <div class="check-title">
                    8. STS 미사용 직접 리소스 핸들링 (권고사항)
                    <span class="status {'warning' if results_data['iam_direct_access'] == 'O' else 'safe'}">
                        {'권고' if results_data['iam_direct_access'] == 'O' else '양호'}
                    </span>
                </div>
                <div class="details">
                    STS(Temporary Credentials) 사용을 권장합니다.
                </div>
            </div>
            
            <div class="check-item {'warning' if results_data['users_without_tags'] else 'safe'}">
                <div class="check-title">
                    9. 태그 미설정 계정 (권고사항)
                    <span class="status {'warning' if results_data['users_without_tags'] else 'safe'}">
                        {'권고 (' + str(len(results_data['users_without_tags'])) + '개)' if results_data['users_without_tags'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join(results_data['users_without_tags'][:10]) if results_data['users_without_tags'] else '모든 계정에 태그가 설정되어 있습니다.'}
                    {'...' if len(results_data['users_without_tags']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['users_without_mfa'] else 'safe'}">
                <div class="check-title">
                    10. MFA 미설정 계정
                    <span class="status {'vulnerable' if results_data['users_without_mfa'] else 'safe'}">
                        {'취약 (' + str(len(results_data['users_without_mfa'])) + '개)' if results_data['users_without_mfa'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    콘솔 로그인 가능한 계정의 MFA 설정을 권장합니다.
                    <br>{', '.join(results_data['users_without_mfa'][:10]) if results_data['users_without_mfa'] else '모든 계정에 MFA가 설정되어 있습니다.'}
                    {'...' if len(results_data['users_without_mfa']) > 10 else ''}
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>이 보고서는 AWS Lambda를 통해 자동 생성되었습니다.</p>
            <p>문의사항이 있으시면 보안팀에 연락해주세요.</p>
        </div>
    </body>
    </html>
    """
    
    try:
        response = ses.send_email(
            Source='noreply@yourdomain.com',  # 발신자 이메일 (SES에서 인증된 이메일)
            Destination={'ToAddresses': [recipient_email]},
            Message={
                'Subject': {
                    'Data': f'[AWS IAM 보안진단] {datetime.now().strftime("%Y-%m-%d")} 보고서',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        print(f"이메일 전송 성공: {response['MessageId']}")
        return True
    except Exception as e:
        print(f"이메일 전송 실패: {str(e)}")
        return False