import boto3
import os
import requests
from datetime import datetime, timedelta
from botocore.exceptions import ClientError


DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
RECIPIENT_EMAIL = os.environ.get('RECIPIENT_EMAIL', '')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', '')

def lambda_handler(event, context):
    # AWS 서비스 객체 생성
    iam = boto3.client('iam')
    cloudtrail = boto3.client('cloudtrail')
    sts = boto3.client('sts')

    # 현재 날짜
    today = datetime.now().date()

    # 1. ROOT 계정에 Access key ID / Secret access key를 발급한 이력이 있는가?
    access_key_result = 'X'
    try:
        # Account Summary로 ROOT access key 확인
        account_summary = iam.get_account_summary()['SummaryMap']
        # AccountAccessKeysPresent가 1이면 ROOT에 Access Key가 있음
        if account_summary.get('AccountAccessKeysPresent', 0) > 0:
            access_key_result = 'O'
    except:
        # Account Summary 실패 시 CloudTrail 이벤트로 확인
        try:
            root_key_events = cloudtrail.lookup_events(
                LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'CreateAccessKey'}],
                MaxResults=50
            )['Events']
            for event in root_key_events:
                if 'root' in str(event.get('Username', '')).lower():
                    access_key_result = 'O'
                    break
        except:
            pass

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
                    create_date = key.get('CreateDate')
                    
                    if last_used:
                        days_unused = (today - last_used.date()).days
                        if days_unused > 30:
                            inactive_keys.append({
                                'user': user['UserName'],
                                'key_id': key['AccessKeyId'],
                                'created': create_date.strftime('%Y-%m-%d') if create_date else 'N/A',
                                'last_used': last_used.strftime('%Y-%m-%d'),
                                'days_unused': days_unused
                            })
                    else:
                        # 한 번도 사용하지 않은 키도 생성일로 확인
                        if create_date:
                            days_since_creation = (today - create_date.date()).days
                            if days_since_creation > 30:
                                inactive_keys.append({
                                    'user': user['UserName'],
                                    'key_id': key['AccessKeyId'],
                                    'created': create_date.strftime('%Y-%m-%d'),
                                    'last_used': '사용 이력 없음',
                                    'days_unused': days_since_creation
                                })
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
                if create_date:
                    days_old = (today - create_date.date()).days
                    if days_old > 90:
                        no_rotation_keys.append({
                            'user': user['UserName'],
                            'key_id': key['AccessKeyId'],
                            'created': create_date.strftime('%Y-%m-%d'),
                            'age_days': days_old,
                            'status': key.get('Status', 'Unknown')
                        })
        except:
            pass

    # 5. IAM 계정에 직접 권한을 부여한 경우
    users_with_direct_policy = []
    for user in all_users:
        try:
            # 직접 연결된 정책 확인 (Managed Policy + Inline Policy)
            attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
            
            # 직접 정책이 하나라도 연결되어 있으면 취약
            if attached_policies or inline_policies:
                managed_names = [p['PolicyName'] for p in attached_policies]
                all_policies = managed_names + list(inline_policies)
                
                users_with_direct_policy.append({
                    'user': user['UserName'],
                    'managed_policies': managed_names,
                    'inline_policies': list(inline_policies),
                    'total_count': len(all_policies)
                })
        except:
            pass

    # 6. 영문ㆍ숫자ㆍ특수문자 중 2종류 10자리 이상 OR 3종류 8자리 이상으로 비밀번호를 구성하지 않거나,
    #    분기별 1회 이상 비밀번호를 변경하지 않은 경우
    non_compliant_passwords = []
    password_policy_info = None
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
        
        password_policy_info = {
            'min_length': min_length,
            'char_types': char_types,
            'max_age': max_password_age if max_password_age else '무제한',
            'policy_compliant': policy_compliant,
            'age_compliant': age_compliant
        }
        
        for user in all_users:
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
                password_last_used = user.get('PasswordLastUsed')
                create_date = login_profile.get('CreateDate')
                
                # 비밀번호 나이 계산
                password_age = None
                if password_last_used:
                    password_age = (today - password_last_used.date()).days
                elif create_date:
                    password_age = (today - create_date.date()).days
                
                # 정책 미준수 또는 비밀번호 나이 미준수
                issues = []
                if not policy_compliant:
                    issues.append(f"정책 미준수(최소 {min_length}자/{char_types}종류)")
                if not age_compliant:
                    issues.append(f"변경주기 미설정")
                if password_age and password_age > 90:
                    issues.append(f"{password_age}일 미변경")
                
                if issues:
                    non_compliant_passwords.append({
                        'user': user['UserName'],
                        'password_age': password_age if password_age else 'N/A',
                        'last_used': password_last_used.strftime('%Y-%m-%d') if password_last_used else 'N/A',
                        'issues': ', '.join(issues)
                    })
            except ClientError as e:
                # NoSuchEntity: 콘솔 로그인이 없는 사용자는 제외
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    pass
    except:
        # 계정 비밀번호 정책이 없는 경우
        password_policy_info = {'error': '비밀번호 정책 미설정'}
        for user in all_users:
            try:
                login_profile = iam.get_login_profile(UserName=user['UserName'])
                non_compliant_passwords.append({
                    'user': user['UserName'],
                    'password_age': 'N/A',
                    'last_used': 'N/A',
                    'issues': '계정 비밀번호 정책 없음'
                })
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
            activity_type = None
            if password_last_used:
                latest_activity = password_last_used.date() if hasattr(password_last_used, 'date') else password_last_used
                activity_type = '콘솔 로그인'
            if key_last_used:
                key_date = key_last_used.date() if hasattr(key_last_used, 'date') else key_last_used
                if not latest_activity or key_date > latest_activity:
                    latest_activity = key_date
                    activity_type = 'Access Key 사용'
            
            if not latest_activity:
                # 생성 후 한 번도 사용 안한 경우
                create_date = user.get('CreateDate')
                if create_date:
                    latest_activity = create_date.date() if hasattr(create_date, 'date') else create_date
                    activity_type = '생성일 (사용 이력 없음)'
            
            if latest_activity:
                days_inactive = (today - latest_activity).days
                if days_inactive > 90:
                    no_lifecycle_users.append({
                        'user': user['UserName'],
                        'last_activity': latest_activity.strftime('%Y-%m-%d'),
                        'days_inactive': days_inactive,
                        'activity_type': activity_type
                    })
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
    users_with_mfa = []
    for user in all_users:
        username = user['UserName']
        has_console_access = False
        
        # 콘솔 로그인 가능 여부 확인
        try:
            iam.get_login_profile(UserName=username)
            has_console_access = True
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                has_console_access = False
            else:
                # 다른 에러는 무시
                pass
        except Exception:
            pass
        
        # 콘솔 접근 가능한 사용자만 MFA 체크
        if has_console_access:
            try:
                mfa_response = iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get('MFADevices', [])
                
                if len(mfa_devices) > 0:
                    users_with_mfa.append(username)
                else:
                    users_without_mfa.append(username)
            except ClientError as e:
                # MFA 조회 실패는 MFA 없는 것으로 처리
                users_without_mfa.append(username)
            except Exception:
                users_without_mfa.append(username)

    # 11. 미사용/유휴 Role·User 탐지 (90~180일)
    idle_roles = []
    idle_users_extended = []  # 90~180일 유휴 사용자
    
    # Role 검색
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            role_name = role['RoleName']
            try:
                # Role 마지막 사용 시간
                role_last_used = role.get('RoleLastUsed', {})
                last_used_date = role_last_used.get('LastUsedDate')
                
                if last_used_date:
                    days_unused = (today - last_used_date.date()).days
                    if 90 <= days_unused <= 180:
                        idle_roles.append({
                            'role': role_name,
                            'last_used': last_used_date.strftime('%Y-%m-%d'),
                            'days_unused': days_unused,
                            'path': role.get('Path', '/')
                        })
                else:
                    # 한 번도 사용된 적 없는 Role
                    create_date = role.get('CreateDate')
                    if create_date:
                        days_since_creation = (today - create_date.date()).days
                        if days_since_creation >= 90:
                            idle_roles.append({
                                'role': role_name,
                                'last_used': '사용 이력 없음',
                                'days_unused': days_since_creation,
                                'path': role.get('Path', '/')
                            })
            except:
                pass
    except:
        pass
    
    # User 90~180일 유휴 체크
    for user_data in no_lifecycle_users:
        if 90 <= user_data['days_inactive'] <= 180:
            idle_users_extended.append(user_data)

    # 12. 과도한 권한 탐지 (wildcard, iam:PassRole)
    excessive_permissions = []
    
    # 모든 사용자의 정책 검사
    for user in all_users:
        try:
            username = user['UserName']
            issues = []
            
            # Managed Policy 검사
            attached_policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                try:
                    policy_version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                    policy_document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                    
                    if isinstance(policy_document, str):
                        import json
                        policy_document = json.loads(policy_document)
                    
                    for statement in policy_document.get('Statement', []):
                        if isinstance(statement, dict) and statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if not isinstance(actions, list):
                                actions = [actions]
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            if '*' in actions:
                                issues.append(f"{policy['PolicyName']}: Action '*'")
                            if '*' in resources:
                                issues.append(f"{policy['PolicyName']}: Resource '*'")
                            if 'iam:PassRole' in actions and '*' in resources:
                                issues.append(f"{policy['PolicyName']}: iam:PassRole with '*'")
                except:
                    pass
            
            # Inline Policy 검사
            inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline_policies:
                try:
                    policy_document = iam.get_user_policy(UserName=username, PolicyName=policy_name)['PolicyDocument']
                    
                    if isinstance(policy_document, str):
                        import json
                        policy_document = json.loads(policy_document)
                    
                    for statement in policy_document.get('Statement', []):
                        if isinstance(statement, dict) and statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if not isinstance(actions, list):
                                actions = [actions]
                            if not isinstance(resources, list):
                                resources = [resources]
                            
                            if '*' in actions:
                                issues.append(f"{policy_name}(인라인): Action '*'")
                            if '*' in resources:
                                issues.append(f"{policy_name}(인라인): Resource '*'")
                            if 'iam:PassRole' in actions and '*' in resources:
                                issues.append(f"{policy_name}(인라인): iam:PassRole with '*'")
                except:
                    pass
            
            if issues:
                excessive_permissions.append({
                    'user': username,
                    'issues': issues,
                    'issue_count': len(issues)
                })
        except:
            pass
    
    # Role의 과도한 권한도 체크
    try:
        roles = iam.list_roles()['Roles']
        for role in roles[:50]:  # 너무 많을 수 있으므로 상위 50개만
            role_name = role['RoleName']
            try:
                issues = []
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                
                for policy in attached_policies:
                    policy_arn = policy['PolicyArn']
                    try:
                        policy_version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                        policy_document = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                        
                        if isinstance(policy_document, str):
                            import json
                            policy_document = json.loads(policy_document)
                        
                        for statement in policy_document.get('Statement', []):
                            if isinstance(statement, dict) and statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                resources = statement.get('Resource', [])
                                
                                if not isinstance(actions, list):
                                    actions = [actions]
                                if not isinstance(resources, list):
                                    resources = [resources]
                                
                                if '*' in actions:
                                    issues.append(f"{policy['PolicyName']}: Action '*'")
                                if '*' in resources:
                                    issues.append(f"{policy['PolicyName']}: Resource '*'")
                                if 'iam:PassRole' in actions and '*' in resources:
                                    issues.append(f"{policy['PolicyName']}: iam:PassRole with '*'")
                    except:
                        pass
                
                if issues:
                    excessive_permissions.append({
                        'role': role_name,
                        'issues': issues,
                        'issue_count': len(issues)
                    })
            except:
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
        'password_policy_info': password_policy_info,
        'no_lifecycle_users': no_lifecycle_users,
        'iam_direct_access': iam_direct_access,
        'users_without_tags': users_without_tags,
        'users_without_mfa': users_without_mfa,
        'idle_roles': idle_roles,
        'idle_users_extended': idle_users_extended,
        'excessive_permissions': excessive_permissions
    }
    
    # 콘솔 출력
    print("\n" + "="*80)
    print("AWS IAM 보안 취약점 진단 보고서")
    print("="*80)
    print(f"진단 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    # 취약점 개수 재계산
    critical_count = sum([
        1 if access_key_result == 'O' else 0,
        1 if root_usage_result == 'O' else 0,
        1 if inactive_keys else 0,
        1 if no_rotation_keys else 0,
        1 if users_with_direct_policy else 0,
        1 if non_compliant_passwords else 0,
        1 if no_lifecycle_users else 0,
        1 if users_without_mfa else 0,
        1 if excessive_permissions else 0,  # 과도한 권한은 위험
    ])
    warning_count = sum([
        1 if iam_direct_access == 'O' else 0,
        1 if users_without_tags else 0,
        1 if idle_roles or idle_users_extended else 0,  # 유휴 계정은 권고
    ])
    print(f"발견된 취약점: {critical_count}개 (위험) / {warning_count}개 (권고) / 총 12개 항목")
    print("="*80)
    
    print("\n[1] ROOT 계정 Access Key 발급")
    if access_key_result == 'O':
        print("    [취약] CloudTrail에서 ROOT Access Key 생성 이력 확인됨")
    else:
        print("    [양호] ROOT Access Key 생성 이력 없음")
    
    print("\n[2] ROOT 계정 사용 이력")
    if root_usage_result == 'O':
        print("    [취약] 최근 ROOT 계정 사용 이력 발견")
    else:
        print("    [양호] ROOT 계정 사용 이력 없음")
    
    print("\n[3] 30일 미사용 Access Key")
    if inactive_keys:
        print(f"    [취약] {len(inactive_keys)}개 발견")
        for key in inactive_keys[:5]:
            print(f"      - {key['user']}/{key['key_id']}: {key['days_unused']}일 미사용 (마지막 사용: {key['last_used']})")
        if len(inactive_keys) > 5:
            print(f"      ... 외 {len(inactive_keys)-5}개")
    else:
        print("    [양호] 모든 Access Key가 최근 30일 이내 사용됨")
    
    print("\n[4] Access Key 미변경 90일 이상")
    if no_rotation_keys:
        print(f"    [취약] {len(no_rotation_keys)}개 발견")
        for key in no_rotation_keys[:5]:
            print(f"      - {key['user']}/{key['key_id']}: {key['age_days']}일 경과 (생성일: {key['created']})")
        if len(no_rotation_keys) > 5:
            print(f"      ... 외 {len(no_rotation_keys)-5}개")
    else:
        print("    [양호] 모든 Access Key가 90일 이내 갱신됨")
    
    print("\n[5] 직접 권한 부여 계정")
    if users_with_direct_policy:
        print(f"    [취약] {len(users_with_direct_policy)}명 발견")
        for user_data in users_with_direct_policy[:5]:
            policies = []
            if user_data['managed_policies']:
                policies.extend([f"{p}(Managed)" for p in user_data['managed_policies']])
            if user_data['inline_policies']:
                policies.extend([f"{p}(Inline)" for p in user_data['inline_policies']])
            print(f"      - {user_data['user']}: {', '.join(policies[:3])}")
            if len(policies) > 3:
                print(f"        ... 외 {len(policies)-3}개 정책")
        if len(users_with_direct_policy) > 5:
            print(f"      ... 외 {len(users_with_direct_policy)-5}명")
    else:
        print("    [양호] 모든 계정이 그룹을 통해 권한 부여받음")
    
    print("\n[6] 비밀번호 정책 위배")
    if password_policy_info and 'error' not in password_policy_info:
        print(f"    계정 정책: 최소 {password_policy_info['min_length']}자, {password_policy_info['char_types']}종류 조합, 최대 나이 {password_policy_info['max_age']}일")
    if non_compliant_passwords:
        print(f"    [취약] {len(non_compliant_passwords)}명 발견")
        for user_data in non_compliant_passwords[:5]:
            print(f"      - {user_data['user']}: {user_data['issues']} (마지막: {user_data['last_used']})")
        if len(non_compliant_passwords) > 5:
            print(f"      ... 외 {len(non_compliant_passwords)-5}명")
        print("    권장: 2종 조합 10자 이상 OR 3종 조합 8자 이상, 90일마다 변경")
    else:
        print("    [양호] 모든 계정이 비밀번호 정책 준수")
    
    print("\n[7] Life-Cycle 미수립 - 90일 미사용")
    if no_lifecycle_users:
        print(f"    [취약] {len(no_lifecycle_users)}명 발견")
        for user_data in no_lifecycle_users[:5]:
            print(f"      - {user_data['user']}: {user_data['days_inactive']}일 미사용 (마지막: {user_data['last_activity']}, 유형: {user_data['activity_type']})")
        if len(no_lifecycle_users) > 5:
            print(f"      ... 외 {len(no_lifecycle_users)-5}명")
    else:
        print("    [양호] 모든 계정이 90일 이내 사용됨")
    
    print("\n[8] STS 미사용 직접 핸들링")
    if iam_direct_access == 'O':
        print("    [권고] IAM 계정이 STS 없이 직접 리소스 접근 중")
        print("    권장: STS(임시 자격증명) 사용")
    else:
        print("    [양호] STS를 통한 안전한 접근")
    
    print("\n[9] 태그 미설정 계정")
    if users_without_tags:
        print(f"    [권고] {len(users_without_tags)}명 발견")
        print(f"    대상: {', '.join(users_without_tags)}")
    else:
        print("    [양호] 모든 계정에 태그 설정됨")
    
    print("\n[10] MFA 미설정 계정")
    if users_without_mfa:
        print(f"    [취약] {len(users_without_mfa)}명 발견")
        print(f"    대상: {', '.join(users_without_mfa)}")
        print("    권장: 콘솔 접근 가능 계정에 MFA 설정 필수")
    else:
        print("    [양호] 콘솔 접근 가능한 모든 계정에 MFA 설정됨")
    
    print("\n[11] 미사용/유휴 Role·User (90~180일)")
    if idle_roles or idle_users_extended:
        if idle_roles:
            print(f"    [권고] 유휴 Role {len(idle_roles)}개 발견")
            for role_data in idle_roles[:3]:
                print(f"      - {role_data['role']}: {role_data['days_unused']}일 미사용 (마지막: {role_data['last_used']})")
            if len(idle_roles) > 3:
                print(f"      ... 외 {len(idle_roles)-3}개")
        if idle_users_extended:
            print(f"    [권고] 유휴 User {len(idle_users_extended)}명 발견")
            for user_data in idle_users_extended[:3]:
                print(f"      - {user_data['user']}: {user_data['days_inactive']}일 미사용 (마지막: {user_data['last_activity']})")
            if len(idle_users_extended) > 3:
                print(f"      ... 외 {len(idle_users_extended)-3}명")
    else:
        print("    [양호] 90~180일 유휴 Role/User 없음")
    
    print("\n[12] 과도한 권한 (wildcard, iam:PassRole)")
    if excessive_permissions:
        print(f"    [위험] {len(excessive_permissions)}개 발견")
        for item in excessive_permissions[:5]:
            entity_name = item.get('user') or item.get('role')
            entity_type = 'User' if 'user' in item else 'Role'
            print(f"      - [{entity_type}] {entity_name}:")
            for issue in item['issues'][:3]:
                print(f"        * {issue}")
            if len(item['issues']) > 3:
                print(f"        ... 외 {len(item['issues'])-3}개 문제")
        if len(excessive_permissions) > 5:
            print(f"      ... 외 {len(excessive_permissions)-5}개")
    else:
        print("    [양호] 과도한 권한 없음")
    
    print("\n" + "="*80)
    
    # Discord 임베드 알림 전송 (환경변수 설정된 경우에만)
    if DISCORD_WEBHOOK_URL:
        send_discord_notification(results_data)
    
    # 이메일 보고서 전송 (환경변수 설정된 경우에만)
    if RECIPIENT_EMAIL and SENDER_EMAIL:
        send_email_report(results_data, RECIPIENT_EMAIL)
    
    return {
        'statusCode': 200,
        'body': results_data
    }

def send_discord_notification(results_data):
    """Discord 임베드 메시지로 가시성 높은 보고서 전송"""
    
    # 위험/권고 개수 계산
    critical_count = sum([
        1 if results_data['access_key_result'] == 'O' else 0,
        1 if results_data['root_usage_result'] == 'O' else 0,
        1 if results_data['inactive_keys'] else 0,
        1 if results_data['no_rotation_keys'] else 0,
        1 if results_data['users_with_direct_policy'] else 0,
        1 if results_data['non_compliant_passwords'] else 0,
        1 if results_data['no_lifecycle_users'] else 0,
        1 if results_data['users_without_mfa'] else 0,
    ])
    warning_count = sum([
        1 if results_data['iam_direct_access'] == 'O' else 0,
        1 if results_data['users_without_tags'] else 0,
    ])
    
    # 색상 결정 (위험 취약점 개수에 따라)
    if critical_count == 0:
        color = 0x00FF00  # 녹색 - 안전
    elif critical_count <= 3:
        color = 0xFFFF00  # 노란색 - 경고
    else:
        color = 0xFF0000  # 빨간색 - 위험
    
    embed = {
        "title": "AWS IAM 보안 취약점 진단 보고서",
        "description": f"**진단 시간**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n**위험**: {critical_count}개 | **권고**: {warning_count}개",
        "color": color,
        "fields": []
    }
    
    # [1] ROOT 계정 Access Key 발급
    if results_data['access_key_result'] == 'O':
        embed["fields"].append({
            "name": "[1] ROOT 계정 Access Key 발급",
            "value": "[취약] CloudTrail에서 ROOT Access Key 생성 이력 확인됨",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[1] ROOT 계정 Access Key 발급",
            "value": "[양호] ROOT Access Key 생성 이력 없음",
            "inline": False
        })
    
    # [2] ROOT 계정 사용 이력
    if results_data['root_usage_result'] == 'O':
        embed["fields"].append({
            "name": "[2] ROOT 계정 사용 이력",
            "value": "[취약] 최근 ROOT 계정 사용 이력 발견",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[2] ROOT 계정 사용 이력",
            "value": "[양호] ROOT 계정 사용 이력 없음",
            "inline": False
        })
    
    # [3] 30일 미사용 Access Key
    if results_data['inactive_keys']:
        keys_info = []
        for key in results_data['inactive_keys'][:3]:
            keys_info.append(f"{key['user']}: {key['days_unused']}일")
        keys_text = ', '.join(keys_info)
        if len(results_data['inactive_keys']) > 3:
            keys_text += f" 외 {len(results_data['inactive_keys'])-3}개"
        embed["fields"].append({
            "name": f"[3] 30일 미사용 Access Key ({len(results_data['inactive_keys'])}개)",
            "value": f"[취약] {keys_text}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[3] 30일 미사용 Access Key",
            "value": "[양호] 모든 Access Key가 최근 30일 이내 사용됨",
            "inline": False
        })
    
    # [4] Access Key 미변경 (90일+)
    if results_data['no_rotation_keys']:
        keys_info = []
        for key in results_data['no_rotation_keys'][:3]:
            keys_info.append(f"{key['user']}: {key['age_days']}일")
        keys_text = ', '.join(keys_info)
        if len(results_data['no_rotation_keys']) > 3:
            keys_text += f" 외 {len(results_data['no_rotation_keys'])-3}개"
        embed["fields"].append({
            "name": f"[4] Access Key 미변경 90일 이상 ({len(results_data['no_rotation_keys'])}개)",
            "value": f"[취약] {keys_text}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[4] Access Key 미변경 90일 이상",
            "value": "[양호] 모든 Access Key가 90일 이내 갱신됨",
            "inline": False
        })
    
    # [5] 직접 권한 부여 계정
    if results_data['users_with_direct_policy']:
        users_list = ', '.join([u['user'] for u in results_data['users_with_direct_policy'][:5]])
        if len(results_data['users_with_direct_policy']) > 5:
            users_list += f" 외 {len(results_data['users_with_direct_policy'])-5}명"
        embed["fields"].append({
            "name": f"[5] 직접 권한 부여 계정 ({len(results_data['users_with_direct_policy'])}명)",
            "value": f"[취약] {users_list}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[5] 직접 권한 부여 계정",
            "value": "[양호] 모든 계정이 그룹을 통해 권한 부여받음",
            "inline": False
        })
    
    # [6] 비밀번호 정책 위배
    if results_data['non_compliant_passwords']:
        users_info = []
        for u in results_data['non_compliant_passwords'][:3]:
            users_info.append(f"{u['user']}: {u['issues']}")
        users_text = ', '.join(users_info) if len(users_info) <= 3 else ', '.join([u['user'] for u in results_data['non_compliant_passwords'][:5]])
        if len(results_data['non_compliant_passwords']) > 5:
            users_text += f" 외 {len(results_data['non_compliant_passwords'])-5}명"
        embed["fields"].append({
            "name": f"[6] 비밀번호 정책 위배 ({len(results_data['non_compliant_passwords'])}명)",
            "value": f"[취약] {users_text}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[6] 비밀번호 정책 위배",
            "value": "[양호] 모든 계정이 비밀번호 정책 준수",
            "inline": False
        })
    
    # [7] Life-Cycle 미수립 (90일 미사용)
    if results_data['no_lifecycle_users']:
        users_info = []
        for u in results_data['no_lifecycle_users'][:3]:
            users_info.append(f"{u['user']}: {u['days_inactive']}일")
        users_text = ', '.join(users_info)
        if len(results_data['no_lifecycle_users']) > 3:
            users_text += f" 외 {len(results_data['no_lifecycle_users'])-3}명"
        embed["fields"].append({
            "name": f"[7] Life-Cycle 미수립 - 90일 미사용 ({len(results_data['no_lifecycle_users'])}명)",
            "value": f"[취약] {users_text}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[7] Life-Cycle 미수립 - 90일 미사용",
            "value": "[양호] 모든 계정이 90일 이내 사용됨",
            "inline": False
        })
    
    # [8] STS 미사용 직접 핸들링
    if results_data['iam_direct_access'] == 'O':
        embed["fields"].append({
            "name": "[8] STS 미사용 직접 핸들링",
            "value": "[권고] IAM 계정이 STS 없이 직접 리소스 접근 중\nSTS(임시 자격증명) 사용 권장",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[8] STS 미사용 직접 핸들링",
            "value": "[양호] STS를 통한 안전한 접근",
            "inline": False
        })
    
    # [9] 태그 미설정 계정
    if results_data['users_without_tags']:
        users_list = ', '.join(results_data['users_without_tags'][:10])
        if len(results_data['users_without_tags']) > 10:
            users_list += f" 외 {len(results_data['users_without_tags'])-10}명"
        embed["fields"].append({
            "name": f"[9] 태그 미설정 계정 ({len(results_data['users_without_tags'])}명)",
            "value": f"[권고] {users_list}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[9] 태그 미설정 계정",
            "value": "[양호] 모든 계정에 태그 설정됨",
            "inline": False
        })
    
    # [10] MFA 미설정 계정
    if results_data['users_without_mfa']:
        users_list = ', '.join(results_data['users_without_mfa'][:10])
        if len(results_data['users_without_mfa']) > 10:
            users_list += f" 외 {len(results_data['users_without_mfa'])-10}명"
        embed["fields"].append({
            "name": f"[10] MFA 미설정 계정 ({len(results_data['users_without_mfa'])}명)",
            "value": f"[취약] {users_list}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[10] MFA 미설정 계정",
            "value": "[양호] 콘솔 접근 가능한 모든 계정에 MFA 설정됨",
            "inline": False
        })
    
    # [11] 미사용/유휴 Role·User (90~180일)
    if results_data['idle_roles'] or results_data['idle_users_extended']:
        count_text = []
        if results_data['idle_roles']:
            count_text.append(f"Role {len(results_data['idle_roles'])}개")
        if results_data['idle_users_extended']:
            count_text.append(f"User {len(results_data['idle_users_extended'])}명")
        
        value_parts = []
        if results_data['idle_roles']:
            role_names = [r['role'] for r in results_data['idle_roles'][:2]]
            value_parts.append(f"Role: {', '.join(role_names)}")
            if len(results_data['idle_roles']) > 2:
                value_parts[-1] += f" 외 {len(results_data['idle_roles'])-2}개"
        if results_data['idle_users_extended']:
            user_names = [u['user'] for u in results_data['idle_users_extended'][:2]]
            value_parts.append(f"User: {', '.join(user_names)}")
            if len(results_data['idle_users_extended']) > 2:
                value_parts[-1] += f" 외 {len(results_data['idle_users_extended'])-2}명"
        
        embed["fields"].append({
            "name": f"[11] 유휴 Role·User ({', '.join(count_text)})",
            "value": f"[권고] {' | '.join(value_parts)}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[11] 유휴 Role·User (90~180일)",
            "value": "[양호] 유휴 Role/User 없음",
            "inline": False
        })
    
    # [12] 과도한 권한 (wildcard, iam:PassRole)
    if results_data['excessive_permissions']:
        entities = []
        for item in results_data['excessive_permissions'][:3]:
            entity_name = item.get('user') or item.get('role')
            entity_type = 'User' if 'user' in item else 'Role'
            entities.append(f"[{entity_type}] {entity_name}")
        entities_text = ', '.join(entities)
        if len(results_data['excessive_permissions']) > 3:
            entities_text += f" 외 {len(results_data['excessive_permissions'])-3}개"
        
        embed["fields"].append({
            "name": f"[12] 과도한 권한 ({len(results_data['excessive_permissions'])}개)",
            "value": f"[위험] {entities_text}",
            "inline": False
        })
    else:
        embed["fields"].append({
            "name": "[12] 과도한 권한",
            "value": "[양호] 과도한 권한 없음",
            "inline": False
        })
    
    embed["footer"] = {
        "text": "AWS IAM Vulnerability Check"
    }
    embed["timestamp"] = datetime.now().isoformat()
    
    payload = {"embeds": [embed]}
    
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        print(f"Discord 알림 전송: {response.status_code}")
    except Exception as e:
        print(f"Discord 알림 전송 실패: {str(e)}")


def send_email_report(results_data, recipient_email):
    """AWS SES를 사용하여 HTML 보고서를 이메일로 전송"""
    import boto3
    from datetime import datetime
    
    ses = boto3.client('ses', region_name='ap-northeast-2')  # SES 리전 설정
    
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
                    1 if results_data['idle_roles'] or results_data['idle_users_extended'] else 0,
                    1 if results_data['excessive_permissions'] else 0,
                ])}</div>
                <div class="summary-label">발견된 취약점</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">12</div>
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
                    {', '.join([k['user'] + ' (' + str(k['days_unused']) + '일)' for k in results_data['inactive_keys'][:10]]) if results_data['inactive_keys'] else '미사용 키가 없습니다.'}
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
                    {', '.join([k['user'] + ' (' + str(k['age_days']) + '일)' for k in results_data['no_rotation_keys'][:10]]) if results_data['no_rotation_keys'] else 'Access Key가 주기적으로 변경되고 있습니다.'}
                    {'...' if len(results_data['no_rotation_keys']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['users_with_direct_policy'] else 'safe'}">
                <div class="check-title">
                    5. IAM 계정 직접 권한 부여
                    <span class="status {'vulnerable' if results_data['users_with_direct_policy'] else 'safe'}">
                        {'취약 (' + str(len(results_data['users_with_direct_policy'])) + '명)' if results_data['users_with_direct_policy'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join([u['user'] for u in results_data['users_with_direct_policy'][:10]]) if results_data['users_with_direct_policy'] else '모든 계정이 그룹을 통해 권한을 부여받고 있습니다.'}
                    {'...' if len(results_data['users_with_direct_policy']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['non_compliant_passwords'] else 'safe'}">
                <div class="check-title">
                    6. 비밀번호 정책 위배
                    <span class="status {'vulnerable' if results_data['non_compliant_passwords'] else 'safe'}">
                        {'취약 (' + str(len(results_data['non_compliant_passwords'])) + '명)' if results_data['non_compliant_passwords'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    권장: 2종류 조합 10자 이상 또는 3종류 조합 8자 이상, 90일마다 변경
                    <br>{', '.join([u['user'] for u in results_data['non_compliant_passwords'][:10]]) if results_data['non_compliant_passwords'] else '비밀번호 정책이 준수되고 있습니다.'}
                    {'...' if len(results_data['non_compliant_passwords']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['no_lifecycle_users'] else 'safe'}">
                <div class="check-title">
                    7. IAM Life-Cycle 미수립 (90일 미사용)
                    <span class="status {'vulnerable' if results_data['no_lifecycle_users'] else 'safe'}">
                        {'취약 (' + str(len(results_data['no_lifecycle_users'])) + '명)' if results_data['no_lifecycle_users'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    {', '.join([u['user'] + ' (' + str(u['days_inactive']) + '일)' for u in results_data['no_lifecycle_users'][:10]]) if results_data['no_lifecycle_users'] else '모든 계정이 활발히 사용되고 있습니다.'}
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
                        {'취약 (' + str(len(results_data['users_without_mfa'])) + '명)' if results_data['users_without_mfa'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    콘솔 로그인 가능한 계정의 MFA 설정을 권장합니다.
                    <br>{', '.join(results_data['users_without_mfa'][:10]) if results_data['users_without_mfa'] else '모든 계정에 MFA가 설정되어 있습니다.'}
                    {'...' if len(results_data['users_without_mfa']) > 10 else ''}
                </div>
            </div>
            
            <div class="check-item {'warning' if results_data['idle_roles'] or results_data['idle_users_extended'] else 'safe'}">
                <div class="check-title">
                    11. 미사용/유휴 Role·User (90~180일)
                    <span class="status {'warning' if results_data['idle_roles'] or results_data['idle_users_extended'] else 'safe'}">
                        {'권고 (Role: ' + str(len(results_data['idle_roles'])) + '개, User: ' + str(len(results_data['idle_users_extended'])) + '명)' if results_data['idle_roles'] or results_data['idle_users_extended'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    장기간 사용하지 않는 Role과 User는 보안상 삭제를 권장합니다.
                    {('<br>Role: ' + ', '.join([r['role'] + ' (' + str(r['days_unused']) + '일)' for r in results_data['idle_roles'][:5]]) + ('...' if len(results_data['idle_roles']) > 5 else '')) if results_data['idle_roles'] else ''}
                    {('<br>User: ' + ', '.join([u['user'] + ' (' + str(u['days_unused']) + '일)' for u in results_data['idle_users_extended'][:5]]) + ('...' if len(results_data['idle_users_extended']) > 5 else '')) if results_data['idle_users_extended'] else ''}
                    {'' if results_data['idle_roles'] or results_data['idle_users_extended'] else '<br>유휴 Role/User가 없습니다.'}
                </div>
            </div>
            
            <div class="check-item {'vulnerable' if results_data['excessive_permissions'] else 'safe'}">
                <div class="check-title">
                    12. 과도한 권한 (wildcard, iam:PassRole)
                    <span class="status {'vulnerable' if results_data['excessive_permissions'] else 'safe'}">
                        {'위험 (' + str(len(results_data['excessive_permissions'])) + '개)' if results_data['excessive_permissions'] else '양호'}
                    </span>
                </div>
                <div class="details">
                    Action "*" 또는 Resource "*" 또는 iam:PassRole이 "*"인 정책을 사용하는 것은 매우 위험합니다.
                    {('<br>' + '<br>'.join([('[User] ' if 'user' in item else '[Role] ') + (item.get('user') or item.get('role')) + ': ' + ', '.join(item['issues'][:3]) for item in results_data['excessive_permissions'][:5]])) if results_data['excessive_permissions'] else '<br>과도한 권한이 없습니다.'}
                    {'<br>...' if len(results_data['excessive_permissions']) > 5 else ''}
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
            Source=SENDER_EMAIL,
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