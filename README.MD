# AWS IAM 취약점 점검 서비스

AWS Lambda를 활용한 자동화된 IAM 보안 취약점 진단 도구입니다.

SK 쉴더스 클라우드 보안 가이드와 AWS 보안 모범사례를 참고하여 점검 항목을 선정했습니다.

참고 문서: https://rogue-gouda-f87.notion.site/AWS-de0b5749d03b464ea2e555cba3974d0b

---

## 점검 항목

총 12개 항목을 점검합니다:

1. **ROOT 계정 Access Key 발급**
   - ROOT 계정에 Access Key 발급 이력 존재 여부

2. **ROOT 계정 사용 이력**
   - ROOT 계정 실제 사용 이력 존재 여부

3. **30일 이상 미사용 Access Key**
   - 장기간 사용하지 않은 Access Key 탐지

4. **장기간 갱신하지 않은 Access Key (90일 이상)**
   - 90일 이상 갱신하지 않은 Access Key 탐지

5. **IAM 계정에 직접 정책 연결 여부**
   - 그룹 기반 권한 관리 미적용 여부

6. **비밀번호 정책 위배**
   - 복잡도 미준수 (2종류 10자 이상 또는 3종류 8자 이상)
   - 분기별 변경 미적용 (90일 이내)

7. **장기간 미사용 IAM 계정**
   - 90일 이상 미사용 계정 탐지

8. **STS 미사용 직접 핸들링**
   - STS 임시 자격증명 미사용 여부

9. **태그 미설정 계정**
   - IAM 계정 태그 미설정 여부

10. **MFA 미설정 계정**
    - 콘솔 접근 가능 계정의 MFA 미설정 여부

11. **유휴 Role·User (90~180일)**
    - 90일 이상 180일 이하 미사용 Role 및 User 탐지

12. **과도한 권한 (wildcard, iam:PassRole)**
    - 정책 내 wildcard 권한 및 iam:PassRole 남용 탐지

상세 점검 방법: https://lee-cloud-security.notion.site/AWS-IAM-fcfe3e5df6ee4374b76ec503e2e8c62f

---

## 설치 및 배포

### Lambda Layer 생성

의존성 패키지를 Layer로 패키징합니다:

```bash
pip install -r requirements.txt -t python/
zip -r layer.zip python
```

생성된 `layer.zip` 파일을 Lambda Layer로 업로드합니다.

### Lambda 함수 배포

1. Lambda 함수에 코드 업로드
2. Layer 연결
3. 실행 역할 설정 (IAM, CloudTrail 읽기 권한 필요)

---

## 환경변수 설정

Lambda 콘솔에서 다음 환경변수를 설정해야 합니다:

| 변수명 | 설명 | 필수 여부 |
|--------|------|-----------|
| `DISCORD_WEBHOOK_URL` | Discord 웹훅 URL (Discord 채널 설정 > 연동 > 웹후크에서 복사) | 선택 |
| `RECIPIENT_EMAIL` | 이메일 수신자 주소 | 선택 |
| `SENDER_EMAIL` | 이메일 발신자 주소 (AWS SES에서 인증된 이메일 주소) | 선택 |

**참고:**
- `DISCORD_WEBHOOK_URL`이 설정되지 않으면 Discord 알림은 전송되지 않습니다.
- `RECIPIENT_EMAIL` 또는 `SENDER_EMAIL`이 설정되지 않으면 이메일 전송은 수행되지 않습니다.

---

## 출력 형식

점검 결과는 다음 형식으로 제공됩니다:

1. **콘솔 출력**: CloudWatch Logs에 상세 보고서 출력
2. **Discord 알림**: 웹훅이 설정된 경우 임베드 메시지로 전송
3. **이메일 보고서**: 환경변수가 설정된 경우 HTML 형식으로 전송
