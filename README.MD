# AWS IAM 취약점 점검 서비스

AWS Lambda를 활용한 자동화된 IAM 보안 취약점 진단 도구입니다.

SK 쉴더스 클라우드 보안 가이드와 AWS 보안 모범사례를 참고하여 점검 항목을 선정했다

---

## 점검 항목

1. **ROOT 계정 Access Key 발급**
2. **ROOT 계정 사용 이력**
3. **30일 이상 미사용 Access Key**
4. **장기간 갱신하지 않은 Access Key (90일 이상)**
5. **IAM 계정에 직접 정책 연결 여부**
6. **비밀번호 정책 위배**
7. **장기간 미사용 IAM 계정**
8. **STS 미사용 직접 핸들링**
9. **태그 미설정 계정**
10. **MFA 미설정 계정**
11. **유휴 Role·User (90~180일)**
12. **과도한 권한 (wildcard, iam:PassRole)**


상세 내용: https://lee-cloud-security.notion.site/AWS-IAM-fcfe3e5df6ee4374b76ec503e2e8c62f

---

## 설치 및 배포

### Lambda 계층 업로드

```bash
pip install -r requirements.txt -t python/
zip -r layer.zip python
```

`layer.zip` 파일을 람다의 계층에 업로드한다.


---

## 구성

새로운 역할을 만들고 인라인 정책에 policy.json의 내용을 붙여넣어 준다.
그리고 기본 설정에서 기본 역할에 새로 만든 역할을 선택한다.

메모리는 512MB, 런타임 제한은 넉넉하게 1분 이상으로 설정하는 것을 추천한다. (테스트 필수)

---

## 환경변수 설정

Lambda 콘솔에서 다음 환경변수를 설정해야 한다:

| 변수명 | 설명 | 필수 여부 |
|--------|------|-----------|
| `DISCORD_WEBHOOK_URL` | Discord 웹훅 URL (Discord 채널 설정 > 연동 > 웹후크에서 복사) | 선택 |
| `RECIPIENT_EMAIL` | 이메일 수신자 주소 | 선택 |
| `SENDER_EMAIL` | 이메일 발신자 주소 (AWS SES에서 인증된 이메일 주소) | 선택 |

**참고:**
Discord나 Email을 이용하지 않아도 점검 결과는 Cloudwatch에서 자세한 정보를 확인할 수 있다.

---

## 출력 형식

1. **콘솔 출력**: CloudWatch Logs에 상세 보고서 출력
2. **Discord 알림**: 웹훅이 설정된 경우 임베드 메시지로 전송 (간략하게)
3. **이메일 보고서**: 환경변수가 설정된 경우 HTML 형식으로 전송
