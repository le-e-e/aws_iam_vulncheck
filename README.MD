계층 파일 업로드 방법
pip install -r requirements.txt -t python/
zip -r layer.zip python

Lambda 콘솔에서 다음 환경변수를 설정해야 한다.
DISCORD_WEBHOOK_URL: Discord 웹훅 URL (Discord 채널 설정 > 연동 > 웹후크에서 복사)
RECIPIENT_EMAIL: 이메일 수신자 주소 (선택사항, 설정하지 않으면 이메일 전송 안 함)
SENDER_EMAIL: 이메일 발신자 주소 (AWS SES에서 인증된 이메일 주소)