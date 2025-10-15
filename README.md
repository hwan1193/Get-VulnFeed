# Get-VulnFeed
이 스크립트는 CISA KEV, NVD, 주요 Vendor(CERT) 보안 권고 페이지를 자동으로 크롤링하여 최신 취약점 정보를 수집하고 CSV 파일로 정리

- 요약 출력 :
  콘솔에 신규 취약점 요약(source, CVE, vendor, added, cvss, url) 확인 가능
  자동 알림 기능(선택): Teams 또는 Slack Webhook으로 신규 CVE 요약 전송 가능

🧰 사용 방법
# 관리자 PowerShell에서 실행
cd C:\sec
.\Get-VulnFeed.ps1

<img width="1751" height="551" alt="image" src="https://github.com/user-attachments/assets/8ab7076a-d73f-441c-afa0-1b242a952b38" />

실행 후 결과는 C:\sec\out\ 폴더에 자동 저장됩니다.

🧩 적용 가능 영역

보안 운영팀의 주간 취약점 리포트 자동화

클라우드 보안 점검 자동화(Intune, Defender for Cloud 연계)

취약점 관리 대시보드의 데이터 소스

