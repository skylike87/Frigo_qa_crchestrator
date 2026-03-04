# Security Review Pipeline (OWASP Reference Driven)

## 목적
`.qa/security`는 Frigo 저장소를 대상으로 OWASP 기준의 보안 검토를 자동화하는 파이프라인이다.  
기존 공격 단위(`attacks/{attack_name}`) 방식 대신, 현재는 아래 3개 기준 문서를 축으로 보안 위협을 평가한다.

- `MAS` (모바일 앱 보안, MASTG/MASVS 관점)
- `LLM` (LLM 애플리케이션 보안)
- `API` (API 보안)

생성 산출물은 `docs/security_feedback/owasp/{MAS|LLM|API}.md`에 저장된다.

## 어떤 보안 위협을 방어하는가 (3가지 큰 축)
### 1) MAS: 모바일 런타임/저장소/네트워크 위협
- 로컬 저장소 평문 노출, 토큰/세션 아티팩트 유출, 백업 경로 데이터 누수
- 전송구간 보안 미흡(TLS 설정, 신뢰 모델 약점, MITM 우회 가능성)
- 앱 변조/리버스엔지니어링을 통한 클라이언트 검증 우회

핵심 목표:
- `MASVS-STORAGE`, `MASVS-NETWORK`, `MASVS-AUTH`, `MASVS-RESILIENCE` 관련 약점 탐지
- 클라이언트 신뢰에 의존한 보안 가정 제거, 서버 강제 검증 확인

### 2) LLM: 프롬프트/툴/데이터 경계 위협
- 직접/간접 프롬프트 인젝션(외부 문서, RAG 소스, 에이전트 체인 오염 전파)
- 툴 호출 파라미터 미검증으로 인한 과도 권한 실행 및 코드 실행 위험
- 민감정보 노출(프롬프트/로그/API 키), 멀티 에이전트 권한 분리 실패

핵심 목표:
- 입력/컨텍스트 불신 모델 강제
- 툴 입력 스키마 검증, 실행 샌드박스화, 세션/테넌트 격리
- 거부(refusal) 응답 및 실패 경로의 안전 처리

### 3) API: 인증/인가/자원소비/연동 경계 위협
- BOLA/BFLA/BOPLA, 약한 인증/세션 관리, 함수 단위 인가 누락
- 무제한 리소스 소비(요청량뿐 아니라 메모리/프로세스/fd 소진)
- SSRF, 외부 API 불안전 소비, 잘못된 인벤토리/구성 관리

핵심 목표:
- default-deny + 메서드별 인가 검증
- 응답 스키마 통제 및 과다 노출 차단
- 아웃바운드 allowlist/redirect 통제, 운영/스테이징 데이터 경계 준수

## 에이전트가 참조하는 레퍼런스
### OWASP 기준 문서
- `.qa/ref/owasp/MAS.md`
- `.qa/ref/owasp/LLM.md`
- `.qa/ref/owasp/API.md`

### 워크플로 및 페르소나/프롬프트
- 워크플로: `.qa/security/workflows/attack_security_review.yaml`
- Collector persona: `.qa/security/agent/personas/context_collector_gpt5.yaml`
- Reviewer persona: `.qa/security/agent/personas/security_reviewer_codex.yaml`
- Collector prompt: `.qa/security/agent/prompts/context_collector_task_prompt.md`
- Reviewer prompt: `.qa/security/agent/prompts/security_reviewer_task_prompt.md`

## 처리 프로세스 (워크플로)
워크플로는 `reference_name` 단위(`MAS`, `LLM`, `API`)로 독립 실행된다.

1. Reference resolve/validate
- 입력된 `reference_name`에 대해 `.qa/ref/owasp/{reference_name}.md` 존재 여부 확인

2. Collector seed
- 레퍼런스 문서 + 현재 저장소 코드를 읽어 초기 취약점 후보를 작성
- 출력: `OWASP Reference Summary`, `Candidate Vulnerabilities`, `Assumptions and Gaps`

3. Reviewer append
- Collector 산출물과 코드 증거를 재검증하고 심각도 순으로 상세 평가 추가
- 출력: `Detailed Findings`, `Evidence Map`, `Recommended Fixes`, `Validation Checklist`, `Residual Risks`

4. Report compile
- 피드백 문서에서 점수/잔여위험을 계산해 리포트 생성
- 출력: `docs/report/security/security_report_{reference_name}_{run_date_utc}.md`

## 어떤 기준으로 확인/리뷰/리포팅하는가
### 리뷰 기준
- 증거 기반 원칙: 모든 이슈는 파일 경로(가능하면 앵커/라인) 포함
- 심각도 순서: `Critical > High > Medium > Low`
- 불확실 항목은 가정으로 분리 표기
- 코드 맥락 없는 일반론 금지

### 점수 산정(리포트)
- 범위: `0-100`
- 가중치:
  - Exploitability 30%
  - Impact 30%
  - Coverage Confidence 20%
  - Remediation Readiness 20%

### 산출물 경로
- 피드백: `docs/security_feedback/owasp/{reference_name}.md`
- 최종 리포트: `docs/report/security/security_report_{reference_name}_{run_date_utc}.md`
- 실행 JSON 결과: `.qa/output/security/{reference_name}_{run_date_utc}.json`

## 시작 방법 (실행 스크립트)
### 기본 실행 (3개 모두 생성: MAS/LLM/API)
```bash
python3 .qa/security/scripts/run_attack_security_review.py
```

### 단일 레퍼런스 실행
```bash
python3 .qa/security/scripts/run_attack_security_review.py --reference-name MAS
python3 .qa/security/scripts/run_attack_security_review.py --reference-name LLM
python3 .qa/security/scripts/run_attack_security_review.py --reference-name API
```

### 드라이런
```bash
python3 .qa/security/scripts/run_attack_security_review.py --dry-run
```

### 셸 래퍼 사용
```bash
.qa/security/scripts/run_attack_security_review.sh
.qa/security/scripts/run_attack_security_review.sh --reference-name API --dry-run
```

## 참고
- `--attack-name` 옵션은 하위호환 별칭이며 현재는 `--reference-name` 사용을 권장한다.
- 본 파이프라인은 분석/리뷰용이며 코드 자동 수정은 수행하지 않는다.
