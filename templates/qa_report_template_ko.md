# QA 최종 보고서: {{STORY_ID}}

## 1. 문서 정보

- Run ID: `{{RUN_ID}}`
- Story: `{{STORY_ID}}`
- 기준 Work Order Report: `{{SOURCE_REPORT_REF}}`
- 생성 시각(UTC): `{{GENERATED_AT_UTC}}`

## 2. 실행 범위 및 환경

- 실행 컨텍스트: `playwright`
- 스크립트 패턴: `{{SCRIPT_PATTERN}}`
- 매칭 스크립트:
{{SCRIPT_FILES}}
- 실행 명령:
{{COMMANDS}}

## 3. 테스트 실행 요약

| 항목 | 값 |
|---|---|
| Script Execution Status | `{{RESULT_STATUS}}` |
| Pass Count | `{{PASS_COUNT}}` |
| Fail Count | `{{FAIL_COUNT}}` |
| QA Verdict | `{{QA_VERDICT}}` |
| Testplan Gate Status | `{{TESTPLAN_GATE_STATUS}}` |

## 4. 테스트 결과 상세

{{RESULT_LINES}}

## 5. 품질 게이트 및 리스크

- 실패 체크 항목:
{{FAILED_CHECKS}}
- 게이트 사유 코드: `{{REASON_CODE}}`
- 에러 로그 요약:
{{ERROR_LOG}}

## 6. 최종 판정 및 후속 조치

- 최종 판정: `{{QA_VERDICT}}`
- 후속 조치:
{{NEXT_ACTIONS}}
