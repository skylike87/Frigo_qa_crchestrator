# Startup Guide

`startup/` 디렉토리는 **깃 풀/클론 이전 단계**와 **초기 세팅 단계**에서 쓰는 스크립트만 모아둔 곳입니다.

목표:
- 테스트 컨테이너 환경을 먼저 준비한다.
- 컨테이너에 진입해 메인 워크스페이스와 `.qa` 서브 워크스페이스를 세팅한다.
- `.qa` 실행 전 필요한 초기화(예: 히스토리 DB)를 수행한다.

## 포함된 스크립트

### 1) `setup_test_container_env.sh`
QA 테스트 컨테이너 이미지를 빌드합니다.

기본값:
- 이미지 태그: `frigo-qa-runner:local`
- Dockerfile: `containers/Dockerfile.qa`

사용법:
```bash
bash startup/setup_test_container_env.sh
```

옵션:
```bash
bash startup/setup_test_container_env.sh --no-cache
```

환경변수:
- `QA_IMAGE_NAME`: 빌드할 이미지 이름/태그 지정

예시:
```bash
QA_IMAGE_NAME=my-qa-runner:dev bash startup/setup_test_container_env.sh
```

### 2) `enter_test_container.sh`
빌드된 QA 이미지를 사용해 컨테이너에 진입합니다.

사용법:
```bash
bash startup/enter_test_container.sh
```

컨테이너 내부에서 바로 명령 실행:
```bash
bash startup/enter_test_container.sh "node --version && python3 --version"
```

환경변수:
- `QA_IMAGE_NAME`: 사용할 이미지 이름/태그
- `WORKSPACE_DIR`: 컨테이너 `/workspace`에 마운트할 호스트 디렉토리

예시:
```bash
WORKSPACE_DIR=/path/to/main-workspace \
QA_IMAGE_NAME=my-qa-runner:dev \
bash startup/enter_test_container.sh
```

### 3) `run_in_qa_container.sh`
`.qa/containers/compose.qa.yml` 기준으로 `qa-runner` 컨테이너를 실행합니다.

사용법:
```bash
bash .qa/startup/run_in_qa_container.sh
```

명령 실행:
```bash
bash .qa/startup/run_in_qa_container.sh "flutter --version && node --version && npx playwright --version"
```

### 4) `init_history_db.py`
SQLite 히스토리 DB를 초기화하고 `personas/*.yaml` 기반 에이전트 레코드를 시드합니다.

사용법:
```bash
python .qa/startup/init_history_db.py --db-path .qa/db/qa_history.db
```

## 권장 워크스페이스 세팅 순서

1. 테스트 컨테이너 이미지 빌드
```bash
bash startup/setup_test_container_env.sh
```

2. 컨테이너 진입
```bash
bash startup/enter_test_container.sh
```

3. 컨테이너 내부에서 메인 워크스페이스 클론
```bash
git clone <main-workspace-repo> /workspace/<main-workspace>
cd /workspace/<main-workspace>
```

4. `.qa` 서브 워크스페이스(이 저장소) 연결
```bash
git submodule add <qa-repo-url> .qa
git submodule update --init --recursive
```

5. `.qa` 히스토리 DB 초기화 (최초 1회)
```bash
python .qa/startup/init_history_db.py --db-path .qa/db/qa_history.db
```

6. `.qa` 오케스트레이션 스크립트 실행
```bash
python .qa/scripts/graph.py --help
```

## 참고

- `startup/`에는 사전 환경준비 성격의 스크립트만 둡니다.
- 오케스트레이션 실행/그래프 실행 스크립트는 기존처럼 `.qa/scripts/`를 사용합니다.
