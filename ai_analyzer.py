# -*- coding: utf-8 -*-
import datetime
import json
import logging
import re
import time
import requests
from pathlib import Path
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

from utils.anonymizer import DataAnonymizer
from utils.helpers import Color, compare_versions, log_step

# [개선] 토큰 기반 청크 분할을 위한 tiktoken 라이브러리 추가
try:
    import tiktoken

    IS_TIKTOKEN_AVAILABLE = True
except ImportError:
    IS_TIKTOKEN_AVAILABLE = False


class AIAnalyzer:
    """
    [신규] AIBox 서버와 통신하여 sosreport 데이터를 분석하고,
    보안 위협 정보를 가져오는 클래스.
    """
    def __init__(self, server_url: str, report_date: Optional[str]):
        self.server_url = server_url.rstrip('/')
        self.model_config = {} # [신규] 모델 설정을 저장하기 위한 속성
        self.report_date_str = report_date.strftime('%Y-%m-%d') if report_date else "N/A"
        # [BUG FIX] Python 3.12+ 호환성: f-string 내 백슬래시 사용 오류를 해결하기 위해 re.sub을 밖으로 분리합니다.
        self.CVE_DB_PATH = "/data/iso/AIBox/meta/office-check_db.json"
        self.tokenizer = None
        if IS_TIKTOKEN_AVAILABLE:
            try:
                self.tokenizer = tiktoken.get_encoding("cl100k_base")
            except Exception as e:
                logging.warning(f"tiktoken 토크나이저 로딩 실패: {e}. 문자 길이 기반으로 폴백합니다.")
        # [사용자 요청] LLM 요청 횟수를 추적하기 위한 카운터
        self.llm_request_count = 0
        self._fetch_model_config() # [신규] 생성자에서 모델 설정을 가져옵니다.

    def _safe_float(self, value: Any) -> float:
        """[개선] 입력값을 float으로 안전하게 변환합니다."""
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(str(value).replace(',', '.'))
        except (ValueError, TypeError):
            return 0.0

    def _fetch_model_config(self):
        """[신규] AI 서버에서 모델 설정을 가져와 self.model_config에 저장합니다."""
        try:
            config_url = f"{self.server_url}/api/config"
            response = requests.get(config_url, timeout=10)
            response.raise_for_status()
            self.model_config = response.json()
            # [BUG FIX] AI 서버의 /api/config 응답 키가 'model'이므로, 'model_name' 대신 'model'을 참조하도록 수정합니다.
            # [사용자 요청] 모델별로 다른 context size를 참조하도록 수정합니다.
            # [BUG FIX] reasoning_model 키가 없을 경우, 기본 'model' 키를 사용하도록 폴백 로직을 추가합니다.
            reasoning_model = self.model_config.get('reasoning_model', self.model_config.get('model', 'N/A'))
            reasoning_context = self.model_config.get('reasoning_model_context', 'N/A')
            fast_model = self.model_config.get('fast_model', self.model_config.get('model', 'N/A'))
            fast_context = self.model_config.get('fast_model_context', 'N/A')
            logging.info(f"AI 서버 모델 설정 로드 완료: Reasoning='{reasoning_model}' (Context: {reasoning_context}KB), Fast='{fast_model}' (Context: {fast_context}KB)")
        except requests.exceptions.RequestException as e:
            logging.warning(f"AI 서버에서 모델 설정을 가져오는 데 실패했습니다: {e}. 기본값을 사용합니다.")
            self.model_config = {}


    def _make_request(self, endpoint: str, data: Dict, timeout: int = 600) -> Dict:
        """[개선] 재시도 로직이 추가된 AIBox 서버 요청 함수."""
        url = f"{self.server_url}/api/{endpoint}"
        self.llm_request_count += 1
        max_retries = 3
        for attempt in range(max_retries):
            try:
                logging.info(f"AI 서버에 분석 요청: {url} (시도 {attempt + 1}/{max_retries})") # [BUG FIX] AI 서버 요청 시, 'prompt' 키로 데이터를 감싸지 않고 요청 본문(payload)을 직접 전달하도록 수정합니다.
                # 서버의 /api/sos/analyze_system 엔드포인트는 요청 본문이 'prompt_template'과 'data' 키를 포함하는 객체 자체이기를 기대합니다.
                response = requests.post(url, json=data, timeout=timeout)

                if attempt > 0:
                    logging.info(Color.success(f"AI 서버 재연결 성공 (시도 {attempt + 1}/{max_retries}): {url}"))

                response.raise_for_status()
                # [BUG FIX] AI 서버가 순수 텍스트로 응답하는 경우를 처리합니다.
                # 'str' object has no attribute 'get' 오류를 방지하기 위해, 응답이 JSON이 아니면 파싱을 시도하고, 실패 시 기본 딕셔너리 구조로 래핑합니다.
                try:
                    return response.json()
                except json.JSONDecodeError:
                    response_text = response.text
                    try:
                        # 텍스트가 JSON 형식일 수 있으므로 다시 파싱 시도
                        return json.loads(response_text)
                    except json.JSONDecodeError:
                        return {
                            "summary": response_text,
                            "critical_issues": [],
                            "warnings": [],
                            "recommendations": [],
                        }
            except requests.exceptions.RequestException as e:
                logging.warning(Color.warn(f"AI 서버({url}) 통신 오류 (시도 {attempt + 1}/{max_retries}): {e}"))
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                else:
                    error_message = f"AI 서버({url}) 통신이 모든 재시도 후에도 최종 실패했습니다."
                    logging.error(Color.error(error_message))
                    return { "error": "AI Server Communication Failed", "details": error_message, "summary": "AI 분석 서버와 통신하지 못했습니다. 네트워크 연결 및 서버 상태를 확인하세요.", "critical_issues": [], "warnings": [], "recommendations": [] }
        return None # Should not be reached

    def _make_get_request_with_retry(self, url: str, timeout: int = 10, max_retries: int = 3) -> Optional[requests.Response]: # type: ignore
        """[BUG FIX] 재시도 로직이 포함된 GET 요청 함수."""
        for attempt in range(max_retries):
            try:
                # 로컬 서버와 통신하므로 프록시를 사용하지 않습니다.
                # [BUG FIX] requests.get 호출 시 'json=data' 인자를 제거합니다.
                # GET 요청은 본문에 데이터를 포함하지 않으며, 'json' 인자는 POST/PUT 요청에 사용됩니다.
                # GET 요청에 'json' 인자를 사용하면 RequestException이 발생할 수 있습니다.
                # 또한, 'proxies' 인자는 requests.get에 직접 전달되어야 합니다.
                
                # [BUG FIX] _make_request 대신 requests.get을 직접 호출하여 올바른 GET 요청을 보냅니다.
                response = requests.get(url, timeout=timeout, proxies={'http': None, 'https': None})
                
                if attempt > 0:
                    logging.info(f"GET 요청 재연결 성공 (시도 {attempt + 1}/{max_retries}): {url}")

                response.raise_for_status()
                return response # type: ignore
            except requests.exceptions.RequestException as e:
                logging.warning(f"GET 요청 오류 (시도 {attempt + 1}/{max_retries}): {url}, 오류: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    logging.error(f"GET 요청이 모든 재시도 후에도 최종 실패했습니다: {url}")
        return None # type: ignore
    def _perform_sar_smart_analysis(self, sar_data: Dict[str, Any], cpu_cores: int) -> Dict[str, Any]:
        """
        [신규] SAR 데이터에서 임계치를 초과하는 성능 지표만 필터링하는 '스마트 분석'을 수행합니다.
        AI 분석에 유의미한 데이터만 선별하여 분석 효율을 높입니다.
        """
        logging.info("  - SAR 데이터 스마트 분석 시작 (임계치 기반 필터링)...")
        problematic_data: Dict[str, Any] = {}
        
        # CPU: iowait > 20%
        if cpu_data := sar_data.get('cpu'):
            high_iowait = [d for d in cpu_data if d.get('pct_iowait', 0) > 20]
            if high_iowait: problematic_data['cpu_high_iowait'] = high_iowait

        # Load: 5분 평균 부하 > CPU 코어 수
        if load_data := sar_data.get('load'):
            high_load = [d for d in load_data if d.get('ldavg-5', 0) > cpu_cores]
            if high_load: problematic_data['load_average_high'] = high_load

        # Disk: util > 80% or await > 20ms
        if disk_data := sar_data.get('disk_detail'):
            disk_bottleneck = [d for d in disk_data if d.get('pct_util', 0) > 80 or d.get('await', 0) > 20]
            if disk_bottleneck: problematic_data['disk_bottleneck'] = disk_bottleneck

        # Memory: memused > 90%
        if mem_data := sar_data.get('memory'):
            high_mem = [d for d in mem_data if d.get('pct_memused', 0) > 90]
            if high_mem: problematic_data['memory_pressure'] = high_mem

        # Swap: swpused > 10%
        if swap_data := sar_data.get('swap'):
            swap_usage = [d for d in swap_data if d.get('pct_swpused', 0) > 10]
            if swap_usage: problematic_data['swap_activity'] = swap_usage

        if problematic_data:
            summary_text = f"SAR 데이터 스마트 분석 결과, {len(problematic_data)}개 영역에서 성능 저하 의심 지표가 발견되었습니다: {', '.join(problematic_data.keys())}"
            logging.info(Color.warn(f"    -> {summary_text}"))
            # AI가 컨텍스트를 이해할 수 있도록 요약 정보를 추가
            problematic_data['sar_smart_analysis_summary'] = summary_text
            return problematic_data
        else:
            logging.info("    -> SAR 데이터에서 특이점을 발견하지 못했습니다. AI 분석에서 SAR 데이터는 제외됩니다.")
            # 특이점이 없으면 빈 딕셔너리를 반환하여 AI 요청 데이터 양을 줄임
            return {}

    def _create_chunk_analysis_prompt(self, chunk_name: str, chunk_data: Any) -> str:
        """[신규] 개별 데이터 청크(묶음) 분석을 위한 프롬프트를 생성합니다."""
        # [개선] chunk_data가 이미 잘린 문자열일 경우를 처리합니다.
        if isinstance(chunk_data, dict) and "_truncated_data_" in chunk_data:
            data_content_for_prompt = f"```jsonc\n{chunk_data['_truncated_data_']}\n```\n(데이터가 너무 커서 일부만 포함됨)"
        else:
            # [BUG FIX] chunk_data를 JSON 문자열로 변환하여 프롬프트에 직접 삽입합니다.
            # ensure_ascii=False를 사용하여 한글이 유니코드 이스케이프되지 않도록 합니다.
            data_content_for_prompt = f"```jsonc\n{json.dumps(chunk_data, indent=2, default=str, ensure_ascii=False)}\n```"

        return f"""
[시스템 역할]
당신은 20년 경력의 Red Hat Certified Architect (RHCA)이자, Red Hat Enterprise Linux(RHEL) 시스템, 고가용성(HA) 클러스터(Pacemaker, Corosync), 그리고 스토리지(DRBD)에 대한 깊은 전문성을 가진 최고 수준의 진단 전문가입니다. 당신은 주어진 특정 데이터 조각을 면밀히 분석하여, 해당 섹션에서 발견되는 모든 이상 징후, 잠재적 문제점, 성능 병목, 또는 구성 오류를 식별하고 핵심적인 통찰을 제공합니다.

[분석 대상 데이터]
- 데이터 섹션: {chunk_name} 
- 데이터 내용 (JSON):
```jsonc
{json.dumps(chunk_data, indent=2, default=str, ensure_ascii=False)}
```

[요청]
위 데이터에서 가장 중요하거나 비정상적인 특징, 잠재적인 문제점을 나타내는 핵심 사항을 2~3개의 불릿 포인트로 요약해 주십시오.
응답은 반드시 유효한 JSON 객체 형식이어야 하며, 'summary' 키에 요약 내용을 담아주세요. 예: {{{{ "summary": "- 요약 1\\n- 요약 2" }}}}
"""

    def _create_final_analysis_prompt(self, summaries: Dict[str, str], problematic_sar_data: Dict[str, Any]) -> str:
        """
        [사용자 요청] AI의 역할을 RHEL, Pacemaker, DRBD 시스템을 심층 분석하는 전문가로 재정의합니다.
        단순한 현상 나열이 아닌, 로그와 구성 요소 간의 인과관계를 추론하여 근본 원인을 밝혀내도록 유도합니다.
        """
        # [REVERT] 분할 분석 요약(summaries)을 사용하도록 복원합니다.
        summaries_text = "\n".join(f"- **{name}**: {summary}" for name, summary in summaries.items())
        problematic_sar_json = ""
        if problematic_sar_data: # 성능 병목 데이터는 여전히 추가 정보로 활용합니다.
            problematic_sar_json = f"\n[추가 분석 데이터: 성능 병목 의심 SAR 데이터]\n```json\n{json.dumps(problematic_sar_data, indent=2, default=str)}\n```"
        
        # [제안 반영] CoT(Chain of Thought)를 강화하고 HA/DRBD 특화 지식을 프롬프트에 주입합니다.
        return f"""[시스템 역할: 엔터프라이즈 RHEL/HA 시스템 심층 분석가]
당신은 20년 이상의 경력을 가진 **Red Hat Certified Architect (RHCA)**이자 **고가용성(High Availability) 클러스터 및 스토리지 아키텍트**입니다. 당신의 임무는 고객의 sosreport 요약 데이터를 바탕으로 시스템 장애의 근본 원인을 파악하고, 전문가 수준의 해결책을 제시하는 것입니다.

**당신의 전문 분야 및 분석 가이드라인:**
1.  **Pacemaker/Corosync 클러스터:**
    * Fencing(Stonith) 발생 원인을 집요하게 파악하십시오. (단순한 '펜싱 발생' 보고는 불충분합니다. *왜* 발생했는지 추론하십시오.)
    * Totem Token Loss, KNET Link Down, Quorum Loss와 같은 네트워크/통신 문제를 식별하십시오.
    * 리소스 에이전트(Resource Agent)의 타임아웃 및 실패(Failover) 패턴을 분석하십시오.
2.  **DRBD (Distributed Replicated Block Device):**
    * Split-Brain 상황, Connection Lost, Diskless 상태 등 데이터 복제 문제를 분석하십시오.
    * 네트워크 대역폭 부족이나 디스크 I/O 지연이 복제에 미친 영향을 평가하십시오.
3.  **RHEL 시스템 커널 및 성능:**
    * Kernel Panic, Oops, OOM Killer, Soft/Hard Lockup 등의 치명적 오류를 최우선으로 분석하십시오.
    * Call Trace가 있다면 실패한 함수를 통해 문제가 발생한 커널 서브시스템(Memory, Network, Storage 등)을 특정하십시오.

[분석 방법론: Chain of Thought (단계별 추론)]
**반드시 다음 순서로 사고하고 분석 결과를 도출하십시오.**
1.  **[Fact Finding]**: 제공된 데이터에서 '무엇이' 일어났는지 핵심 사실들을 나열하십시오. (예: "10:00에 노드 A가 펜싱됨", "동시에 eth0 링크 다운 로그 발생")
2.  **[Correlation & Causality]**: 발견된 사실들 간의 인과관계를 연결하십시오.
    * *나쁜 예:* "펜싱이 발생했고, 네트워크가 끊겼습니다." (단순 나열)
    * *좋은 예:* "eth0 인터페이스의 링크 다운으로 인해 Corosync 토큰이 유실되었고, 이로 인해 노드 A가 클러스터에서 격리(Fencing)되었습니다." (인과 관계)
3.  **[Root Cause Analysis]**: 현상이 아닌 '근본 원인'을 지목하십시오. (예: "근본 원인은 일시적인 스위치 장애로 인한 네트워크 단절입니다.")
4.  **[Recommendations]**: 단순히 "재부팅하세요"가 아닌, 재발 방지를 위한 구체적인 설정을 제안하십시오. (예: "knet_transport를 sctp로 변경하거나, totem token timeout 값을 10000ms로 증가시키십시오.")

[분석 대상: 시스템 데이터 요약본]
{summaries_text} 
{problematic_sar_json}

[출력 형식]
위 분석 과정을 거쳐, 다음의 키를 가진 단일 JSON 객체로만 반환하십시오. 다른 서론이나 설명은 절대 포함하지 마십시오.

`summary` 필드는 다음의 마크다운 구조를 사용하여 전문적이고 가독성 있게 작성하십시오.
### 1. 종합 진단 (Executive Summary)
<시스템 상태에 대한 전문가적 소견 및 장애의 심각도 평가>
### 2. 장애 시나리오 재구성 (Failure Scenario Reconstruction)
<시간 순서에 따른 장애 발생 과정을 인과관계 중심으로 서술>
### 3. 근본 원인 분석 (Root Cause Analysis)
<문제의 핵심 원인 (네트워크, 스토리지, 커널, 설정 오류 등)>
### 4. 주요 발견 사항 (Key Findings)
* <Pacemaker/Corosync 관련 이슈>
* <DRBD/스토리지 관련 이슈>
* <시스템/커널 관련 이슈>

```json
{{{{
  "summary": "위의 마크다운 구조에 따라 작성된 상세 분석 내용",
  "critical_issues": ["즉각적인 조치가 필요한 치명적 오류 (예: Split-Brain, Fencing Loop, FS Corruption)"],
  "warnings": ["잠재적 위험 요소 (예: 높은 I/O Wait, 단일 네트워크 링크 사용)"],
  "recommendations": [ 
      {{{{ 
          "priority": "긴급/높음/중간", 
          "category": "HA클러스터/DRBD/커널/네트워크", 
          "issue": "문제점 요약", 
          "solution": "구체적인 기술적 해결 방안 (설정 변경, 파라미터 튜닝 등)", 
          "related_logs": ["근거가 된 주요 로그 메시지"] 
      }}}} 
  ]
}}}}
```"""

    def _reconstruct_incidents(self, metadata: Dict, sar_data: Dict) -> Dict[str, Any]:
        """
        [신규] 시스템의 핵심 장애 이벤트를 '앵커'로 식별하고,
        해당 이벤트 발생 전후의 로그와 성능 데이터를 수집하여 장애 상황을 재구성합니다.
        (parser.py에서 이관됨)
        """
        logging.info("  - 장애 재구성(Incident Reconstruction) 분석 시작...")
        
        all_log_lines = []
        # dmesg와 messages 로그를 타임스탬프와 함께 통합
        for source_name, content in [('dmesg', metadata.get('dmesg_content', '')), ('messages', metadata.get('messages_content', ''))]:
            if not content: continue
            for line in content.split('\n'):
                # [안정성 강화] 더 많은 타임스탬프 형식을 지원하는 정규식
                match = re.match(r'^(?:\[\s*(\d+\.\d+)\s*\]\s*)?([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?', line)
                if not match: continue

                kernel_ts, sys_ts = match.groups()
                dt_obj = None
                if sys_ts and metadata.get('system_info', {}).get('report_creation_date'):
                    try:
                        report_dt = datetime.datetime.strptime(metadata['system_info']['report_creation_date'].split(' (epoch:').strip(), '%a %b %d %H:%M:%S %Z %Y')
                        dt_obj = datetime.datetime.strptime(f"{report_dt.year} {sys_ts}", '%Y %b %d %H:%M:%S')
                    except (ValueError, KeyError): pass
                elif kernel_ts and metadata.get('system_info', {}).get('boot_time_epoch'):
                    try: dt_obj = datetime.datetime.fromtimestamp(metadata['system_info']['boot_time_epoch'] + float(kernel_ts))
                    except (ValueError, TypeError): pass
                
                if dt_obj:
                    all_log_lines.append({'dt': dt_obj, 'source': source_name, 'log': line})

        if not all_log_lines:
            logging.warning(Color.warn("  - 타임스탬프가 있는 로그 라인을 찾을 수 없어 장애 재구성 분석을 건너뜁니다."))
            return {}

        all_log_lines.sort(key=lambda x: x['dt'])

        ANCHOR_KEYWORDS = re.compile(
            (r'\b(Kernel panic|OOM-killer|Out of memory|BUG: soft lockup|'
             r'XFS.*shutdown|EXT4-fs error|Journal has aborted|'
             r'Split-Brain|Quorum lost|node.*OFFLINE|'
             r'I/O error|rejecting I/O to offline device|'
             r'MCE: \[Hardware Error\]|EDAC .* correctable errors)\b'),
            re.IGNORECASE)

        anchor_events = [item for item in all_log_lines if ANCHOR_KEYWORDS.search(item['log'])]
        if not anchor_events:
            logging.info("  - 핵심 장애 이벤트(Anchor Event)를 찾을 수 없습니다.")
            return {}

        logging.info(f"  - {len(anchor_events)}개의 핵심 장애 이벤트(Anchor)를 식별, 컨텍스트 수집 시작...")

        incident_reports = []
        TIME_WINDOW_BEFORE = timedelta(minutes=1)
        TIME_WINDOW_AFTER = timedelta(minutes=2)

        for anchor in anchor_events:
            start_time, end_time = anchor['dt'] - TIME_WINDOW_BEFORE, anchor['dt'] + TIME_WINDOW_AFTER
            contextual_logs = [f"[{item['dt'].isoformat()}] [{item['source']}] {item['log']}" for item in all_log_lines if start_time <= item['dt'] <= end_time]
            
            correlated_sar = {}
            for section, data_list in sar_data.items():
                section_metrics = []
                for entry in data_list:
                    try:
                        entry_dt = datetime.datetime.fromisoformat(entry.get('timestamp', ''))
                        if start_time <= entry_dt <= end_time:
                            section_metrics.append(entry)
                    except (ValueError, KeyError): continue
                if section_metrics: correlated_sar[section] = section_metrics
            
            incident_reports.append({"anchor_event": f"[{anchor['dt'].isoformat()}] [{anchor['source']}] {anchor['log']}", "contextual_logs": contextual_logs, "correlated_sar": correlated_sar})

        logging.info(f"  - 장애 재구성 분석 완료. 총 {len(incident_reports)}개의 장애 상황 리포트를 생성했습니다.")
        return {"incident_reports": incident_reports}

    def _get_token_count(self, text: str) -> int:
        """텍스트의 토큰 수를 반환합니다. tiktoken이 없으면 문자 수를 반환합니다."""
        if self.tokenizer:
            return len(self.tokenizer.encode(text))
        return len(text) # Fallback to character count if tiktoken is not available

    def _split_large_list_chunk(self, chunk_name: str, data_list: List[Any], max_tokens_per_sub_chunk: int) -> List[Tuple[str, List[Any]]]:
        """
        주어진 리스트를 AI 모델의 토큰 제한에 맞춰 여러 개의 서브 리스트로 분할합니다.
        각 서브 리스트는 JSON으로 변환되었을 때 max_tokens_per_sub_chunk를 넘지 않도록 합니다.
        """
        sub_chunks_info = []
        current_sub_chunk = []
        current_sub_chunk_tokens = 0
        
        # Calculate tokens for the prompt template that wraps the data
        sample_prompt_template_for_list = self._create_chunk_analysis_prompt(chunk_name, []) # Empty list to get base prompt tokens
        prompt_template_tokens = self._get_token_count(sample_prompt_template_for_list)
        
        # Max tokens available for the actual JSON data within the prompt
        effective_max_data_size = max_tokens_per_sub_chunk - prompt_template_tokens

        if effective_max_data_size <= 0:
            logging.warning(Color.warn(f"  - '{chunk_name}' 청크의 프롬프트 템플릿이 너무 커서 데이터를 위한 공간이 없습니다. 분할 불가."))
            return [(chunk_name, data_list)] # Cannot split meaningfully

        for item in data_list:
            item_json_str = json.dumps(item, default=str, ensure_ascii=False)
            item_tokens = self._get_token_count(item_json_str)

            if current_sub_chunk_tokens + item_tokens > effective_max_data_size and current_sub_chunk:
                sub_chunks_info.append((f"{chunk_name}_part_{len(sub_chunks_info)+1}", current_sub_chunk))
                current_sub_chunk = []
                current_sub_chunk_tokens = 0
            
            current_sub_chunk.append(item)
            current_sub_chunk_tokens += item_tokens
        
        if current_sub_chunk:
            sub_chunks_info.append((f"{chunk_name}_part_{len(sub_chunks_info)+1}", current_sub_chunk))
        
        return sub_chunks_info

    def get_structured_analysis(self, metadata_path: Path, sar_data_path: Path) -> Dict[str, Any]:
        """[REVERT] AI 분석 방식을 '분할 정복(Map-Reduce)' 방식으로 되돌립니다."""
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            with open(sar_data_path, 'r', encoding='utf-8') as f:
                sar_data = json.load(f)
    
            # [개선] AI 분석 전, 유의미한 SAR 데이터만 필터링
            cpu_cores = metadata.get('system_info', {}).get('cpu_cores', 0)
            problematic_sar_data = self._perform_sar_smart_analysis(sar_data, cpu_cores)

            # [리팩토링] 장애 재구성 로직을 AIAnalyzer로 이동하여 전처리 단계로 수행
            incident_reports = self._reconstruct_incidents(metadata, sar_data)
            metadata.update(incident_reports)
    
            # --- Map 단계: 데이터를 작은 묶음으로 나누어 병렬로 요약 ---
            logging.info(Color.info("  - [Map Phase] 데이터 섹션별 병렬 요약 분석 시작..."))
            data_chunks = {
                "system_info": metadata.get("system_info"),
                "storage": metadata.get("storage"),
                "processes": metadata.get("processes"),
                "network": metadata.get("network"),
                "boot_cmdline": metadata.get("boot_cmdline"),
                "failed_services": metadata.get("failed_services"),
                "configurations": metadata.get("configurations"),
                "incident_reports": metadata.get("incident_reports"),
                "performance_analysis": metadata.get("performance_analysis"),
                "smart_log_analysis": metadata.get("smart_log_analysis"),
            }
            data_chunks = {k: v for k, v in data_chunks.items() if v}
    
            chunk_summaries = {}
            with ThreadPoolExecutor(max_workers=8, thread_name_prefix='Chunk_Analyzer') as executor:
                future_to_chunk = {
                    executor.submit(
                        self._make_request,
                        'sos/analyze', # [제안 반영] Map 단계에서는 빠른 요약을 위해 'fast' 모델 사용을 요청합니다.
                        # [BUG FIX] 프롬프트 생성 시 이미 데이터가 포함되므로, .format() 호출을 제거합니다.
                        {"prompt": self._create_chunk_analysis_prompt(name, data), "model_type": "fast"}
                    ): name
                    for name, data in data_chunks.items()
                }
                for future in as_completed(future_to_chunk):
                    chunk_name = future_to_chunk[future]
                    try:
                        result = future.result()
                        chunk_summaries[chunk_name] = result.get('summary', str(result)) if isinstance(result, dict) else str(result)
                        logging.info(f"    -> '{chunk_name}' 섹션 요약 완료.")
                    except Exception as e:
                        logging.error(f"'{chunk_name}' 섹션 요약 중 오류 발생: {e}")
                        chunk_summaries[chunk_name] = f"'{chunk_name}' 섹션 분석 중 오류가 발생했습니다."

            # --- Reduce 단계: 요약된 결과들을 모아 최종 종합 분석 요청 ---
            logging.info(Color.info("  - [Reduce Phase] 요약본을 종합하여 최종 분석 요청..."))
            final_prompt = self._create_final_analysis_prompt(chunk_summaries, problematic_sar_data)
            logging.debug(f"  - 생성된 최종 AI 분석 프롬프트:\n---\n{final_prompt}\n---") # [제안 반영] Reduce 단계에서는 깊은 추론을 위해 'reasoning' 모델 사용을 요청합니다.
            final_analysis = self._make_request('sos/analyze', {"prompt": final_prompt, "model_type": "reasoning"}) or {
                "summary": "AI 최종 분석 요청에 실패했습니다.", "critical_issues": [], "warnings": [], "recommendations": []
            }
            logging.debug(f"  - AI 서버로부터 수신한 원본 분석 결과:\n---\n{json.dumps(final_analysis, indent=2, ensure_ascii=False)}\n---")

            # [BUG FIX] AI 서버가 JSON 형식의 문자열을 반환하는 경우, 이를 파싱하여 딕셔너리로 변환합니다.
            # 'str' object has no attribute 'get' 오류를 해결합니다.
            if isinstance(final_analysis, str):
                try:
                    final_analysis = json.loads(final_analysis)
                except json.JSONDecodeError:
                    logging.warning(Color.warn("AI 최종 분석 결과가 유효한 JSON 형식이 아닙니다. 기본 구조로 래핑합니다."))
                    final_analysis = {"summary": final_analysis, "critical_issues": [], "warnings": [], "recommendations": []}

            # [BUG FIX] AI가 summary에 모든 내용을 담아 반환하는 경우, 이를 파싱하여 구조화된 데이터로 재구성합니다.
            if isinstance(final_analysis.get("summary"), str) and not final_analysis.get("recommendations"):
                logging.info("AI 응답이 단일 summary 필드에 포함된 것으로 보입니다. 구조화를 시도합니다.")
                summary_text = final_analysis["summary"]
                
                # "주요 발견 사항"을 critical_issues와 warnings로 분리
                findings_match = re.search(r'###\s*주요 발견 사항\s*\n(.*?)(?=\n###|$)', summary_text, re.DOTALL)
                if findings_match:
                    findings_text = findings_match.group(1)
                    # '심각', '주의' 등의 키워드로 분리 시도
                    issues = re.findall(r'^\*\s*(.*?)$', findings_text, re.MULTILINE)
                    for issue in issues:
                        if any(kw in issue for kw in ['장애', '중단', '실패', '심각']):
                            final_analysis.setdefault("critical_issues", []).append(issue)
                        else:
                            final_analysis.setdefault("warnings", []).append(issue)

                # "세부 조치 항목"을 recommendations로 변환
                recommendations_matches = re.finditer(r'###\s*[\d\.\-]+\s*(.*?)\s*\(우선순위\s*(.*?)\s*/\s*카테고리\s*(.*?)\)\n(.*?)(?=\n###|$)', summary_text, re.DOTALL)
                for match in recommendations_matches:
                    issue_title, priority, category, solution_text = match.groups()
                    
                    # 테이블 형식의 solution을 파싱하여 한 줄의 문자열로 변환
                    solution_lines = [line.strip() for line in solution_text.strip().split('\n') if '|' in line and not line.startswith('|--')]
                    solution_summary = " -> ".join([part.strip() for part in solution_lines[1].split('|')[1:-1]]) if len(solution_lines) > 1 else solution_text.strip()

                    final_analysis.setdefault("recommendations", []).append({
                        "priority": priority.strip(),
                        "category": category.strip(),
                        "issue": issue_title.strip(),
                        "solution": solution_summary,
                        "related_logs": []
                    })
                
                # [BUG FIX] summary 텍스트 끝에 포함된 JSON 블록을 파싱하는 로직 추가
                # 예: "### 상세 권고 사항...\n{ \"critical_issues\": ... }"
                json_block_match = re.search(r'{\s*"critical_issues":.*}', summary_text, re.DOTALL)
                if json_block_match:
                    json_string = json_block_match.group(0)
                    try:
                        structured_data = json.loads(json_string)
                        final_analysis.setdefault("critical_issues", []).extend(structured_data.get("critical_issues", []))
                        final_analysis.setdefault("warnings", []).extend(structured_data.get("warnings", []))
                        final_analysis.setdefault("recommendations", []).extend(structured_data.get("recommendations", []))
                        
                        # summary에서 JSON 부분을 제거하여 순수한 텍스트만 남김
                        final_analysis["summary"] = summary_text[:json_block_match.start()].strip()
                    except json.JSONDecodeError:
                        logging.warning(Color.warn("Summary에 포함된 JSON 블록 파싱에 실패했습니다."))

            return final_analysis
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(Color.error(f"AI 분석을 위한 데이터 파일을 읽는 중 오류 발생: {e}"))
            return {"summary": "분석 데이터 파일을 처리할 수 없어 AI 분석을 수행하지 못했습니다.", "critical_issues": [], "warnings": [], "recommendations": []}

    def _prioritize_vulnerabilities_by_context(self, vulnerabilities: List[Dict], running_processes: List[Dict]) -> List[Dict]:
        """[제안 반영] 실행 중인 프로세스 정보를 바탕으로 CVE의 우선순위를 동적으로 조정합니다."""
        if not running_processes or not vulnerabilities:
            return vulnerabilities

        # 실행 중인 프로세스 이름에서 파생된 패키지 이름 집합 생성
        running_packages = set()
        for proc in running_processes:
            # /usr/sbin/httpd -> httpd
            package_name = proc.get('command', '').split('/')[-1].split()[0]
            running_packages.add(package_name)

        for cve in vulnerabilities:
            for finding in cve.get('findings', []):
                if finding.get('package') in running_packages:
                    cve['severity'] = 'Critical' # 실행 중인 프로세스와 관련된 CVE는 심각도를 'Critical'로 격상
        return vulnerabilities

    def analyze_security_advisories(self, metadata: Dict) -> List[Dict]:
        """
        설치된 패키지 버전을 기반으로 CVE 데이터베이스를 확인하여 조치가 필요한 보안 권고 사항을 분석하고,
        AI를 통해 각 CVE의 요약을 생성합니다.
        [사용자 요청] AI 요약 로직을 제거하고, cve_check_report.py와 유사하게 설치된 패키지와 DB를 직접 비교하여 모든 취약점을 리스트업합니다.
        """

        # [사용자 요청 & 개선] security.py의 TARGET_PRODUCT_PATTERNS를 도입하여 제품 필터링의 정확성과 일관성을 높입니다.
        TARGET_PRODUCT_PATTERNS = [
            re.compile(r"^Red Hat Enterprise Linux 7$"),
            re.compile(r"^Red Hat Enterprise Linux 7 Extended Lifecycle Support$"),
            re.compile(r"^Red Hat Enterprise Linux 8$"),
            re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Extended Update Support$"),
            re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Extended Update Support Long-Life Add-On$"),
            re.compile(r"^Red Hat Enterprise Linux 8\.\d+ Update Services for SAP Solutions$"),
            re.compile(r"^Red Hat Enterprise Linux 9$"),
            re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Extended Update Support$"),
            re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Extended Update Support Long-Life Add-On$"),
            re.compile(r"^Red Hat Enterprise Linux 9\.\d+ Update Services for SAP Solutions$"),
            re.compile(r"^Red Hat Enterprise Linux 10$"),
            re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support$"),
            re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Extended Update Support Long-Life Add-On$"),
            re.compile(r"^Red Hat Enterprise Linux 10\.\d+ Update Services for SAP Solutions$"),
        ] # noqa: E501
    
        if not (installed_packages_list := metadata.get('installed_packages', [])):
            logging.warning(Color.warn("  - 설치된 패키지 정보가 없어 CVE 보안 권고 확인을 건너뜁니다."))
            return []
    
        logging.info(f"  - CVE 데이터베이스 로드 중: {self.CVE_DB_PATH}")
        try:
            with open(self.CVE_DB_PATH, 'r', encoding='utf-8') as f:
                cve_database = json.load(f)
        except FileNotFoundError:
            logging.error(Color.error(f"  - CVE 데이터베이스 파일({self.CVE_DB_PATH})을 찾을 수 없습니다."))
            return []
        except json.JSONDecodeError as e:
            logging.error(Color.error(f"  - CVE 데이터베이스 파일({self.CVE_DB_PATH}) 파싱 오류: {e}"))
            return []
    
        logging.info(f"  - CVE 데이터베이스에서 {len(cve_database)}개 CVE 로드 완료.") # noqa: E501
    
        installed_packages_map = {pkg['name']: pkg['version'] for pkg in installed_packages_list}
        # [사용자 요청] cve_check_report.py와 유사하게 CVE ID를 기준으로 결과를 그룹화합니다.
        found_vulnerabilities_map = {}
    
        # [BUG FIX] metadata의 'system_info' 객체에서 'os_release'를 정확히 참조하도록 수정합니다.
        os_release_from_metadata = metadata.get('system_info', {}).get('os_release', 'N/A')
        logging.info(f"  - 시스템 OS 버전: {os_release_from_metadata}")
        os_release_str = metadata.get('system_info', {}).get('os_release', '') # noqa: E501
        
        os_ver_match = re.search(r'release\s+(\d+)', os_release_str)
        if not os_ver_match:
            logging.warning(Color.warn("  - 시스템 OS의 주 버전을 확인할 수 없어 CVE 분석을 건너뜁니다."))
            return []
        sys_major_ver = os_ver_match.group(1)

        for cve_id, cve_data in cve_database.items():
            # [개선] _summarize_vulnerability 함수에 전달할 영어 요약 정보를 미리 준비합니다.
            english_summary_for_batch = "No summary available."
            if cve_data.get("details") and isinstance(cve_data["details"], list) and cve_data["details"][0]:
                english_summary_for_batch = cve_data["details"][0]
            elif cve_data.get("statement"):
                english_summary_for_batch = cve_data["statement"].split('.')[0] + '.'
            english_summary_for_batch = english_summary_for_batch.strip().replace('\n', ' ')

            cve_findings = []
            
            logging.debug(f"  - CVE '{cve_id}' 검사 중...")

            # [사용자 요청] 'affected_release' (패치 존재)와 'package_state' (패치 미존재)를 모두 분석합니다.
            all_potential_affects = cve_data.get("affected_release", []) + cve_data.get("package_state", [])

            for item in all_potential_affects:
                product_name = item.get("product_name")
                if not product_name: continue

                # 1. 제품 필터링: 대상 RHEL 제품군이고, 시스템의 OS 주 버전과 일치하는지 확인
                is_target_product = any(p.match(product_name) for p in TARGET_PRODUCT_PATTERNS)
                cve_product_major_ver_match = re.search(r'Red Hat Enterprise Linux\s+(\d+)', product_name)
                is_major_ver_match = cve_product_major_ver_match and cve_product_major_ver_match.group(1) == sys_major_ver

                if not (is_target_product and is_major_ver_match):
                    logging.debug(f"    - '{cve_id}' 건너뜀: 제품 '{product_name}'이(가) 분석 대상이 아님.")
                    continue

                # 2. 패키지 이름 추출
                package_field = item.get("package") or item.get("package_name")
                if not package_field: continue

                # 패키지 이름과 버전 분리 (cve_check_report.py 로직 참고)
                match = re.match(r'^(.+?)-(\d+):(.+-.+)$', package_field)
                if match:
                    vuln_pkg_name, epoch, ver_rel = match.groups()
                    fix_version = f"{epoch}:{ver_rel}"
                else:
                    parts = package_field.rsplit('-', 1)
                    if len(parts) == 2 and re.search(r'[\d.]', parts[1]):
                        vuln_pkg_name, fix_version = parts
                    else: # 분리 실패 시, 전체를 이름으로 간주 (주로 package_state의 경우)
                        vuln_pkg_name, fix_version = package_field, "N/A"

                # 3. 시스템에 설치된 패키지인지 확인
                if vuln_pkg_name in installed_packages_map:
                    installed_ver = installed_packages_map[vuln_pkg_name] # type: ignore
                    version_comparison_result = -2 # 기본값: 정보 없음 (e.g., fix_version이 N/A)
                    
                    # 4. 버전 비교 (fix_version이 있는 경우에만)
                    if fix_version != "N/A":
                        # [사용자 요청] 제품명에 따른 버전 비교 로직 분기
                        # [사용자 요청 수정] 일반 RHEL 및 ELS(Extended Lifecycle Support) 제품을 동일하게 처리합니다.
                        # EUS(Extended Update Support)와는 다른 로직을 적용하기 위함입니다.
                        is_base_or_els_rhel = re.fullmatch(r'Red Hat Enterprise Linux \d+( Extended Lifecycle Support)?', product_name)

                        installed_ver_for_compare = re.sub(r'^\d+:', '', installed_ver) # epoch 제거
                        fix_version_for_compare = re.sub(r'^\d+:', '', fix_version) # epoch 제거

                        if is_base_or_els_rhel:
                            # Case 1: 일반 RHEL - 전체 버전 비교
                            version_comparison_result = compare_versions(installed_ver_for_compare, fix_version_for_compare)
                        else:
                            # Case 2: EUS, SAP 등 - 기본 빌드 번호(x.y.z-a)를 먼저 비교
                            # [BUG FIX] glibc (2.28-189.1)와 kernel (4.18.0-305.1) 모두 처리 가능한 일반화된 정규식으로 수정
                            # 정규식 설명: (버전)-(릴리즈의 첫 숫자 세그먼트)를 추출 (예: '2.28-189', '4.18.0-305')
                            base_ver_pattern = r'^([^-]+-\d+)'
                            installed_base_match = re.match(base_ver_pattern, installed_ver_for_compare)
                            fix_base_match = re.match(base_ver_pattern, fix_version_for_compare)

                            if installed_base_match and fix_base_match and (installed_base_match.group(1) == fix_base_match.group(1)):
                                # 기본 빌드가 같으면 전체 버전 비교
                                version_comparison_result = compare_versions(installed_ver_for_compare, fix_version_for_compare)
                            else:
                                # 기본 빌드가 다르면 '가이드'로 처리
                                version_comparison_result = -3 # -3: Guide
                    
                    if version_comparison_result < 0:
                        logging.info(Color.warn(f"    -> [조치 필요] '{vuln_pkg_name}' 패키지가 '{cve_id}'에 취약합니다! (설치: {installed_ver} < 권고: {fix_version})"))
                    elif fix_version != "N/A":
                        logging.debug(f"      - '{vuln_pkg_name}' 패키지는 이미 패치됨 (설치: {installed_ver} >= 권고: {fix_version}).")
                    else: # fix_version이 'N/A'인 경우
                        logging.info(Color.warn(f"    -> [영향 있음] '{vuln_pkg_name}' 패키지는 '{cve_id}'에 영향이 있으나, 아직 패치 정보가 없습니다. (fix_state: {item.get('fix_state')})"))

                    # 5. 최종 결과(finding) 생성
                    finding_details = {
                        "package": vuln_pkg_name,
                        "installed_version": installed_ver,
                        "fix_version": fix_version,
                        "rhsa_id": item.get("advisory", "N/A"),
                        "version_comparison": version_comparison_result,
                        "fix_state": item.get("fix_state"), # "Affected" 또는 None
                        "product_name": product_name # [사용자 요청] product_name 추가
                    }
                    cve_findings.append(finding_details)
            
            # 해당 CVE에 대한 finding이 하나라도 있으면, CVE 정보를 맵에 추가합니다.
            if cve_findings: # type: ignore
                if cve_id not in found_vulnerabilities_map: # type: ignore
                    found_vulnerabilities_map[cve_id] = { # type: ignore
                            'cve_id': cve_id,
                            'severity': cve_data.get('threat_severity', 'N/A'),
                            'description_en': english_summary_for_batch, # 배치 요약을 위해 영어 요약 저장
                            'public_date': cve_data.get('public_date', 'N/A'),
                            'cvss3': cve_data.get('cvss3', {}),
                            'findings': []
                        }
                found_vulnerabilities_map[cve_id]['findings'].extend(cve_findings) # type: ignore

        if found_vulnerabilities_map:
            # [개선] 배치 요약 처리
            cves_to_summarize = [{'cve_id': cve_id, 'english_summary': v['description_en']} for cve_id, v in found_vulnerabilities_map.items()]
            batch_summaries = self._batch_summarize_vulnerabilities(cves_to_summarize)

            for cve_id, cve_entry in found_vulnerabilities_map.items():
                # [사용자 요청] cve_check_report.py와 유사하게 AI 요약을 생성합니다.
                # [BUG FIX] _summarize_vulnerability 호출 시 누락된 인자(cve_id, batch_summaries)를 추가합니다.
                summary = self._summarize_vulnerability(
                    cve_entry['description_en'], # 이미 추출된 영어 요약 사용
                    cve_entry.get('statement', ''), # statement는 폴백용으로 전달
                    cve_id,
                    batch_summaries
                )
                cve_entry['description'] = summary # 한국어 요약으로 업데이트
                # 더 이상 필요 없는 'description_en' 키는 삭제
                if 'description_en' in cve_entry:
                    del cve_entry['description_en']

        # 최종 리포트용 리스트로 변환
        final_vulnerabilities = list(found_vulnerabilities_map.values()) # type: ignore

        # [제안 반영] 실행 중인 프로세스 컨텍스트를 기반으로 취약점 우선순위 조정
        final_vulnerabilities = self._prioritize_vulnerabilities_by_context(final_vulnerabilities, metadata.get('processes', {}).get('list', []))

        logging.info(Color.success("\n보안 권고 분석 완료."))
        return final_vulnerabilities
    
    def _batch_summarize_vulnerabilities(self, cve_list: List[Dict]) -> Dict[str, str]:
        """[신규] 여러 CVE 요약을 한번에 처리하여 AI 호출을 최소화합니다."""
        if not cve_list:
            return {}

        logging.info(f"  - {len(cve_list)}개의 CVE에 대한 AI 요약 생성 요청 (배치 처리)...")
        prompt = self._create_batch_summarize_prompt(cve_list)
        payload = {"prompt": prompt}
        
        try:
            response = self._make_request('sos/analyze', payload, timeout=120)
            if response and isinstance(response, dict) and 'summaries' in response:
                # 응답을 {cve_id: korean_summary} 형태의 딕셔너리로 변환
                return {item.get('cve_id'): item.get('korean_summary', '요약 실패') for item in response['summaries']}
        except Exception as e:
            logging.warning(Color.warn(f"CVE 배치 요약 생성 중 오류 발생: {e}"))

        return {}

    def _summarize_vulnerability(self, english_summary: str, statement: str, cve_id: str, batch_summaries: Dict[str, str]) -> str:
        """[신규] cve_check_report.py의 AI 요약 로직을 가져와 적용합니다."""
        # 배치 요약 결과가 있으면 먼저 사용
        if cve_id in batch_summaries:
            return batch_summaries[cve_id]

        # 배치 요약에 실패했거나, 개별 요약이 필요한 경우
        # english_summary가 이미 정제되어 있으므로, 추가적인 details/statement 처리는 필요 없습니다.
        if not english_summary:
            english_summary = statement.split('.')[0] + '.' if statement else "No summary available."
        
        english_summary = english_summary.strip().replace('\n', ' ')
        if len(english_summary) > 250:
            english_summary = english_summary[:247] + "..."

        # AIBox 서버에 번역 및 요약 요청
        try:
            api_url = f"{self.server_url}/api/sos/analyze"
            prompt = f"""[SYSTEM ROLE]
You are a cybersecurity analyst. Your task is to summarize the core threat of the following vulnerability in a single, concise Korean sentence, focusing on the impact (e.g., remote code execution, privilege escalation).

[ENGLISH SUMMARY]
{english_summary}

[OUTPUT FORMAT]
You MUST return ONLY a single, valid JSON object with the key "analysis_report". Do not add any other text.
Example: {{"analysis_report": "특정 조건에서 원격 코드 실행이 가능한 취약점입니다."}}
"""
            payload = {"prompt": prompt}
            response = self._make_request('sos/analyze', payload, timeout=30)
            
            if response and isinstance(response, dict):
                summary = response.get('analysis_report')
                if summary and isinstance(summary, str):
                    return summary
            
            # AI가 JSON 형식을 지키지 않았을 경우, 응답 전체를 반환
            if response:
                return str(response)

        except Exception as e:
            logging.warning(Color.warn(f"AI 요약 생성 실패: {e}. 영문 요약을 사용합니다."))
        
        return english_summary

    def _create_batch_summarize_prompt(self, cve_list: List[Dict]) -> str:
        """[신규] 여러 CVE 요약을 한번에 처리하기 위한 배치 프롬프트를 생성합니다."""
        prompt = f"""[시스템 역할]
당신은 여러 개의 영문 CVE 요약 정보를 각각 1~2 문장의 간결하고 명확한 한국어 요약으로 변환하는 보안 전문가입니다.
[입력 데이터]
{json.dumps(cve_list, indent=2, ensure_ascii=False)}

[출력 형식]
반드시 다음의 키를 가진 단일 JSON 객체로만 응답하십시오. 다른 설명은 절대 추가하지 마세요.
```jsonc
{{
  "summaries": [
    {{ "cve_id": "<CVE-ID-1>", "korean_summary": "<CVE-1의 한국어 요약>" }},
    {{ "cve_id": "<CVE-ID-2>", "korean_summary": "<CVE-2의 한국어 요약>" }}
  ]
}}
```"""
        return prompt

    def _add_installed_version_to_advisories(self, advisories: List[Dict], installed_packages: List[Dict]) -> List[Dict]:
        """[수정] AI가 선정한 보안 권고 목록에 실제 설치된 패키지 버전 정보를 추가합니다."""
        # 패키지 이름으로 버전을 빠르게 찾기 위한 맵 생성
        # 예: {'kernel': '3.10.0-1160.el7', 'openssh': '7.4p1-21.el7'}
        package_version_map = {pkg['name']: pkg['version'] for pkg in installed_packages}

        for advisory in advisories:
            pkg_name = advisory.get('package')
            if pkg_name and pkg_name in package_version_map:
                # [BUG FIX] HTML 템플릿과의 호환성을 위해 전체 패키지 문자열을 생성합니다.
                installed_version_str = package_version_map[pkg_name]
                fix_version_str = advisory.get('fix_version', 'N/A')
                advisory['installed_version'] = f"{pkg_name}-{installed_version_str}"
                advisory['fix_version'] = f"{pkg_name}-{fix_version_str}"
        
        return advisories
