#!/usr/bin/env python3.11
# -*- coding: utf-8 -*-
# ==============================================================================
# Smart sosreport Analyzer - The Truly Final & Stabilized Edition
# ------------------------------------------------------------------------------
# [혁신] old.py의 전문가 프롬프트를 계승하고 발전시켜, LLM이 최고 수준의
# RHEL 전문가 및 보안 분석가 역할을 수행하도록 AI 분석 로직을 전면 개편했습니다.
# 이제 sos_analyzer는 단순 데이터 전송을 넘어, 동적으로 생성한 전문가 프롬프트를
# 서버에 전달하여 비교할 수 없는 수준의 고품질 분석을 수행합니다.
# ==============================================================================

import argparse
import json
import os
import tarfile
import logging
import datetime
import sys
from pathlib import Path
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 프로젝트 내부 모듈 임포트 ---
from analyzer.ai_analyzer import AIAnalyzer
from analyzer.parser import SosreportParser
from analyzer.report_generator import HTMLReportGenerator
from security_analyzer import SecurityAnalyzer
from knowledge_base import KnowledgeBase
from utils.helpers import Color, json_serializer, log_step

# --- 그래프 라이브러리 설정 ---
try:
    import matplotlib
    matplotlib.use('Agg') # GUI 백엔드 없이 실행
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    IS_MATPLOTLIB_AVAILABLE = True
except ImportError:
    IS_MATPLOTLIB_AVAILABLE = False

# --- 로깅 및 콘솔 출력 설정 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)

def _initialize_matplotlib_font():
    """
    [사용자 요청 반영] Matplotlib의 폰트 설정을 초기화합니다.
    지정된 경로의 'NanumGothicBold.ttf' 폰트를 로드하여 그래프에 적용합니다.
    폰트 파일이 없을 경우, 기본 폰트를 사용하고 경고를 기록합니다.
    """
    if not IS_MATPLOTLIB_AVAILABLE:
        return

    try:
        plt.rcParams['axes.unicode_minus'] = False

        # 스크립트가 위치한 디렉토리를 기준으로 폰트 파일 경로를 설정합니다.
        script_dir = Path(__file__).parent
        font_path = script_dir / 'fonts' / 'NanumGothicBold.ttf'

        if font_path.exists():
            # 폰트 매니저에 폰트 추가
            fm.fontManager.addfont(font_path)
            # Matplotlib의 기본 폰트로 설정
            plt.rcParams['font.family'] = 'NanumGothic'
            logging.info(f"Matplotlib에 커스텀 폰트 'NanumGothic'를 로드했습니다: {font_path}")
        else:
            logging.warning(Color.warn(f"지정된 폰트 파일을 찾을 수 없습니다: {font_path}. Matplotlib의 기본 폰트를 사용합니다. 그래프의 한글이 깨질 수 있습니다."))

    except Exception as e:
        logging.error(f"Matplotlib 폰트 설정 중 예외 발생: {e}. 그래프의 한글이 깨질 수 있습니다.", exc_info=True)

#--- 메인 실행 로직 ---
def main(args: argparse.Namespace):
    # [안정성 강화] 분석 시작 전, 입력된 파일 경로가 유효한지 먼저 확인합니다.
    tar_path = Path(args.tar_path)
    if not tar_path.is_file():
        logging.error(Color.error(f"치명적인 오류 발생: 입력된 파일 경로를 찾을 수 없습니다: '{args.tar_path}'"))
        logging.error(Color.error(f"스크립트가 실행된 현재 작업 디렉토리: '{os.getcwd()}'"))
        logging.error(Color.error("파일의 절대 경로를 사용하거나, 파일이 있는 디렉토리에서 스크립트를 실행해 주세요."))
        sys.exit(1)

    log_step(f"'{tar_path.name}' 분석 시작")

    # [사용자 요청] 임시 디렉터리를 /tmp/sos_analyzer/ 하위에 생성하도록 경로를 지정합니다.
    base_temp_dir = Path("/tmp/sos_analyzer")
    base_temp_dir.mkdir(parents=True, exist_ok=True)

    # [사용자 요청] 실행 로그를 파일로 저장하기 위한 로거 설정
    # 임시 경로에서 hostname을 먼저 파싱하여 로그 파일명을 결정합니다.
    temp_extract_path = Path(tempfile.mkdtemp(prefix="sos-temp-", dir=base_temp_dir))
    try:
        hostname = "unknown"
        with tarfile.open(args.tar_path, 'r:*') as tar:
            # [BUG FIX] sosreport-HOSTNAME-DATE/hostname 과 같은 경로를 정확히 찾기 위해 로직을 수정합니다.
            # 1. 아카이브의 최상위 디렉토리 이름을 먼저 찾습니다.
            top_level_dirs = {Path(m.name).parts[0] for m in tar.getmembers() if m.isdir()}
            if top_level_dirs:
                base_dir = list(top_level_dirs)[0]
                hostname_path_in_tar = f"{base_dir}/hostname"
                
                # 2. 'sosreport-HOSTNAME-DATE/hostname' 경로의 파일을 직접 추출합니다.
                try:
                    hostname_member = tar.getmember(hostname_path_in_tar)
                    hostname_file = tar.extractfile(hostname_member)
                    if hostname_file:
                        hostname = hostname_file.read().decode('utf-8').strip()
                except KeyError:
                    logging.warning(f"'{hostname_path_in_tar}' 파일을 tar 아카이브에서 찾을 수 없습니다.")
    finally:
        shutil.rmtree(temp_extract_path, ignore_errors=True)

    extract_path = Path(tempfile.mkdtemp(prefix="sos-", dir=base_temp_dir))
    logging.info(Color.info(f"임시 디렉터리 생성: {extract_path}"))
    try:
        def safe_tar_filter(tarinfo, path):
            """
            [안정성 강화] tar 압축 해제 시 특수 파일(device, fifo 등)을 건너뛰어
            'Operation not permitted' 오류를 방지하는 필터 함수.
            """
            # path 인자는 현재 로직에서 사용되지 않지만, tarfile.extractall의 filter 시그니처를 맞추기 위해 필요합니다.
            if tarinfo.isdev() or tarinfo.ischr() or tarinfo.isblk() or tarinfo.isfifo():
                logging.warning(f"압축 해제 건너뜀 (특수 파일): {tarinfo.name}")
                return None
            return tarinfo
        logging.info(f"[STEP] EXTRACTING: '{tar_path.name}' 압축 해제 중...")
        with tarfile.open(tar_path, 'r:*') as tar: tar.extractall(path=extract_path, filter=safe_tar_filter)
        logging.info(Color.success("압축 해제 완료."))

        # [사용자 요청] 압축 해제가 성공적으로 완료되면 원본 sosreport 파일을 삭제합니다.
        try:
            tar_path.unlink()
            logging.info(Color.info(f"압축 해제 완료 후 원본 sosreport 파일 삭제: {tar_path.name}"))
        except OSError as e:
            logging.warning(Color.warn(f"원본 sosreport 파일({tar_path.name}) 삭제 중 오류 발생: {e}"))

        # 로그 파일 핸들러 추가
        output_dir = Path(args.output)
        output_dir.mkdir(exist_ok=True)
        log_file_path = output_dir / f"report-{hostname}.log"
        
        root_logger = logging.getLogger()
        # [BUG FIX] 기존 핸들러를 유지하고 파일 핸들러를 추가하여 콘솔과 파일에 모두 로깅
        file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        root_logger.addHandler(file_handler)
        logging.info(f"실행 로그를 '{log_file_path}' 파일에 저장합니다.")

        logging.info("STATUS:PARSING_SYSTEM") # 상태 업데이트
        logging.info("STATUS:PARSING_SYSTEM") # 상태 업데이트
        log_step("[STEP 1/5] 시스템 데이터 파싱")
        parser = SosreportParser(extract_path)
        # [BUG FIX] parser.parse_all()은 (metadata, sar_data) 튜플을 반환하므로, 두 변수로 나누어 받습니다.
        metadata, sar_data_from_parser = parser.parse_all()
        
        hostname = metadata.get('system_info', {}).get('hostname', 'unknown')

        logging.info("STATUS:PARSING_SAR") # 상태 업데이트
        log_step("[STEP 2/5] SAR 성능 데이터 처리")
        sar_data = sar_data_from_parser # parse_all에서 반환된 sar_data를 사용합니다.
        parser.sar_data = sar_data # 이후 분석 단계에서 sar_data를 참조할 수 있도록 저장

        metadata_path = output_dir / f"metadata-{hostname}.json"
        sar_data_path = output_dir / f"sar_data-{hostname}.json"
        metadata_path.write_text(json.dumps(metadata, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        sar_data_path.write_text(json.dumps(sar_data, indent=2, default=json_serializer, ensure_ascii=False), encoding='utf-8')
        logging.info(Color.success(f"파싱된 데이터 파일 저장 완료: {metadata_path.name}, {sar_data_path.name}"))

        # [BUG FIX] --server-url에 포함된 특정 API 경로를 제거하여 기본 URL만 사용하도록 수정합니다.
        # 이렇게 하면 AIAnalyzer가 여러 다른 API 엔드포인트(cve/analyze, sos/analyze_system)를 올바르게 호출할 수 있습니다.
        base_server_url = args.server_url
        # [BUG FIX] URL에서 '/api/...' 부분을 제거하여 순수 base URL만 남깁니다.
        if '/api/' in base_server_url:
            base_server_url = base_server_url.split('/api/')[0] # type: ignore

        logging.info("STATUS:ANALYZING") # 상태 업데이트
        logging.info("STATUS:ANALYZING") # 상태 업데이트
        log_step("[STEP 3/5] AI 및 규칙 기반 종합 분석")
        ai_analyzer = AIAnalyzer(base_server_url, parser.report_date)
        logging.info("  - 병렬 AI 분석 시작 (시스템 종합 & CVE 보안 권고)...")
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix='AI_Analysis') as executor:
            # [개선] AI 분석과 보안 권고 분석을 병렬로 실행하여 시간 단축
            future_ai = executor.submit(ai_analyzer.get_structured_analysis, metadata_path, sar_data_path)
            future_sec = executor.submit(ai_analyzer.analyze_security_advisories, metadata) # 새 로직으로 호출
            
            structured_analysis = future_ai.result()
            security_advisories = future_sec.result() # type: ignore

            # [BUG FIX] _add_installed_version_to_advisories는 AIAnalyzer 클래스의 메서드이므로, ai_analyzer 인스턴스를 통해 호출해야 합니다.
            # [사용자 요청] AI가 선정한 보안 위협 목록에 설치된 패키지 버전 정보를 추가합니다.
            advisories_with_version = ai_analyzer._add_installed_version_to_advisories(security_advisories, metadata.get('installed_packages', []))
            metadata['security_advisories'] = advisories_with_version
        logging.info(f"  - AI 분석 완료: {len(structured_analysis.get('recommendations', []))}개 권장사항, {len(advisories_with_version)}개 보안 권고")

        # [사용자 요청] 분석 완료 후 총 LLM 요청 횟수를 로그에 기록합니다.
        logging.info(Color.info(f"  -> 총 LLM 요청 횟수: {ai_analyzer.llm_request_count}회"))

        logging.info("  - 로컬 보안 감사 및 규칙 기반 진단 시작...")
        security_analyzer = SecurityAnalyzer()
        security_findings = security_analyzer.analyze(metadata)
        structured_analysis['security_audit_findings'] = security_findings

        # [개선] 규칙 기반 분석(Knowledge Base) 실행
        # [BUG FIX] 현재 작업 디렉토리에 상관없이 스크립트 위치를 기준으로 'rules' 디렉토리의 절대 경로를 사용합니다.
        script_dir = Path(__file__).resolve().parent
        kb = KnowledgeBase(rules_dir=script_dir / 'rules')
        kb_findings = kb.analyze(metadata)
        structured_analysis['kb_findings'] = kb_findings # type: ignore

        logging.info("STATUS:GENERATING_GRAPHS") # 상태 업데이트
        logging.info("STATUS:GENERATING_GRAPHS") # 상태 업데이트
        log_step("[STEP 4/5] 성능 그래프 생성")
        # [BUG FIX] AI 분석 결과가 리포트에 누락되는 문제를 해결합니다.
        # HTMLReportGenerator 생성자에 AI 분석 결과인 structured_analysis를
        # ai_analysis 인자로 정확하게 전달하도록 수정합니다.
        reporter = HTMLReportGenerator(metadata=metadata, sar_data=sar_data, ai_analysis=structured_analysis, hostname=hostname, report_date=parser.report_date, device_map=parser.device_map)
        
        # [사용자 요청] 그래프 생성 시, 저장된 sar_data.json 파일을 다시 읽어 사용합니다.
        logging.info(f"  - 그래프 생성을 위해 '{sar_data_path.name}' 파일 로딩 중...")
        try:
            with open(sar_data_path, 'r', encoding='utf-8') as f:
                sar_data_for_graph = json.load(f)
            reporter.sar_data = sar_data_for_graph # 리포터의 sar_data를 파일에서 읽은 것으로 교체
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(Color.error(f"sar_data.json 파일을 읽는 중 오류 발생: {e}. 그래프 생성이 제한될 수 있습니다."))

        generated_graphs = reporter._generate_graphs() # 그래프 생성
        logging.info("STATUS:GENERATING_REPORT") # 상태 업데이트
        logging.info("STATUS:GENERATING_REPORT") # 상태 업데이트
        log_step("[STEP 5/5] HTML 보고서 생성")
        html_content = reporter.generate(generated_graphs)
        
        report_path = output_dir / f"report-{hostname}.html"
        report_path.write_text(html_content, encoding='utf-8')
        # [BUG FIX] AIBox_Server.py가 성공을 감지할 수 있도록 로그 메시지를 서버의 기대 형식과 정확히 일치시킵니다.
        # ANSI 색상 코드를 제거하고, "HTML 보고서 저장 완료:" 형식으로 출력합니다.
        logging.info(f"HTML 보고서 저장 완료: {report_path}")
        
        # [사용자 요청] 동적 그래프 팝업 HTML 파일 저장
        for key, result in generated_graphs.items():
            if result and isinstance(result, tuple) and len(result) == 2:
                _, interactive_html = result
                if interactive_html:
                    popup_filename = f"popup_{key}_{hostname}.html"
                    popup_path = output_dir / popup_filename
                    logging.debug(f"  - 동적 그래프 팝업 파일 저장: {popup_filename}")
                    popup_path.write_text(f'<!DOCTYPE html><html><head><title>{key.replace("_", " ").title()}</title></head><body style="margin:0;padding:0;">{interactive_html}</body></html>', encoding='utf-8')

        # [신규] 개별 디스크 I/O 그래프 페이지 생성
        logging.info("  - 디스크 상세 정보 팝업 페이지 생성 중...")
        disk_report_result = reporter._generate_individual_disk_graphs_page(sar_data)
        if disk_report_result:
            individual_disk_report_html, disk_popups = disk_report_result
            disk_report_path = output_dir / f"sar_gui_disk-{hostname}.html"
            disk_report_path.write_text(individual_disk_report_html, encoding='utf-8')
            logging.info(f"  - 개별 디스크 I/O 보고서 저장 완료: {disk_report_path.name}")
            # 디스크 팝업 파일 저장
            for popup_filename, popup_html in disk_popups.items():
                popup_path = output_dir / popup_filename
                logging.debug(f"  - 디스크 상세 동적 그래프 팝업 파일 저장: {popup_filename}")
                popup_path.write_text(f'<!DOCTYPE html><html><head><title>Disk Detail</title></head><body style="margin:0;padding:0;">{popup_html}</body></html>', encoding='utf-8')

        # [신규] 개별 NIC 그래프 페이지 생성
        logging.debug("  - 네트워크 상세 정보 팝업 페이지 생성 중...")
        nic_report_result = reporter._generate_individual_nic_graphs_page(sar_data, metadata)
        if nic_report_result:
            individual_nic_report_html, nic_popups = nic_report_result
            nic_report_path = output_dir / f"sar_nic_detail-{hostname}.html"
            nic_report_path.write_text(individual_nic_report_html, encoding='utf-8')
            logging.info(f"  - 개별 NIC 보고서 저장 완료: {nic_report_path.name}")
            # NIC 팝업 파일 저장
            for popup_filename, popup_html in nic_popups.items():
                popup_path = output_dir / popup_filename
                logging.debug(f"  - NIC 상세 동적 그래프 팝업 파일 저장: {popup_filename}")
                popup_path.write_text(f'<!DOCTYPE html><html><head><title>NIC Detail</title></head><body style="margin:0;padding:0;">{popup_html}</body></html>', encoding='utf-8')
        logging.info(Color.success(f"\n모든 보고서 및 데이터 파일 생성이 완료되었습니다. 경로: {output_dir}"))

    except Exception as e:
        # [BUG FIX] sys.exit(1)을 호출하면 서버가 오류의 원인을 알 수 없습니다.
        # 대신, 오류 로그를 표준 출력으로 명확히 남겨 서버가 실패 원인을 파악하도록 합니다.
        logging.error(Color.error(f"치명적인 오류 발생: {e}"), exc_info=True)
        # sys.exit(1) # 이 부분을 제거합니다.
    finally:
        log_step("분석 프로세스 종료")
        if extract_path.exists():
            shutil.rmtree(extract_path, ignore_errors=True)
            logging.info(f"임시 디렉터리 정리 완료: {extract_path}")
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Smart sosreport Analyzer")
    # [BUG FIX] 서버에서 모든 인자를 명령줄로 전달하는 방식으로 통일합니다.
    # 위치 인자로 파일 경로를 받고, --server-url과 --output을 옵션 인자로 받도록 수정합니다.
    parser.add_argument("tar_path", help="분석할 sosreport tar 아카이브 경로")
    parser.add_argument("--server-url", help="AI 분석을 위한 ABox_Server.py의 API 엔드포인트 URL")
    parser.add_argument("--output", default="output", help="보고서 및 데이터 저장 디렉토리")    
    parser.add_argument("--debug", action='store_true', help="디버그 레벨 로그를 활성화합니다.")
    
    args = parser.parse_args()

    # [BUG FIX] 필수 인자인 tar_path와 server_url이 모두 제공되었는지 확인합니다.
    if not args.tar_path or not args.server_url:
        logging.error(Color.error("치명적인 오류: 스크립트 실행 시 'tar_path'와 '--server-url' 인자가 모두 필요합니다."))
        # [BUG FIX] 서버가 실패를 감지할 수 있도록 표준 출력으로 명확한 실패 메시지를 남깁니다.
        # 이 메시지는 AIBox_Server.py의 run_analysis_in_background 함수에서 감지됩니다.
        print("ANALYSIS_FAILED: Missing required arguments.")
        sys.exit(1)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.info(Color.warn("디버그 로깅이 활성화되었습니다."))

    _initialize_matplotlib_font()
    
    try:
        main(args)
    except Exception as e:
        logging.error(Color.error(f"분석 프로세스 중 예기치 않은 오류 발생: {e}"), exc_info=True)
        print(f"ANALYSIS_FAILED: An unexpected error occurred during analysis: {e}")
