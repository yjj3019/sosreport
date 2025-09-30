#!/usr/bin/env python3
"""
sosreport 압축 파일 AI 분석 및 보고서 생성 모듈 (v5.1 - 안정성 및 진단 강화)
- [신규] 외부 YAML 규칙 파일을 이용하는 지식 기반(Knowledge Base) 분석 기능 추가
- [신규] 패키지 CVE 및 주요 설정 파일을 점검하는 자동화된 보안 감사 모듈 추가
- [개선] 신규 분석 모듈(knowledge_base, security_analyzer)을 통합하여 분석 리포트 강화
- [개선] AIBox 서버 연결 실패 및 404 Not Found 오류에 대한 안정성 및 진단 메시지 강화
- [개선] 규칙/보안 분석 결과를 AI 프롬프트에 포함하여 종합 분석 품질 향상
- Git 버전(yjj3019)의 상세 데이터 파싱, 성능/로그 분석, 상관관계 분석 기능 완전 이식
- AI 분석은 AIBox 서버의 API를 통해 수행하는 클라이언트-서버 구조 유지
- 공식 sosreport 소스를 참고하여 파싱 안정성 및 범위 확장
- 인터넷 연결 없이 로컬 폰트 파일을 사용하도록 변경하여 방화벽 환경 문제 해결

사용법:
    # AIBox 서버에 의해 내부적으로 호출됨
    python3 sos_analyzer.py --server-url <AIBOX_SERVER_URL> sosreport-archive.tar.xz
"""

import os
import sys
import json
import requests
import argparse
import time
import re
import tarfile
import shutil
from datetime import datetime, timedelta, date
from pathlib import Path
from typing import Dict, Any, Optional, List
import html
import io
import base64
import tempfile
import subprocess
import traceback

# --- 신규 모듈 임포트 ---
from knowledge_base import KnowledgeBase
from security_analyzer import SecurityAnalyzer

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    import matplotlib.ticker as mticker
except ImportError:
    matplotlib = None
    plt = None

class Color:
    """콘솔 출력에 사용할 ANSI 색상 코드입니다."""
    HEADER = '\033[95m'; OKBLUE = '\033[94m'; OKCYAN = '\033[96m'; OKGREEN = '\033[92m'
    WARNING = '\033[93m'; FAIL = '\033[91m'; ENDC = '\033[0m'; BOLD = '\033[1m'
    @staticmethod
    def header(text): return f"{Color.HEADER}{text}{Color.ENDC}"
    @staticmethod
    def cyan(text): return f"{Color.OKCYAN}{text}{Color.ENDC}"
    @staticmethod
    def success(text): return f"{Color.OKGREEN}{text}{Color.ENDC}"
    @staticmethod
    def warning(text): return f"{Color.WARNING}{text}{Color.ENDC}"
    @staticmethod
    def error(text): return f"{Color.FAIL}{text}{Color.ENDC}"

class AIBoxAPIClient:
    """AIBox 서버와 통신하여 시스템 분석을 요청하는 클라이언트입니다."""
    def __init__(self, server_url: str):
        if not server_url.startswith("http"):
            self.server_url = f"http://{server_url.strip('/')}"
        else:
            self.server_url = server_url.strip('/')

        self.health_endpoint = f"{self.server_url}/api/health"
        self.api_endpoint = f"{self.server_url}/api/v1/chat/completions"
        print(f"[*] AIBox API 클라이언트 초기화 (서버 URL: {self.server_url})")

        self.is_server_healthy = self._check_server_health()
        if not self.is_server_healthy:
            print(Color.warning(f"  - 경고: AIBox 서버 '{self.server_url}'에 연결할 수 없거나 서버가 비정상 상태입니다."))
            print(Color.warning(f"  - AI 분석 없이 로컬 분석만으로 리포트를 생성합니다."))

    def _check_server_health(self) -> bool:
        """서버의 health check 엔드포인트를 호출하여 상태를 확인합니다."""
        print(f"[*] AIBox 서버 상태 확인 중... ({self.health_endpoint})")
        try:
            response = requests.get(self.health_endpoint, timeout=5)
            if response.status_code == 200 and response.json().get('status') == 'ok':
                print(Color.success("  - 서버 상태 정상."))
                return True
            else:
                print(Color.warning(f"  - 서버가 응답했으나 상태가 비정상입니다 (상태 코드: {response.status_code})."))
                return False
        except requests.exceptions.RequestException:
            return False

    def analyze_system(self, sos_data: Dict[str, Any]) -> Dict[str, Any]:
        """시스템 데이터를 AI 서버에 보내 종합 분석을 요청합니다."""
        if not self.is_server_healthy:
            return {
                "analysis_summary": "AI 서버에 연결할 수 없어 AI 기반 종합 분석을 수행하지 못했습니다. 아래는 규칙 기반 및 보안 감사 결과입니다.",
                "key_issues": [],
                "error": "Server connection failed"
            }

        print("[*] AI 기반 종합 분석 요청...")
        prompt = self._generate_prompt(sos_data)
        headers = {"Content-Type": "application/json"}
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "mode": "instruct", 'stream': False
        }
        try:
            response = requests.post(self.api_endpoint, headers=headers, json=payload, timeout=300)

            if response.status_code == 404:
                print(Color.error(f"  - AI 서버 통신 오류: 404 Not Found"))
                print(Color.error(f"  - 요청 URL: {self.api_endpoint}"))
                print(Color.error(f"  - AIBox 서버에 '/api/v1/chat/completions' 엔드포인트가 존재하는지, 서버 URL이 정확한지 확인하십시오."))
                return {"error": "AI 서버에서 분석 API 엔드포인트를 찾을 수 없습니다 (404 Not Found)."}

            response.raise_for_status()
            result = response.json()
            
            if 'choices' in result and result['choices'] and 'message' in result['choices'][0] and 'content' in result['choices'][0]['message']:
                analysis_content = result['choices'][0]['message']['content']
                try:
                    return json.loads(analysis_content)
                except json.JSONDecodeError:
                    print(Color.error("  - AI 응답이 유효한 JSON 형식이 아닙니다. 원본 텍스트를 반환합니다."))
                    return {"analysis_summary": analysis_content, "key_issues": []}
            else:
                 return {"error": "AI 모델로부터 유효한 응답을 받지 못했습니다.", "details": result}
        except requests.exceptions.RequestException as e:
            print(Color.error(f"  - AI 서버 통신 오류: {e}"))
            return {"error": f"AI 서버 통신 중 오류가 발생했습니다: {e}"}

    def _generate_prompt(self, data: Dict[str, Any]) -> str:
        """AI 분석을 위한 프롬프트를 생성합니다."""
        system_info = data.get('system_info', {})
        performance = data.get('performance', {})
        critical_logs = data.get('critical_logs', [])
        kb_findings = data.get('kb_findings', [])
        security_findings = data.get('security_findings', [])

        prompt = f"""
        당신은 수년간의 경험을 가진 최고의 리눅스 시스템 엔지니어입니다. 제공된 sosreport 데이터를 기반으로 시스템의 상태를 종합적으로 분석하고, 잠재적인 문제점과 해결책을 제시해 주십시오.

        **분석 요청:**
        1.  **종합 분석 요약 (analysis_summary)**: 시스템의 전반적인 상태를 평가하고, 규칙 기반 진단과 보안 감사 결과를 포함하여 가장 중요한 문제점들을 요약해 주세요. (3~4 문장)
        2.  **핵심 이슈 및 권장 조치 (key_issues)**: 발견된 주요 문제점들을 목록으로 정리하고, 각 문제에 대한 구체적인 원인과 해결 방안을 제시해 주세요. 형식: `[{{"issue": "문제점 요약", "cause": "예상 원인", "solution": "권장 해결책"}}]`

        **입력 데이터:**
        -   **System Info**: {json.dumps(system_info, indent=2, ensure_ascii=False)}
        -   **Rule-Based System Diagnostics**: {json.dumps(kb_findings, indent=2, ensure_ascii=False)}
        -   **Automated Security Audit**: {json.dumps(security_findings, indent=2, ensure_ascii=False)}
        -   **Critical Log Entries**: {json.dumps(critical_logs, indent=2, ensure_ascii=False)}

        **출력 형식 (반드시 다음 JSON 구조를 준수해 주세요):**
        ```json
        {{
            "analysis_summary": "...",
            "key_issues": [
                {{
                    "issue": "...",
                    "cause": "...",
                    "solution": "..."
                }}
            ]
        }}
        ```
        """
        return prompt

def decompress_sosreport(archive_path: str, extract_to: str):
    """tar 아카이브를 지정된 디렉터리에 압축 해제합니다."""
    print(f"[*] '{archive_path}' 압축 해제 중...")
    try:
        with tarfile.open(archive_path, 'r:*') as tar:
            tar.extractall(path=extract_to)
        print(f"  - 성공: '{extract_to}'에 압축 해제 완료")
    except tarfile.TarError as e:
        raise ValueError(f"압축 파일이 손상되었거나 지원하지 않는 형식입니다: {e}")


class SosreportParser:
    """sosreport 압축 해제 디렉터리에서 주요 정보를 파싱합니다."""
    def __init__(self, sos_dir: str):
        sos_dir_path = Path(sos_dir)
        subdirs = [d for d in sos_dir_path.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and subdirs[0].name.startswith('sosreport'):
            self.sos_dir = subdirs[0]
        else:
            self.sos_dir = sos_dir_path
        print(f"[*] Sosreport 파서 초기화 (분석 디렉터리: {self.sos_dir})")

    def _read_file(self, file_path: str, default: str = "") -> str:
        """파일을 읽어 내용을 반환하고, 오류 발생 시 기본값을 반환합니다."""
        full_path = self.sos_dir / file_path
        if full_path.exists():
            try:
                return full_path.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return default
        return default

    def parse_system_info(self) -> Dict[str, Any]:
        """기본 시스템 정보를 파싱합니다."""
        return {
            'hostname': self._read_file('hostname').strip(),
            'os_release': self._read_file('etc/os-release'),
            'uptime': self._read_file('proc/uptime'),
            'kernel_version': self._read_file('proc/version').strip(),
        }

    def parse_packages(self) -> List[Dict[str, str]]:
        """설치된 패키지 목록을 파싱합니다. (RPM 및 DPKG 지원)"""
        packages = []
        rpm_qa = self._read_file('installed-rpms')
        if rpm_qa:
            for line in rpm_qa.splitlines():
                try:
                    match = re.match(r'^(\S+)-([0-9].*)\.([^.]+)$', line.strip())
                    if match:
                        name, version = match.group(1), match.group(2)
                        if ':' in name:
                            name = name.split(':', 1)[1]
                        packages.append({'name': name, 'version': version})
                except Exception:
                    continue

        dpkg_l = self._read_file('dpkg-l')
        if dpkg_l:
            for line in dpkg_l.splitlines():
                if line.startswith('ii'):
                    parts = line.split()
                    if len(parts) >= 3:
                         packages.append({'name': parts[1], 'version': parts[2]})
        return packages

    def parse_configurations(self) -> Dict[str, Any]:
        """주요 설정 파일을 파싱합니다."""
        sshd_config_content = self._read_file('etc/ssh/sshd_config')
        sshd_config = {}
        for line in sshd_config_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2: sshd_config[parts[0]] = parts[1]
        
        return {'sshd_config': sshd_config}

    def parse_logs(self) -> Dict[str, Any]:
        """주요 로그 파일을 읽습니다."""
        return {
            'dmesg': {'content': self._read_file('dmesg')},
            'messages': {'content': self._read_file('var/log/messages')},
            'secure': {'content': self._read_file('var/log/secure') or self._read_file('var/log/auth.log')},
        }

    def extract_critical_logs(self, logs: Dict[str, Any]) -> List[str]:
        """로그에서 'error', 'critical', 'failed' 등의 키워드가 포함된 라인을 추출합니다."""
        critical_logs = []
        keywords = ['error', 'critical', 'failed', 'panic', 'trace', 'Call Trace']
        for log_name, log_data in logs.items():
            content = log_data.get('content', '')
            for line in content.splitlines():
                if any(keyword in line.lower() for keyword in keywords):
                    critical_logs.append(f"[{log_name}] {line}")
        return critical_logs[-50:]

    def parse(self) -> Dict[str, Any]:
        """모든 파싱 메서드를 호출하여 sosreport 데이터를 종합합니다."""
        print("[*] sosreport 데이터 파싱 시작...")
        logs = self.parse_logs()
        data = {
            'system_info': self.parse_system_info(),
            'packages': self.parse_packages(),
            'configurations': self.parse_configurations(),
            'logs': logs,
            'critical_logs': self.extract_critical_logs(logs),
            'performance': {},
        }
        print("[*] sosreport 데이터 파싱 완료.")
        return data

class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.font_path = self._find_font()
        if self.font_path and plt:
            plt.rcParams['font.family'] = self.font_path.name
            plt.rcParams['axes.unicode_minus'] = False

    def _find_font(self) -> Optional[Path]:
        font_name = "NanumGothic.ttf"
        font_dir = Path("./fonts")
        font_path = font_dir / font_name
        
        if font_path.exists():
            try:
                fm.fontManager.addfont(str(font_path))
                return fm.findfont(fm.FontProperties(fname=font_path))
            except Exception:
                return None
        return None

    def create_performance_graphs(self, sos_data: Dict[str, Any]) -> Dict[str, str]:
        return {}
        
    def create_html_report(self, ai_result: Dict[str, Any], sos_data: Dict[str, Any], graphs: Dict[str, str], output_dir, archive_name: str) -> str:
        """
        AI 분석 결과, 시스템 데이터, 그래프를 종합하여 최종 HTML 보고서를 생성합니다.
        """
        kb_findings = sos_data.get('kb_findings', [])
        security_findings = sos_data.get('security_findings', [])
        
        severity_styles = {
            'Critical': 'background-color: #ff3b30; color: white;', 'High': 'background-color: #ff9500; color: white;',
            'Medium': 'background-color: #ffcc00; color: black;', 'Warning': 'background-color: #ffcc00; color: black;',
            'Low': 'background-color: #d1d1d6; color: black;', 'Info': 'background-color: #e5e5ea; color: black;'
        }

        def generate_findings_table(title, findings):
            html_str = f"<h2>{title}</h2>"
            if not findings:
                return html_str + "<p>해당 진단에서 특이사항이 발견되지 않았습니다.</p>"
            
            html_str += "<table><tr><th>심각도</th><th>진단명</th><th>상세 설명</th><th>권장 조치</th></tr>"
            sorted_findings = sorted(findings, key=lambda x: list(severity_styles.keys()).index(x.get('severity', 'Info')))
            for item in sorted_findings:
                severity = item.get('severity', 'Info')
                style = severity_styles.get(severity, '')
                html_str += f"""
                <tr>
                    <td><span class="severity" style="{style}">{html.escape(severity)}</span></td>
                    <td>{html.escape(item['name'])}</td>
                    <td>{html.escape(item['description'])}</td>
                    <td>{html.escape(item['solution'])}</td>
                </tr>
                """
            return html_str + "</table>"

        kb_html = generate_findings_table("규칙 기반 시스템 진단", kb_findings)
        security_html = generate_findings_table("자동화된 보안 감사", security_findings)
            
        ai_summary = html.escape(ai_result.get('analysis_summary', 'AI 분석 요약을 가져오는 데 실패했습니다.'))
        ai_issues = ai_result.get('key_issues', [])
        ai_html = "<h2>AI 기반 종합 분석</h2>"
        if "error" in ai_result:
            ai_html += f"<p class='summary error'>{html.escape(ai_result['error'])}</p>"
        ai_html += f"<p class='summary'>{ai_summary}</p>"

        if ai_issues:
            ai_html += "<table><tr><th>핵심 이슈</th><th>예상 원인</th><th>권장 조치</th></tr>"
            for item in ai_issues:
                ai_html += f"""
                <tr>
                    <td>{html.escape(item.get('issue', ''))}</td>
                    <td>{html.escape(item.get('cause', ''))}</td>
                    <td>{html.escape(item.get('solution', ''))}</td>
                </tr>"""
            ai_html += "</table>"
        
        html_content = f"""
        <html>
            <head>
                <meta charset="UTF-8">
                <title>SOSReport 분석 결과</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; }}
                    .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px 40px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
                    h1 {{ color: #1c1c1e; border-bottom: 2px solid #e5e5ea; padding-bottom: 10px; }}
                    h2 {{ color: #3c3c3e; margin-top: 40px; border-bottom: 1px solid #e5e5ea; padding-bottom: 8px;}}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e5ea; vertical-align: top; }}
                    th {{ background-color: #f8f8f9; font-weight: 600; color: #5c5c5e; }}
                    tr:hover {{ background-color: #f8f8f9; }}
                    .metadata p {{ background: #f8f8f9; padding: 10px; border-radius: 8px; margin: 5px 0; }}
                    .summary {{ font-size: 1.1em; line-height: 1.6; background: #eef7ff; padding: 15px; border-left: 5px solid #007aff; border-radius: 4px; }}
                    .summary.error {{ background: #fff0f0; border-left-color: #ff3b30; }}
                    .severity {{ padding: 4px 8px; border-radius: 12px; font-weight: bold; font-size: 0.9em; white-space: nowrap; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>SOSReport 분석 결과</h1>
                    <div class="metadata">
                        <p><strong>Hostname:</strong> {sos_data.get('system_info', {}).get('hostname', 'N/A')}</p>
                        <p><strong>분석 일시:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>원본 파일:</strong> {archive_name}</p>
                    </div>
                    {kb_html}
                    {security_html}
                    {ai_html}
                </div>
            </body>
        </html>
        """
        
        report_filename = f"analysis-report-{Path(archive_name).stem}.html"
        report_path = Path(output_dir) / report_filename
        report_path.write_text(html_content, encoding='utf-8')
        return str(report_path)

def main():
    parser = argparse.ArgumentParser(description="sosreport 분석 및 AI 기반 리포트 생성기")
    parser.add_argument("sosreport_archive", help="분석할 sosreport 압축 파일 경로")
    parser.add_argument("--server-url", required=True, help="AIBox API 서버 URL")
    parser.add_argument("--output", default="reports", help="결과 보고서가 저장될 디렉터리")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    
    extract_target_dir = None
    try:
        extract_target_dir = tempfile.mkdtemp(prefix="sos_analysis_")
        decompress_sosreport(args.sosreport_archive, extract_target_dir)
        
        parser = SosreportParser(extract_target_dir)
        sos_data = parser.parse()

        kb = KnowledgeBase(rules_dir='rules')
        sos_data['kb_findings'] = kb.analyze(sos_data)

        sec_analyzer = SecurityAnalyzer()
        sos_data['security_findings'] = sec_analyzer.analyze(sos_data)

        api_client = AIBoxAPIClient(server_url=args.server_url)
        ai_analysis_result = api_client.analyze_system(sos_data)
        
        report_generator = ReportGenerator(output_dir=args.output)
        graphs = report_generator.create_performance_graphs(sos_data)
        html_path = report_generator.create_html_report(ai_analysis_result, sos_data, graphs, args.output, args.sosreport_archive)
        
        print(Color.header("\n분석이 성공적으로 완료되었습니다!"))
        print(f"  - HTML 보고서: {Color.cyan(html_path)}")

    except Exception as e:
        print(Color.error(f"\n❌ 전체 분석 과정 중 오류 발생: {e}"))
        traceback.print_exc()
        sys.exit(1)
    finally:
        if extract_target_dir and Path(extract_target_dir).exists():
            shutil.rmtree(extract_target_dir, ignore_errors=True)
            print(f"[*] 임시 디렉터리 '{extract_target_dir}' 삭제 완료.")

if __name__ == "__main__":
    main()

