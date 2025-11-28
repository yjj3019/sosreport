# -*- coding: utf-8 -*-
# ==============================================================================
# Security Analyzer Module v1.0
# ------------------------------------------------------------------------------
# 기능:
# 1. sosreport에서 추출된 데이터를 기반으로 자동화된 보안 감사를 수행
# 2. 알려진 CVE 취약점 스캔 (패키지 버전 기준)
# 3. 주요 시스템 설정 파일의 보안 규정 준수 여부 검사
# 4. 인증 로그 분석을 통한 잠재적 침해 위협 탐지
# ==============================================================================

from typing import List, Dict, Any
import re
import logging

class SecurityAnalyzer:
    """
    sosreport 데이터를 분석하여 보안 취약점과 설정 오류를 찾아내는 클래스.
    """

    def __init__(self):
        """보안 분석기 초기화."""
        # 실제 환경에서는 오프라인 CVE DB를 로드하거나 API 클라이언트를 초기화합니다.
        logging.info("보안 분석 모듈이 초기화되었습니다.")

    def _audit_ssh_configuration(self, sshd_config: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        SSH 서버 설정 파일(sshd_config)의 보안 모범 사례 준수 여부를 감사합니다.
        
        :param sshd_config: sshd_config 파일의 파싱된 내용
        :return: 발견된 보안 권고 사항 리스트
        """
        findings = []
        if not sshd_config:
            return findings

        logging.info("  - SSH 설정 감사 중...")
        # 루트 로그인 허용 여부 검사
        if sshd_config.get('PermitRootLogin', 'yes').lower() == 'yes':
            findings.append({
                'id': 'SEC-SSH-001',
                'name': "SSH 루트 직접 로그인 허용",
                'severity': "High",
                'description': "'PermitRootLogin'이 'yes'로 설정되어 있어 루트 계정의 직접적인 원격 로그인을 허용합니다. 이는 시스템에 대한 무차별 대입 공격(Brute-force attack)의 주된 표적이 될 수 있습니다.",
                'solution': "sshd_config 파일에서 'PermitRootLogin' 값을 'no'로 변경하고 sshd 서비스를 재시작하십시오. 일반 사용자로 로그인한 후 'su' 또는 'sudo'를 사용하여 루트 권한을 얻는 것이 안전합니다.",
                'category': 'Security Audit (Config)'
            })
            
        # 패스워드 인증 허용 여부 검사
        if sshd_config.get('PasswordAuthentication', 'yes').lower() == 'yes':
            findings.append({
                'id': 'SEC-SSH-002',
                'name': "SSH 패스워드 기반 인증 사용",
                'severity': "Medium",
                'description': "패스워드 기반 인증은 무차별 대입 공격에 취약할 수 있습니다.",
                'solution': "더 안전한 공개 키 기반 인증(Public Key Authentication)을 사용하고, sshd_config에서 'PasswordAuthentication'을 'no'로 설정하는 것을 권장합니다.",
                'category': 'Security Audit (Config)'
            })
        return findings

    def _audit_sudoers_configuration(self, sudoers_content: str) -> List[Dict[str, Any]]:
        """
        sudoers 파일 내용을 분석하여 NOPASSWD 설정과 같은 보안 위험을 감사합니다.
        
        :param sudoers_content: /etc/sudoers 파일의 내용
        :return: 발견된 보안 권고 사항 리스트
        """
        findings = []
        if not sudoers_content or sudoers_content == 'N/A':
            return findings

        logging.info("  - sudoers 설정 감사 중...")
        # NOPASSWD 키워드가 포함된 라인을 찾되, 주석 처리된 라인은 제외
        if re.search(r'^\s*[^#].*\bNOPASSWD\b', sudoers_content, re.MULTILINE):
            findings.append({
                'id': 'SEC-SUDO-001', 'name': "sudo 사용 시 패스워드 불필요 (NOPASSWD)", 'severity': "High", 'description': "sudoers 파일에 'NOPASSWD' 설정이 있어, 특정 사용자나 그룹이 패스워드 없이 루트 권한을 획득할 수 있습니다. 이는 시스템 보안에 심각한 위협이 될 수 있습니다.", 'solution': "반드시 필요한 경우가 아니라면 sudoers 파일에서 'NOPASSWD' 설정을 제거하여 모든 권한 상승에 패스워드를 요구하도록 하십시오.", 'category': 'Security Audit (Config)'
            })
        return findings

    def analyze(self, sos_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        전체 보안 감사를 수행합니다.
        
        :param sos_data: sos_analyzer에 의해 파싱된 전체 데이터 딕셔너리
        :return: 발견된 모든 보안 관련 문제점 리스트
        """
        logging.info("보안 감사 분석 시작...")
        all_findings = []

        # 2. SSH 설정 감사
        sshd_config = sos_data.get('configurations', {}).get('sshd_config', {})
        ssh_findings = self._audit_ssh_configuration(sshd_config)
        all_findings.extend(ssh_findings)
        
        # 3. sudoers 설정 감사
        # [개선] sos_analyzer가 etc/sudoers 파일을 읽어오도록 수정해야 합니다.
        # 우선은 'configurations'에 sudoers_content가 있다고 가정하고 구현합니다.
        sudoers_content = sos_data.get('configurations', {}).get('sudoers_content', '')
        sudo_findings = self._audit_sudoers_configuration(sudoers_content)
        all_findings.extend(sudo_findings)

        logging.info(f"보안 감사 분석 완료. 총 {len(all_findings)}개의 잠재적 보안 이슈를 발견했습니다.")
        return all_findings
