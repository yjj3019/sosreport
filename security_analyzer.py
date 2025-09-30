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

class SecurityAnalyzer:
    """
    sosreport 데이터를 분석하여 보안 취약점과 설정 오류를 찾아내는 클래스.
    """

    def __init__(self):
        """보안 분석기 초기화."""
        # 실제 환경에서는 오프라인 CVE DB를 로드하거나 API 클라이언트를 초기화합니다.
        # 여기서는 데모를 위해 간단한 딕셔너리를 사용합니다.
        self.cve_database = {
            'openssh-server': {
                '8.2p1-4ubuntu0.1': [{'cve': 'CVE-2023-1234', 'severity': 'High'}],
            },
            'kernel': {
                '5.4.0-80-generic': [{'cve': 'CVE-2023-5678', 'severity': 'Critical'}],
            }
        }
        print("[*] 보안 분석 모듈이 초기화되었습니다.")

    def _check_cve_vulnerabilities(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        설치된 패키지 목록을 기반으로 알려진 CVE 취약점을 확인합니다.
        
        :param packages: {'name': '...', 'version': '...'} 형태의 딕셔너리 리스트
        :return: 발견된 CVE 정보 리스트
        """
        findings = []
        if not packages:
            return findings

        print("  - CVE 취약점 스캔 중...")
        for pkg in packages:
            pkg_name = pkg.get('name')
            pkg_version = pkg.get('version')
            if pkg_name in self.cve_database and pkg_version in self.cve_database[pkg_name]:
                for cve_info in self.cve_database[pkg_name][pkg_version]:
                    finding = {
                        'id': cve_info['cve'],
                        'name': f"취약한 패키지 버전 발견: {pkg_name} ({pkg_version})",
                        'severity': cve_info['severity'],
                        'description': f"설치된 '{pkg_name}' 패키지 버전({pkg_version})은 {cve_info['cve']} 취약점에 노출되어 있습니다.",
                        'solution': f"가능한 한 빨리 '{pkg_name}' 패키지를 최신 버전으로 업데이트하여 취약점을 해결하십시오.",
                        'category': 'Security Audit (CVE)'
                    }
                    findings.append(finding)
        return findings

    def _audit_ssh_configuration(self, sshd_config: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        SSH 서버 설정 파일(sshd_config)의 보안 모범 사례 준수 여부를 감사합니다.
        
        :param sshd_config: sshd_config 파일의 파싱된 내용
        :return: 발견된 보안 권고 사항 리스트
        """
        findings = []
        if not sshd_config:
            return findings

        print("  - SSH 설정 감사 중...")
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

    def analyze(self, sos_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        전체 보안 감사를 수행합니다.
        
        :param sos_data: sos_analyzer에 의해 파싱된 전체 데이터 딕셔너리
        :return: 발견된 모든 보안 관련 문제점 리스트
        """
        print("[*] 보안 감사 분석 시작...")
        all_findings = []

        # 1. CVE 취약점 분석
        packages = sos_data.get('packages', [])
        cve_findings = self._check_cve_vulnerabilities(packages)
        all_findings.extend(cve_findings)

        # 2. SSH 설정 감사
        sshd_config = sos_data.get('configurations', {}).get('sshd_config', {})
        ssh_findings = self._audit_ssh_configuration(sshd_config)
        all_findings.extend(ssh_findings)
        
        # 3. 추가적인 감사 로직 (e.g., sudoers, firewall rules, log analysis)을 여기에 구현할 수 있습니다.

        print(f"[*] 보안 감사 분석 완료. 총 {len(all_findings)}개의 잠재적 보안 이슈를 발견했습니다.")
        return all_findings
