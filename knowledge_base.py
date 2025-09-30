# -*- coding: utf-8 -*-
# ==============================================================================
# Knowledge Base (Rule Engine) v1.0
# ------------------------------------------------------------------------------
# 기능:
# 1. 외부 YAML 파일에 정의된 규칙들을 로드
# 2. sosreport에서 파싱된 데이터를 기반으로 규칙의 조건(conditions)을 평가
# 3. 조건에 부합하는 문제점(findings)을 식별하여 진단 결과 리스트를 반환
# ==============================================================================

import yaml
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

class Color:
    """콘솔 출력에 사용할 ANSI 색상 코드입니다."""
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

class KnowledgeBase:
    """
    YAML 파일로부터 진단 규칙을 로드하고, 주어진 데이터에 대해 규칙을 평가하여
    문제점을 찾아내는 규칙 엔진 클래스입니다.
    """
    def __init__(self, rules_dir: str = 'rules'):
        """
        규칙 엔진을 초기화하고 지정된 디렉터리에서 모든 규칙 파일을 로드합니다.
        
        :param rules_dir: .yaml 규칙 파일들이 위치한 디렉터리 경로
        """
        self.rules_dir = Path(rules_dir)
        self.rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self):
        """규칙 디렉터리에서 모든 .yaml 파일을 찾아 규칙을 로드합니다."""
        print(f"[*] 지식 기반 규칙 로딩 시작... (디렉터리: '{self.rules_dir}')")
        if not self.rules_dir.is_dir():
            print(f"{Color.YELLOW}[!] 규칙 디렉터리 '{self.rules_dir}'를 찾을 수 없습니다. 규칙 기반 분석을 건너뜁니다.{Color.ENDC}")
            return

        for rule_file in self.rules_dir.glob('*.yaml'):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rules_from_file = yaml.safe_load(f)
                    if isinstance(rules_from_file, list):
                        self.rules.extend(rules_from_file)
                        print(f"  - 성공: '{rule_file.name}'에서 {len(rules_from_file)}개 규칙 로드")
            except Exception as e:
                print(f"[!] 오류: '{rule_file.name}' 파일 로딩 실패 - {e}")
        print(f"[*] 총 {len(self.rules)}개의 규칙이 로드되었습니다.")

    def _check_log_contains(self, condition: Dict[str, str], sos_data: Dict[str, Any]) -> bool:
        """'log_contains' 조건 유형을 확인합니다."""
        log_key = condition.get('log_key')
        pattern = condition.get('pattern')
        
        if not log_key or not pattern:
            return False
            
        log_content = sos_data.get('logs', {}).get(log_key, {}).get('content')
        if not log_content:
            return False

        return re.search(pattern, log_content, re.IGNORECASE) is not None

    def _check_config_value(self, condition: Dict[str, str], sos_data: Dict[str, Any]) -> bool:
        """'config_value' 조건 유형을 확인합니다."""
        config_key = condition.get('config_key')
        parameter = condition.get('parameter')
        expected_value = condition.get('value')

        if not all([config_key, parameter, expected_value]):
            return False
        
        # 'sshd_config'와 같은 중첩된 구조를 탐색
        config_data = sos_data.get('configurations', {}).get(config_key, {})
        actual_value = config_data.get(parameter)
        
        if actual_value is None:
            return False
        
        return str(actual_value).strip().lower() == str(expected_value).strip().lower()

    def analyze(self, sos_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        로드된 모든 규칙을 sos_data에 적용하여 문제점을 찾아냅니다.
        
        :param sos_data: sos_analyzer.py에 의해 파싱된 전체 데이터 딕셔너리
        :return: 발견된 문제점(finding)들의 리스트
        """
        if not self.rules:
            return []
            
        findings = []
        print("[*] 지식 기반 분석 시작...")
        
        for rule in self.rules:
            all_conditions_met = True
            for condition in rule.get('conditions', []):
                condition_met = False
                cond_type = condition.get('type')

                if cond_type == 'log_contains':
                    condition_met = self._check_log_contains(condition, sos_data)
                elif cond_type == 'config_value':
                    condition_met = self._check_config_value(condition, sos_data)
                # 여기에 다른 조건 유형 (e.g., command_output, file_exists 등)을 추가할 수 있습니다.
                
                if not condition_met:
                    all_conditions_met = False
                    break
            
            if all_conditions_met:
                finding = {
                    'id': rule.get('id'),
                    'name': rule.get('name'),
                    'severity': rule.get('severity'),
                    'description': rule.get('recommendation', {}).get('problem'),
                    'solution': rule.get('recommendation', {}).get('solution'),
                    'category': 'Knowledge Base'
                }
                findings.append(finding)
                print(f"  - 발견: [{rule.get('severity')}] {rule.get('name')}")
        
        print(f"[*] 지식 기반 분석 완료. 총 {len(findings)}개의 문제점을 발견했습니다.")
        return findings

# 이 파일이 직접 실행될 경우를 위한 간단한 테스트 로직
if __name__ == '__main__':
    # 가상의 sos_data 생성
    mock_sos_data = {
        'logs': {
            'dmesg': {
                'content': '...some log...\n[  12.345] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\n...more log...'
            },
            'secure': {
                'content': '...some log...\nSep 30 14:20:01 my-server sshd[12345]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2'
            }
        },
        'configurations': {
            'sshd_config': {
                'PermitRootLogin': 'yes',
                'PasswordAuthentication': 'yes'
            }
        }
    }

    # 지식 기반 초기화 및 분석 수행
    kb = KnowledgeBase(rules_dir='rules')
    detected_findings = kb.analyze(mock_sos_data)

    # 결과 출력
    if detected_findings:
        print("\n--- 감지된 문제점 ---")
        for find in detected_findings:
            print(f"\nID: {find['id']}\n이름: {find['name']}\n심각도: {find['severity']}")
            print(f"문제: {find['description']}\n해결책: {find['solution']}")
    else:
        print("\n감지된 문제점이 없습니다.")
