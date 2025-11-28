# -*- coding: utf-8 -*-
import datetime
import io
import json
import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

import yaml

from analyzer.parsers import parse_ha_cluster_info, parse_sbd_info, parse_drbd_info, parse_network_details, \
    parse_system_details, parse_storage, parse_process_stats, parse_additional_info

from utils.helpers import Color, log_step

# [효율성 제안] Pandas 라이브러리 추가
try:
    import pandas as pd
    IS_PANDAS_AVAILABLE = True
except ImportError:
    IS_PANDAS_AVAILABLE = False

# [정확성 제안] pytz 라이브러리 추가
try:
    import pytz
    IS_PYTZ_AVAILABLE = True
except ImportError:
    IS_PYTZ_AVAILABLE = False


class SosreportParser:
    def __init__(self, extract_path: Path):
        subdirs = [d for d in extract_path.iterdir() if d.is_dir()]
        if not subdirs: raise FileNotFoundError(f"sosreport 베이스 디렉토리를 찾을 수 없습니다: {extract_path}")
        self.base_path = subdirs[0]
        # [BUG FIX & 사용자 요청] report_date를 None으로 초기화하고, _initialize_report_date를 먼저 호출하여 올바른 날짜를 설정합니다.
        self.report_date: Optional[datetime.datetime] = None
        self._initialize_report_date()
        self.cpu_cores_count = 0
        self._sar_cache = {}  # [개선] SAR 출력 캐싱
        self._initialize_cpu_cores() # [BUG FIX] 생성자에서 CPU 코어 수를 먼저 초기화합니다.
        self.device_map = self._create_device_map() # [개선] 장치명 매핑 정보 생성 
        self.metadata = {'device_map': self.device_map} # [추가] 메타데이터에 장치 맵 추가
        logging.info(f"파서 초기화 완료. 분석 대상: '{self.base_path.name}'")

    def _read_file(self, possible_paths: List[str], default: str = 'N/A') -> str:
        for path_suffix in possible_paths:
            full_path = self.base_path / path_suffix
            if full_path.exists():
                try: return full_path.read_text(encoding='utf-8', errors='ignore').strip()
                except Exception: continue
        return default

    def _initialize_report_date(self):
        date_content = self._read_file(['sos_commands/date/date', 'date'])
        # [사용자 요청] sar 데이터 추출 기준 날짜를 sosreport 내의 date 파일로 설정합니다.
        try:
            # [BUG FIX] 정규식을 수정하여 요일(Weekday) 대신 월(Month)을 올바르게 캡처합니다.
            match = re.search(r'[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+([\d:]+)\s+([A-Z]+)\s+(\d{4})', date_content)
            if match:
                month_abbr, day, time_str, tz_str, year = match.groups()
                month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                if month_abbr in month_map:
                    hour, minute, second = map(int, time_str.split(':'))
                    # [정확성 제안] pytz를 사용하여 타임존을 명시적으로 처리
                    if IS_PYTZ_AVAILABLE:
                        try:
                            tz = pytz.timezone(tz_str)
                            self.report_date = tz.localize(datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second))
                        except pytz.UnknownTimeZoneError:
                            self.report_date = datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second)
                    else:
                        self.report_date = datetime.datetime(int(year), month_map[month_abbr], int(day), hour, minute, second)

                    logging.info(f"분석 기준 날짜 설정됨: {self.report_date.strftime('%Y-%m-%d %Z')} ('date' 파일 기준)")
                    return
        except Exception as e: logging.warning(f"sosreport 생성 날짜 파싱 중 오류 발생: {e}")

        # [사용자 제안] date 파일 파싱 실패 시, sosreport 디렉터리 이름에서 날짜를 추출하는 폴백 로직을 추가합니다.
        if self.report_date is None:
            logging.warning(Color.warn("'date' 파일에서 날짜를 파싱하지 못했습니다. sosreport 디렉터리 이름에서 날짜 추출을 시도합니다."))
            try:
                # [BUG FIX] Python 3.8 미만 버전과의 호환성을 위해 할당 표현식(:=)을 사용하지 않도록 수정합니다.
                match = re.search(r'(\d{4})-(\d{2})-(\d{2})', self.base_path.name)
                if match:
                    year, month, day = map(int, match.groups())
                    self.report_date = datetime.datetime(year, month, day)
                    logging.info(f"분석 기준 날짜 설정됨: {self.report_date.strftime('%Y-%m-%d')} (디렉터리명 기준)")
                    return
            except Exception as e:
                logging.warning(f"sosreport 디렉터리명에서 날짜 파싱 중 오류 발생: {e}")

        # 모든 날짜 추출 로직이 실패하면, 현재 시간을 기본값으로 사용합니다.
        if self.report_date is None:
            self.report_date = datetime.datetime.now()
            logging.error("  - 분석 기준 날짜를 설정하지 못했습니다. 현재 시간을 기준으로 분석을 시도합니다.")

    def _initialize_cpu_cores(self):
        lscpu_output = self._read_file(['lscpu', 'sos_commands/processor/lscpu'])
        match = re.search(r'^CPU\(s\):\s+(\d+)', lscpu_output, re.MULTILINE)
        if match: self.cpu_cores_count = int(match.group(1))

    def _create_device_map(self) -> Dict[str, str]:
        """
        [신규] proc/partitions와 dmsetup 정보를 결합하여 (major, minor) -> device_name 매핑을 생성합니다.
        """
        device_map: Dict[str, str] = {}

        # 1. dmsetup 정보 파싱 (LVM 장치명 매핑)
        dmsetup_content = self._read_file(['sos_commands/devicemapper/dmsetup_info_-c'])
        if dmsetup_content != 'N/A':
            # [BUG FIX] 이름에 공백이 포함된 경우(예: 'rhel-root (dm-0)')를 처리하기 위해 정규식 사용
            # Name Maj Min ...
            # rhel-root 253 0 ...
            dmsetup_pattern = re.compile(r'^([^\s]+)\s+(\d+)\s+(\d+)')
            for line in dmsetup_content.split('\n')[1:]:
                match = dmsetup_pattern.match(line.strip())
                if match:
                    name, major, minor = match.groups()
                    device_map[f"{major}:{minor}"] = name

        # 2. lsblk 정보 파싱 (일반 파티션 및 LVM 장치명 보강)
        lsblk_content = self._read_file(['sos_commands/block/lsblk'])
        if lsblk_content != 'N/A':
            for line in lsblk_content.split('\n')[1:]:
                # [BUG FIX] 장치 이름에 하이픈(-)이 포함된 경우(예: rhel-root)를 처리하도록 정규식 수정
                # NAME, MAJ:MIN, ... (장치 이름에 하이픈, 백틱, 파이프, 작은따옴표 포함 가능)
                # [BUG FIX] Python 3.8 미만 버전과의 호환성을 위해 할당 표현식(:=)을 사용하지 않도록 수정합니다.
                match = re.search(r'^([\w\-\`|\'\s]+)\s+(\d+:\d+)', line) # noqa: W605
                if match:
                    name, maj_min = match.groups()
                    # dmsetup에서 이미 매핑된 정보가 아니라면 추가
                    if maj_min not in device_map:
                        # lsblk 출력의 '|-`' 같은 트리 문자를 제거합니다.
                        device_map[maj_min] = name.strip('|-`')

        return device_map

    def _safe_float(self, value: Any) -> float:
        """[개선] 입력값을 float으로 안전하게 변환합니다."""
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(str(value).replace(',', '.'))
        except (ValueError, TypeError): return 0.0

    def _run_sar_command(self, sar_binary_path: str, sar_data_file: Path, options: str) -> str:
        """[안정성 강화 & 재시도 로직 추가] 지정된 sar 바이너리와 옵션으로 명령을 실행하고, 실패 시 3회 재시도합니다."""
        # [개선] SAR 명령 결과를 캐싱합니다.
        cache_key = f"{sar_binary_path}:{sar_data_file}:{options}"
        if cache_key in self._sar_cache:
            return self._sar_cache[cache_key]

        command_str = f"LANG=C {sar_binary_path} -f {sar_data_file} {options}"
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                env = os.environ.copy()
                result = subprocess.run(command_str, capture_output=True, text=True, check=True, env=env, shell=True, timeout=60)
                self._sar_cache[cache_key] = result.stdout
                return result.stdout # 성공 시 즉시 결과 반환
            except (subprocess.CalledProcessError, FileNotFoundError, AttributeError, subprocess.TimeoutExpired) as e:
                logging.warning(f"sar 명령어 실행 실패 (시도 {attempt + 1}/{max_retries}): {command_str}. 오류: {e}")
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt # 1, 2초 대기
                    logging.info(f"  -> {wait_time}초 후 재시도합니다...") # [사용자 요청] 재시도 대기 시간 로깅
                else:
                    logging.error(Color.error(f"sar 명령어 실행이 {max_retries}번의 시도 후에도 최종 실패했습니다: {command_str}"))
                    # [정확성 제안] 실패 시 빈 문자열 대신 예외를 발생시켜 폴백 로직이 동작하도록 함
                    raise e
        return "" # Should not be reached

    # [사용자 요청] sar 데이터 형식의 비일관성을 해결하기 위해 스키마 기반 파싱을 도입합니다.
    # 각 sar 명령어 옵션에 대해 가능한 헤더 이름과 표준화된 키를 매핑합니다.
    SAR_HEADER_SCHEMA = {
        'cpu': {
            '%user': 'pct_user', '%nice': 'pct_nice', '%system': 'pct_system', '%iowait': 'pct_iowait',
            '%steal': 'pct_steal', '%idle': 'pct_idle'
        },
        'memory': {
            'kbmemfree': 'kbmemfree', 'kbmemused': 'kbmemused', '%memused': 'pct_memused',
            'kbbuffers': 'kbbuffers', 'kbcached': 'kbcached', 'kbcommit': 'kbcommit',
            '%commit': 'pct_commit', 'kbactive': 'kbactive', 'kbinact': 'kbinact',
            'kbdirty': 'kbdirty'
        },
        'load': {
            'runq-sz': 'runq_sz', 'plist-sz': 'plist_sz', 'ldavg-1': 'load_1',
            'ldavg-5': 'load_5', 'ldavg-15': 'load_15', 'blocked': 'blocked'
        },
        'disk': {
            'tps': 'tps', 'rtps': 'rtps', 'wtps': 'wtps', 
            'bread/s': 'bread_s', 'bwrtn/s': 'bwrtn_s', # RHEL 7
            'rkB/s': 'bread_s', 'wkB/s': 'bwrtn_s'      # RHEL 8
        },
        'disk_detail': {
            'tps': 'tps', 'rd_sec/s': 'rd_sec_s', 'wr_sec/s': 'wr_sec_s',
            'avgrq-sz': 'avgrq_sz', 'avgqu-sz': 'avgqu_sz', 'await': 'await',
            'svctm': 'svctm', '%util': 'pct_util', 'rkB/s': 'rkB_s', 'wkB/s': 'wkB_s',
            'areq-sz': 'avgrq_sz', 'aqu-sz': 'avgqu_sz',
            # [개선 & RHEL8 호환성] 로케일 및 버전에 따른 대체 헤더 추가
            'rd_sect/s': 'rd_sec_s', 'wr_sect/s': 'wr_sec_s',
            'rkB/s': 'rd_sec_s', 'wkB/s': 'wr_sec_s',
            'areq-sz': 'avgrq_sz', 'aqu-sz': 'avgqu_sz'
        },
        'swap': {
            'kbswpfree': 'kbswpfree', 'kbswpused': 'kbswpused', '%swpused': 'pct_swpused',
            'kbswpcad': 'kbswpcad', '%swpcad': 'pct_swpcad'
        },
        'network': {
            'rxpck/s': 'rxpck_s', 'txpck/s': 'txpck_s', 'rxkB/s': 'rxkB_s', 'txkB/s': 'txkB_s',
            # [RHEL8 호환성] RHEL 8에 추가된 네트워크 헤더
            'rxcmp/s': 'rxcmp_s', 'txcmp/s': 'txcmp_s', 'rxmcst/s': 'rxmcst_s', '%ifutil': 'pct_ifutil'
        },
        # [사용자 요청] sar -B (페이징 통계) 스키마 추가
        'paging': {
            'pgpgin/s': 'pgpgin_s', 'pgpgout/s': 'pgpgout_s', 'fault/s': 'fault_s', 'majflt/s': 'majflt_s'
        },
        'file_handler': {
            'dentunusd': 'dentunusd', 'file-nr': 'file_nr', 'inode-nr': 'inode_nr', 'pty-nr': 'pty_nr'
        }
    }

    def _parse_sar_section(self, sar_binary_path: str, target_sar_file: Path, section: str, option: str) -> List[Dict]:
        """지정된 섹션에 대해 sar 명령을 실행하고 결과를 파싱합니다."""
        if not IS_PANDAS_AVAILABLE:
            return []

        try:
            content = self._run_sar_command(sar_binary_path, target_sar_file, option)
        except Exception:
            return [] # 명령어 실행 실패 시 빈 리스트 반환

        lines = [line.strip() for line in content.strip().split('\n') if line.strip() and not line.startswith('Average:')]
        if len(lines) < 2:
            return []

        header_line = lines[0]
        # [BUG FIX] 헤더가 여러 줄에 걸쳐 있을 수 있는 경우(예: sar -n DEV)를 처리합니다.
        # 'Linux'로 시작하는 라인을 건너뛰고 실제 헤더를 찾습니다.
        header_index = 0
        # [BUG FIX] RHEL8의 '00:00:00 CPU ...'와 같은 헤더를 건너뛰지 않도록, 타임스탬프만 있는 라인을 찾는 조건을 수정합니다.
        # 실제 헤더는 타임스탬프 외에 다른 문자(예: CPU, IFACE)를 포함합니다.
        while header_index < len(lines) and (lines[header_index].startswith('Linux') or not re.search(r'[a-zA-Z]', lines[header_index])):
            header_index += 1
        
        if header_index >= len(lines): return []
        
        # [BUG FIX] RHEL8의 sar 출력은 헤더 라인에 타임스탬프가 포함될 수 있습니다.
        # 예: '00:00:00 CPU %user ...' 또는 '00:00:00 IFACE rxpck/s ...'
        # 타임스탬프 부분을 제외하고 실제 헤더만 추출합니다.
        header_line_full = lines[header_index].strip()
        header_parts_full = re.split(r'\s+', header_line_full)
        
        # 첫 번째 요소가 타임스탬프 형식인지 확인
        if re.match(r'^\d{2}:\d{2}:\d{2}$', header_parts_full[0]):
            header_parts = header_parts_full[1:] # 타임스탬프 제외
        else:
            header_parts = header_parts_full
        
        # [BUG FIX] 데이터 시작 라인을 더 정확하게 찾습니다.
        # 헤더 다음 라인부터 시작하되, 비어있거나 'Linux'로 시작하는 라인은 건너뜁니다.
        data_start_index = header_index + 1
        while data_start_index < len(lines) and (not lines[data_start_index].strip() or lines[data_start_index].startswith('Linux')):
            data_start_index += 1

        data_io = io.StringIO('\n'.join(lines[data_start_index:]))

        try:
            # [BUG FIX] 로케일에 따라 소수점이 쉼표(,)로 표시되는 경우를 처리하기 위해 decimal=',' 추가
            df = pd.read_csv(data_io, sep=r'\s+', header=None, engine='python', decimal=",")
            if df.empty:
                return []

            # --- [BUG FIX] RHEL8 호환성을 위한 컬럼 이름 설정 로직 개선 ---
            schema_keys = self.SAR_HEADER_SCHEMA.get(section, {})
            
            # 1. 최종 컬럼 이름을 담을 리스트 초기화
            cols = []
            
            # 2. 헤더의 첫 번째 열이 타임스탬프가 아닌 식별자(CPU, IFACE, DEV)인 경우를 처리
            first_header = header_parts[0] if header_parts else ''
            if first_header in ['CPU', 'IFACE', 'DEV']:
                # [BUG FIX] 'network' 섹션의 경우, 첫 번째 헤더는 'IFACE'입니다.
                # cols 리스트에 ['timestamp', 'IFACE']를 미리 추가해야 합니다.
                if section == 'network' and first_header == 'IFACE':
                    cols.extend(['timestamp', 'IFACE'])
                else:
                    cols.extend(['timestamp', first_header])
                # 실제 데이터 헤더는 식별자 다음부터 시작합니다.
                raw_headers_for_check = header_parts[1:]
            else:
                # CPU/DEV/IFACE가 없는 경우 (예: sar -r), 첫 열은 타임스탬프입니다.
                cols = ['timestamp']
                # 모든 헤더 파트를 데이터 컬럼으로 사용합니다.
                raw_headers_for_check = header_parts

            # 3. 나머지 헤더들을 스키마에 따라 표준화하여 컬럼 목록에 추가합니다.
            # [BUG FIX] 네트워크 섹션의 경우, 원본 키('/')와 표준화된 키('_')를 모두 유지해야 합니다.
            # report_generator에서 원본 키를 사용하여 그래프를 생성하기 때문입니다.
            if section == 'network':
                # 네트워크 섹션은 원본 헤더 이름을 그대로 사용합니다.
                cols.extend(raw_headers_for_check)
            else:
                cols.extend([schema_keys.get(h, h.replace('%', 'pct_').replace('/', '_').replace('-', '_')) for h in raw_headers_for_check])
            
            # 4. [안정성 강화] 데이터프레임의 실제 컬럼 수와 생성된 컬럼 이름 목록의 길이를 비교하여 안전하게 컬럼 이름을 할당합니다.
            #    이는 예상치 못한 출력 형식으로 인해 발생하는 오류를 방지합니다.
            num_cols_to_assign = min(len(df.columns), len(cols))
            df.columns = cols[:num_cols_to_assign]
            # 데이터프레임의 컬럼 수를 할당된 컬럼 수에 맞게 자릅니다.
            df = df.iloc[:, :num_cols_to_assign]

            # 타임스탬프 변환
            # [사용자 요청] 그래프의 시간을 UTC가 아닌 sosreport의 로컬 타임존으로 표시하도록 수정합니다.
            # .astimezone(pytz.utc) 변환 로직을 제거하여 원래의 타임존을 유지합니다.
            df['timestamp'] = pd.to_datetime(df['timestamp'], format='%H:%M:%S').dt.time
            df['timestamp'] = df.apply(lambda row: self.report_date.replace(hour=row['timestamp'].hour, minute=row['timestamp'].minute, second=row['timestamp'].second).isoformat(), axis=1)

            # 숫자형으로 변환
            for col in df.columns:
                if col not in ['timestamp', 'IFACE', 'DEV', 'CPU']:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

            # 필터링
            if section == 'cpu' and 'CPU' in df.columns: df = df[df['CPU'] == 'all']
            if section == 'network' and 'IFACE' in df.columns: df = df[df['IFACE'] != 'lo']

            return df.to_dict('records')

        except Exception as e:
            logging.debug(f"'{section}' 섹션 Pandas 파싱 중 오류 발생 (블록 건너뜀): {e}")
            return []

    def _parse_sar_data_from_text(self) -> Dict[str, List[Dict]]:
        """텍스트 기반 sar 파일(예: sos_commands/sar/sarDD)을 파싱합니다."""
        logging.info("텍스트 sar 데이터 파싱 시도 (바이너리 파싱 실패 시 폴백)...")
        
        report_day = self.report_date.day  # type: ignore
        report_date_str = self.report_date.strftime('%Y%m%d')
        # [사용자 요청] 다양한 경로와 이름 형식의 텍스트 sar 파일을 순서대로 탐색합니다.
        possible_paths = [
            f'var/log/sa/sar{report_day:02d}', f'var/log/sa/sar{report_date_str}',
            f'sos_commands/sar/sar{report_day:02d}', f'sos_commands/sar/sar{report_date_str}'
        ]
        
        content, found_path = next(((self._read_file([p]), p) for p in possible_paths if self._read_file([p]) != 'N/A'), ('N/A', None))
        if not found_path:
            logging.warning(Color.warn(f"  - 날짜에 맞는 텍스트 sar 파일을 찾을 수 없어 텍스트 파싱을 건너뜁니다."))
            return {}

        logging.info(f"사용할 텍스트 sar 파일: {found_path}")

        all_sar_data: Dict[str, List[Dict]] = {}
        current_section = None
        header_cols = []

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Average:'):
                if line.startswith('Average:'): header_cols = []
                continue

            parts = re.split(r'\s+', line)
            logging.debug(f"  [TEXT] Processing line: {line}")
            # [BUG FIX] 헤더 라인 식별 로직 강화
            is_header_line = (parts[0] == 'Linux') or (re.match(r'^\d{2}:\d{2}:\d{2}(?!\d)', parts[0]) and any(p in ['CPU', 'IFACE', 'DEV'] or '%' in p or '/' in p or '-' in p for p in parts[1:]))
            time_end_idx_check = 2 if len(parts) > 1 and parts[1] in ['AM', 'PM'] else 1
            is_data_line = re.match(r'^\d{2}:\d{2}:\d{2}(?!\d)', parts[0]) and not is_header_line and any(p.replace('.', '', 1).isdigit() for p in parts[time_end_idx_check:])

            if is_header_line:
                raw_headers = parts[time_end_idx_check:]
                logging.debug(f"    -> Identified as HEADER line.")
                # 헤더를 보고 현재 섹션이 무엇인지 추론
                for section, schema in self.SAR_HEADER_SCHEMA.items():
                    if any(h in schema for h in raw_headers):
                        current_section = section
                        # [BUG FIX] 'disk'와 'disk_detail' 구분 로직 추가
                        # 'disk'와 'disk_detail'은 'tps' 헤더를 공유하므로, 'rd_sec/s'와 같은
                        # disk_detail에만 있는 헤더의 존재 여부로 두 섹션을 구분합니다.
                        if current_section == 'disk' and any(h in self.SAR_HEADER_SCHEMA['disk_detail'] for h in raw_headers if h != 'tps'):
                            current_section = 'disk_detail'
                        if current_section == 'disk' and any(h in self.SAR_HEADER_SCHEMA['disk_detail'] for h in raw_headers if h != 'tps'):
                            current_section = 'disk_detail'
                        schema_keys = self.SAR_HEADER_SCHEMA.get(current_section, {})
                        
                        first_col_header = parts[time_end_idx_check-1]
                        header_cols = []
                        if first_col_header in ['CPU', 'DEV', 'IFACE']:
                            header_cols.append(first_col_header)

                        for raw_header in raw_headers:
                            if raw_header not in ['IFACE', 'DEV', 'CPU']:
                                header_cols.append(schema_keys.get(raw_header, raw_header.replace('%', 'pct_').replace('/', '_').replace('-', '_')))
                        
                        logging.debug(f"    -> Section: '{current_section}', Parsed Headers: {header_cols}")
                        if current_section not in all_sar_data: all_sar_data[current_section] = []
                        break

            if is_data_line and header_cols and current_section:
                logging.debug(f"    -> Identified as DATA line for section '{current_section}'.")
                time_end_idx = time_end_idx_check
                ts_str = " ".join(parts[:time_end_idx])
                try: dt_obj = datetime.datetime.strptime(ts_str, '%I:%M:%S %p' if time_end_idx == 2 else '%H:%M:%S'); timestamp_iso = self.report_date.replace(hour=dt_obj.hour, minute=dt_obj.minute, second=dt_obj.second).isoformat()
                except ValueError: continue # yapf: disable

                values = parts[time_end_idx:]
                # [BUG FIX] 헤더에 'DEV'가 있지만 실제 데이터 라인에 장치명이 없는 경우를 처리
                if 'DEV' in header_cols and len(values) == len(header_cols) -1: values.insert(0, 'N/A')
                entry = {'timestamp': timestamp_iso}
                for i in range(min(len(header_cols), len(values))):
                    header = header_cols[i]
                    value = values[i]
                    entry[header] = value if header in ['IFACE', 'DEV', 'CPU'] else self._safe_float(value)

                if current_section == 'disk_detail' and 'DEV' in entry and isinstance(entry['DEV'], str) and entry['DEV'].startswith('dev'):
                    major, minor = entry['DEV'][3:].split('-')
                    # [사용자 요청] 장치명 매핑에 실패하면 원본 dev-x-y 이름을 device_name으로 사용합니다. (self.device_map 사용)
                    entry['device_name'] = self.device_map.get(f"{major}:{minor}", entry['DEV'])
                
                # [사용자 요청] CPU 데이터는 'all'만, 네트워크 데이터는 'lo' 제외
                if current_section == 'cpu' and entry.get('CPU') != 'all':
                    continue
                if current_section == 'network' and entry.get('IFACE') == 'lo':
                    continue
                all_sar_data[current_section].append(entry); logging.debug(f"    -> Parsed entry: {entry}")

        if all_sar_data:
            logging.info("텍스트 sar 파일에서 데이터 수집 완료:")
            for section, data_list in all_sar_data.items():
                logging.debug(f"    -> '{section}' 데이터 {len(data_list)}개 수집")

        return all_sar_data

    def _parse_sar_data(self) -> Dict[str, List[Dict]]:
        logging.debug(f"SAR 성능 데이터 파싱 시작 (기준 날짜: {self.report_date.strftime('%Y-%m-%d')})")

        os_release_content = self._read_file(['etc/redhat-release'])
        rhel_version_match = re.search(r'release\s+(\d+)', os_release_content)
        rhel_version = rhel_version_match.group(1) if rhel_version_match else "7"

        # [사용자 요청] RHEL 버전에 따라 사용할 sar 바이너리 버전을 결정합니다.
        # RHEL 9.x는 RHEL 8.x와 동일한 sar 바이너리를 사용합니다.
        sar_version_to_use = rhel_version
        if rhel_version == "9":
            sar_version_to_use = "8"
        sar_binary_path = f"/usr/bin/sar_{sar_version_to_use}"
        
        if not Path(sar_binary_path).exists():
            logging.warning(Color.warn(f"sar 실행 파일 '{sar_binary_path}'를 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        sa_dir = self.base_path / 'var/log/sa'
        if not sa_dir.is_dir():
            logging.warning(Color.warn(f"sar 데이터 디렉토리({sa_dir})를 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        report_day = self.report_date.day
        report_date_str = self.report_date.strftime('%Y%m%d')
        possible_filenames = [f"sa{report_day:02d}", f"sa{report_date_str}"]
        target_sar_file = next((sa_dir / fn for fn in possible_filenames if (sa_dir / fn).exists()), None)

        if not target_sar_file:
            logging.warning(Color.warn(f"날짜에 맞는 sar 바이너리 파일({', '.join(possible_filenames)})을(를) 찾을 수 없습니다. 텍스트 파일 파싱으로 대체합니다."))
            return self._parse_sar_data_from_text()

        logging.debug(f"사용할 sar 바이너리: {sar_binary_path}, 데이터 파일: {target_sar_file.name}")

        sar_options_map = {
            'cpu': '-u', 'memory': '-r', 'load': '-q', 'disk': '-b',
            'disk_detail': '-d', 'swap': '-S', 'network': '-n DEV', 'file_handler': '-v',
            'paging': '-B' # [사용자 요청] 페이징 통계(-B) 옵션 추가
        }

        merged_data: Dict[str, List[Dict]] = {}
        for section, option in sar_options_map.items():
            logging.debug(f"  -> '{section}' ({option}) 데이터 파싱 중...")
            section_data = self._parse_sar_section(sar_binary_path, target_sar_file, section, option)
            merged_data[section] = section_data

        text_data = self._parse_sar_data_from_text()
        for section, data in text_data.items():
            if section not in merged_data or not merged_data[section]:
                logging.info(f"'{section}' 섹션 데이터를 텍스트 소스에서 보충합니다. (데이터 {len(data)}개)")
                merged_data[section] = data

        summary = ", ".join([f"{key}: {len(value)}" for key, value in merged_data.items()])
        if summary:
            logging.info("SAR 데이터 파싱 완료. 수집된 데이터 포인트:")
            for key, value in merged_data.items():
                logging.info(f"  - {key}: {len(value)}개")
        else:
            logging.warning(Color.warn("SAR 데이터 파싱 완료. 수집된 데이터 포인트가 없습니다."))

        for section, data in merged_data.items():
            if not data:
                logging.warning(Color.warn(f"  -> '{section}' 섹션에 대한 sar 데이터를 수집하지 못했습니다. 관련 그래프가 생성되지 않을 수 있습니다."))
        return merged_data

    def _find_sar_data_around_time(self, sar_section_data: List[Dict], target_dt: datetime.datetime, window_minutes: int = 2) -> Optional[Dict]:
        if not sar_section_data or not IS_PYTZ_AVAILABLE: return None
        closest_entry, min_delta = None, timedelta.max
        target_dt_utc = target_dt.astimezone(pytz.utc) if IS_PYTZ_AVAILABLE and target_dt.tzinfo else target_dt
        for entry in sar_section_data: # noqa: E501
            try:
                entry_dt = datetime.datetime.fromisoformat(entry['timestamp']); delta = abs(entry_dt - target_dt_utc)
                if delta < min_delta: min_delta, closest_entry = delta, entry
            except (ValueError, KeyError): continue
        return closest_entry.copy() if closest_entry and min_delta <= timedelta(minutes=window_minutes) else None

    def _analyze_logs_and_correlate_events(self, sar_data: Dict) -> Dict:
        logging.debug("주요 로그 이벤트 분석 및 SAR 데이터와 연관 관계 분석 중...")
        log_content = self._read_file(['var/log/messages', 'var/log/syslog']); critical_events = []
        if log_content == 'N/A': return {"critical_log_events": []}
        
        lines = log_content.split('\n')
        for i, line in enumerate(lines):
            match = re.match(r'^([A-Za-z]{3}\s+\d{1-2}\s+\d{2}:\d{2}:\d{2})', line)
            if match:
                try: log_dt = datetime.datetime.strptime(f"{self.report_date.year} {match.group(1)}", '%Y %b %d %H:%M:%S')
                except ValueError: continue
                event_type, context = None, {}
                
                if 'i/o error' in line.lower():
                    event_type = "I/O Error"
                    if sar_context := self._find_sar_data_around_time(sar_data.get('disk', []), log_dt): context['sar_disk'] = sar_context
                
                elif 'out of memory' in line.lower():
                    event_type = "Out of Memory"
                    if sar_context := self._find_sar_data_around_time(sar_data.get('memory', []), log_dt): context['sar_memory'] = sar_context
                    
                    # [사용자 요청] OOM 발생 시 상세 메모리 정보 수집
                    oom_details = {}
                    # OOM 로그는 여러 줄에 걸쳐 상세 정보를 포함하므로, 다음 50줄을 스캔합니다.
                    for j in range(i + 1, min(i + 50, len(lines))):
                        detail_line = lines[j]
                        # "active_anon:12345 pages"와 같은 형식의 라인을 찾습니다.
                        detail_match = re.search(r'(\w+):\s*(\d+)\s*pages', detail_line)
                        if detail_match:
                            key, value = detail_match.groups()
                            oom_details[key] = f"{value} pages"
                        # "total_pagecache"와 같이 형식이 다른 경우도 처리합니다.
                        elif 'total_pagecache' in detail_line:
                            pagecache_match = re.search(r'total_pagecache\s*(\d+)', detail_line)
                            if pagecache_match:
                                oom_details['total_pagecache'] = f"{pagecache_match.group(1)} pages"
                    
                    if oom_details:
                        context['oom_details'] = oom_details

                if event_type: critical_events.append({"event_type": event_type, "timestamp": log_dt.isoformat(), "log_message": line, "context": context})
        return {"critical_log_events": critical_events}

    def _analyze_performance_bottlenecks(self, sar_data: Dict) -> Dict:
        logging.debug("성능 병목 현상 분석 중...")
        analysis = {}
        cpu_data = sar_data.get('cpu')
        if cpu_data:
            if high_iowait := [d for d in cpu_data if d.get('pct_iowait', 0) > 20]: analysis['io_bottleneck'] = f"CPU I/O Wait이 20%를 초과한 경우가 {len(high_iowait)}번 감지되었습니다."
        load_data = sar_data.get('load')
        if load_data:
            if self.cpu_cores_count > 0 and (high_load := [d for d in load_data if d.get('ldavg-5', 0) > self.cpu_cores_count * 1.5]): analysis['high_load_average'] = f"5분 평균 부하가 CPU 코어 수의 1.5배를 초과한 경우가 {len(high_load)}번 감지되었습니다."
        swap_data = sar_data.get('swap')
        if swap_data:
            if swap_data and (max_swap := max(d.get('pct_swpused',0) for d in swap_data)) > 10: analysis['swap_usage'] = f"최대 스왑 사용률이 {max_swap:.1f}%에 달했습니다."
        return analysis

    def _parse_and_patternize_logs(self) -> Dict[str, Any]:
        """
        [핵심 개선] /var/log/의 모든 로그를 지능적으로 패턴화하고, 발생 빈도 기반의 이상 탐지를 통해
        유의미한 로그만 추출하여 데이터 크기를 획기적으로 줄입니다.
        """
        log_step("2. 스마트 로그 분석 및 패턴화")
        log_dir = self.base_path / 'var/log'
        if not log_dir.is_dir():
            logging.warning(Color.warn(f"로그 디렉터리 '{log_dir}'를 찾을 수 없습니다. 스마트 로그 분석을 건너뜁니다."))
            return {}

        # 1. 모든 로그 라인을 읽어 패턴화하고 빈도수 계산
        all_patterns = Counter()
        pattern_examples = {} # 각 패턴의 첫 번째 원본 로그 예시 저장
        
        # [개선] 하드코딩된 패턴 대신 log_patterns.yaml 파일을 동적으로 로드하여 사용합니다.
        # 이를 통해 코드 수정 없이 YAML 파일만으로 로그 정규화 규칙을 관리할 수 있습니다.
        PATTERNS_TO_NORMALIZE = []
        patterns_file = Path(__file__).parent / 'log_patterns.yaml'
        if patterns_file.exists():
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    yaml_patterns = yaml.safe_load(f)
                    for item in yaml_patterns:
                        flags = re.IGNORECASE if item.get('ignorecase') else 0
                        PATTERNS_TO_NORMALIZE.append(
                            (item.get('name', 'Unnamed'), re.compile(item['regex'], flags), item['placeholder'])
                        )
                logging.info(f"  - '{patterns_file.name}'에서 {len(PATTERNS_TO_NORMALIZE)}개의 로그 정규화 패턴을 로드했습니다.")
            except Exception as e:
                logging.error(f"'{patterns_file.name}' 파일 로딩 또는 파싱 중 오류 발생: {e}")
        else:
            logging.warning(Color.warn(f"'{patterns_file.name}' 파일을 찾을 수 없어 로그 정규화가 제한적으로 수행될 수 있습니다."))

        # [사용자 요청] LLM 부하 감소를 위해 로그 수집을 /var/log/messages 파일로 제한합니다.
        # sosreport 구조에 따라 여러 경로에 있을 수 있는 messages 파일을 탐색합니다.
        messages_path = next((p for p in [log_dir / 'messages', log_dir / 'syslog'] if p.exists() and p.is_file() and p.stat().st_size > 0), None)
        # [제안 반영] dmesg 로그도 스마트 패턴화 대상에 포함합니다.
        dmesg_path = next((self.base_path / p for p in ['dmesg', 'sos_commands/kernel/dmesg'] if (self.base_path / p).exists()), None)

        log_files_to_process = [f for f in [messages_path, dmesg_path] if f]
        if not log_files_to_process:
            logging.warning(Color.warn(f"  - '{log_dir}'에서 'messages', 'syslog', 'dmesg' 파일을 찾을 수 없어 로그 분석을 건너뜁니다."))
            return {}
        logging.info(f"  - 스마트 로그 분석 대상 파일: {[f.name for f in log_files_to_process]}")

        # [BUG FIX] 로그 파일 처리 로직을 try-except 블록 밖으로 이동하여 변수 범위 문제를 해결합니다.
        for log_file in log_files_to_process:
            if any(log_file.name.endswith(ext) for ext in ['.gz', '.xz', '.bz2', 'lastlog', 'wtmp', 'btmp']):
                continue
            
            try:
                content = log_file.read_text(encoding='utf-8', errors='ignore')
                lines = content.split('\n')

                for line in lines:
                    if not line.strip(): continue
                    
                    # [사용자 요청] 어떤 패턴이 적용되었는지 추적하기 위해 정규화 과정을 수정합니다.
                    normalized_pattern = line
                    for name, regex, placeholder in PATTERNS_TO_NORMALIZE:
                        # re.subn()은 치환된 문자열과 치환 횟수를 튜플로 반환합니다.
                        new_pattern, num_subs = regex.subn(placeholder, normalized_pattern)
                        if num_subs > 0:
                            # [사용자 요청] 로그가 너무 많아 가독성을 해치므로, 로그 레벨을 DEBUG로 변경합니다.
                            logging.debug(f"    -> Log line normalized by pattern '{name}'.")
                            normalized_pattern = new_pattern

                    final_pattern = re.sub(r'\s+', ' ', normalized_pattern).strip()
                    
                    # dmesg 로그는 'dmesg'라는 가상 파일명으로 통일하여 처리
                    filename_key = 'dmesg' if 'dmesg' in log_file.name else log_file.name
                    pattern_key = (filename_key, final_pattern)
                    all_patterns[pattern_key] += 1
                    if pattern_key not in pattern_examples:
                        pattern_examples[pattern_key] = line
            except Exception as e:
                logging.warning(f"  - 로그 파일 '{log_file.name}' 처리 중 오류 발생: {e}")

        # 2. 빈도수 기반으로 유의미한 로그 필터링
        smart_log_analysis = {}
        ANOMALY_THRESHOLD = 5
        # [사용자 요청] 과도하게 반복되는 로그를 제외하기 위한 임계값
        HIGH_FREQUENCY_THRESHOLD = 1000

        # [사용자 요청] LLM에 전달할 최종 데이터의 최대 크기 (바이트 단위, 예: 1MB)
        MAX_SMART_LOG_SIZE_BYTES = 1 * 1024 * 1024
        # [사용자 요청] 각 로그 예시의 최대 길이 (문자 단위)
        MAX_EXAMPLE_LENGTH = 500
        # [사용자 요청] 선정된 로그 유형별 카운터를 추가합니다.
        rare_log_count = 0
        keyword_log_count = 0
        selected_patterns = set() # 중복 계산 방지

        # [요청사항] 시스템 영향 분석을 위한 핵심 키워드 목록 강화
        # 기존의 단순 오류 키워드에서 더 구체적이고 심층적인 키워드로 확장합니다.
        # [사용자 요청] pacemaker 관련 로그 패턴 추가 (lost, OFFLINE, Quorum lost, link... DOWN)
        CORE_KEYWORDS = re.compile(
            # [BUG FIX] 여러 줄의 문자열을 괄호로 묶어 하나의 문자열로 합칩니다.
            # 각 줄 끝에 쉼표가 누락되어 발생하던 'unterminated subpattern' 오류를 해결합니다.
            (r'\b(error|failed|failure|critical|panic|denied|segfault|corrupt|unrecoverable|'  # 일반 오류
             r'stonith|fencing|fence|split-brain|standby|primary|secondary|sync|failover|quorum|unfenced|inconsistent|'  # HA 클러스터
             r'i/o error|out of memory|oom-killer|hung|deadlock|'  # 시스템 문제
             r'lost|OFFLINE|Quorum lost|link.*DOWN)\b'),  # Pacemaker 상태
            re.IGNORECASE)

        for (filename, pattern), count in all_patterns.items():
            # [사용자 요청] 필터링 로직 강화: 이제 '핵심 키워드'를 포함하는 로그만 분석 대상으로 삼습니다.
            # 단순히 희귀하다는 이유만으로 로그를 포함하지 않아, 부팅 메시지 등 정상적인 저빈도 로그를 제외합니다.
            is_significant_keyword = CORE_KEYWORDS.search(pattern)

            if is_significant_keyword:
                # [사용자 요청] 핵심 키워드를 포함하는 로그만 카운트하도록 로직 변경
                pattern_key = (filename, pattern)
                if pattern_key not in selected_patterns:
                    keyword_log_count += 1
                    selected_patterns.add(pattern_key)

                if filename not in smart_log_analysis:
                    smart_log_analysis[filename] = []
                smart_log_analysis[filename].append({
                    "pattern": pattern,
                    "count": count,
                    # [문제 해결] AI가 분석의 근거가 되는 로그를 참조할 수 있도록 'example' 필드를 다시 활성화합니다.
                    "example": pattern_examples[(filename, pattern)][:MAX_EXAMPLE_LENGTH]
                })

        # 파일별로 count 기준으로 정렬
        for filename in smart_log_analysis:
            smart_log_analysis[filename].sort(key=lambda x: x['count'], reverse=True)

        total_selected = keyword_log_count

        logging.info(Color.info(f"스마트 로그 분석 완료. 총 {total_selected}개의 핵심 키워드 기반 로그 패턴을 추출했습니다."))

        return {"smart_log_analysis": smart_log_analysis}

    def _parse_rhel7_pcs_status(self, crm_report_content: str) -> Dict[str, Any]:
        """
        [신규] RHEL 7의 텍스트 기반 'pcs status' (crm_report) 출력을 파싱하여
        RHEL 8+ 과 유사한 구조의 ha_cluster_info 딕셔너리를 생성합니다.
        """
        if not crm_report_content or "Last updated" not in crm_report_content:
            return {}

        logging.info("  - RHEL 7 형식의 'pcs status' 출력을 파싱합니다...")
        ha_info: Dict[str, Any] = {
            'summary': {},
            'nodes': {'online': [], 'offline': []},
            'resources': [],
            'failed_resources': [],
            'daemons': {},
            'is_rhel7_fallback': True # 폴백 로직으로 파싱되었음을 명시
        }

        # 1. 요약 정보 (Last updated, Current DC 등)
        summary_match = re.search(r'Stack: corosync\s*Current DC: (.*?)\s*Last updated: (.*?)\s*Last change: (.*?)\s*pcsd-status: (.*?)\s*', crm_report_content, re.DOTALL)
        if summary_match:
            ha_info['summary']['Current DC'] = summary_match.group(1).strip()
            ha_info['summary']['Last updated'] = summary_match.group(2).strip()

        # 2. 노드 상태
        nodes_section_match = re.search(r'(\d+) nodes configured:\n(.*?)\n\n', crm_report_content, re.DOTALL)
        if nodes_section_match:
            nodes_text = nodes_section_match.group(2)
            online_nodes = re.findall(r'Online: \[\s*(.*?)\s*\]', nodes_text)
            if online_nodes:
                ha_info['nodes']['online'] = online_nodes[0].split()
            offline_nodes = re.findall(r'Offline: \[\s*(.*?)\s*\]', nodes_text)
            if offline_nodes:
                ha_info['nodes']['offline'] = offline_nodes[0].split()

        # 3. 리소스 상태
        current_group = None
        current_clone = None
        
        # 개별 리소스 라인을 파싱하는 정규식
        # 예: "    my_ip    (ocf:heartbeat:IPaddr2):    Started node001"
        # 예: "    my_drbd    (ocf:linbit:drbd):    Master node001"
        resource_detail_line_pattern = re.compile(
            r'^\s+([^\s\(]+)\s+\(([^)]+)\)(?::)?\s+(Started|Stopped|FAILED|Masters|Slaves|Master|Slave)\s*(\S*)'
        )

        for line in crm_report_content.split('\n'):
            line = line.strip()

            # 그룹 또는 클론 헤더 매칭
            group_match = re.match(r'Resource Group: (\S+)', line)
            clone_set_match = re.match(r'(?:Clone Set|Master/Slave Set): (\S+)(?:\s+\[(\S+)\])?', line)

            if group_match:
                current_group = group_match.group(1)
                current_clone = None # 그룹이 시작되면 클론 정보 초기화
                continue
            elif clone_set_match:
                current_clone = clone_set_match.group(1) # 클론 세트 이름
                current_group = None # 클론이 시작되면 그룹 정보 초기화
                continue
            
            # 개별 리소스 상세 라인 매칭
            detail_match = resource_detail_line_pattern.match(line)
            if detail_match:
                res_id, full_type, status, node = detail_match.groups()
                
                res_info = {
                    'id': res_id.strip(),
                    'type': full_type.strip(),
                    'status': status.strip(),
                    'node': node.strip() if node else 'Unknown',
                    'group': current_group,
                    'clone': current_clone,
                }
                ha_info['resources'].append(res_info)
                if status.strip() == 'FAILED':
                    ha_info['failed_resources'].append(res_id.strip())
                continue # 다음 라인 처리

        # 4. Quorum 상태 (단순화된 추정)
        ha_info['quorum_status'] = {'quorum': {'Quorate': 'Yes' if ha_info['nodes']['online'] else 'No'}} # [BUG FIX] 쿼럼 상태는 온라인 노드 여부로 추정
        return ha_info

    def _reconstruct_timeline_events(self, sar_data: Dict, smart_log_analysis: Dict) -> List[Dict]:
        """
        [신규] 시간 정보가 있는 모든 데이터를 통합하여 시간순으로 재구성하고,
        주요 이벤트 발생 시점의 컨텍스트(성능 지표)를 보강합니다.
        """
        logging.debug("시간축 기반 이벤트 재구성 시작...")
        timeline = []

        # 1. SAR 데이터에서 성능 이벤트 추출
        for section, data_list in sar_data.items():
            for entry in data_list:
                if 'timestamp' in entry:
                    timeline.append({
                        "timestamp": entry['timestamp'],
                        "source": "sar",
                        "type": "metric",
                        "section": section,
                        "metrics": {k: v for k, v in entry.items() if k != 'timestamp'}
                    })

        # 2. 스마트 로그 분석 결과에서 로그 이벤트 추출
        #    (smart_log_analysis는 이미 중요한 로그만 필터링한 상태)
        for filename, logs in smart_log_analysis.get('smart_log_analysis', {}).items():
            for log_item in logs:
                # 'example' 로그에서 타임스탬프를 파싱 시도
                example_log = log_item.get('example', '')
                match = re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', example_log)
                if match and self.report_date:
                    try:
                        log_dt = datetime.datetime.strptime(f"{self.report_date.year} {match.group(1)}", '%Y %b %d %H:%M:%S')
                        timeline.append({"timestamp": log_dt.isoformat(), "source": filename, "type": "log", "content": log_item.get('pattern'), "count": log_item.get('count')})
                    except ValueError:
                        continue

        # 3. 타임라인을 시간순으로 정렬
        timeline.sort(key=lambda x: x['timestamp'])
        logging.info(f"총 {len(timeline)}개의 시간축 이벤트를 재구성했습니다.")
        return timeline

    def parse_all(self) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """[개선] ThreadPoolExecutor를 사용하여 I/O 중심의 파싱 작업을 병렬로 처리합니다."""
        metadata: Dict[str, Any] = {}
        
        # 병렬로 실행할 파싱 작업 목록
        parsing_tasks = {
            'system_info': (parse_system_details, self),
            'storage': (parse_storage, self),
            'processes': (parse_process_stats, self),
            'network': (parse_network_details, self),
            'ha_cluster_info': (parse_ha_cluster_info, self),
            'drbd_info': (parse_drbd_info, self),
            'sbd_info': (parse_sbd_info, self),
            'additional_info': (parse_additional_info, self),
        }

        logging.info("데이터 파싱 시작 (병렬 처리)...")
        with ThreadPoolExecutor(max_workers=len(parsing_tasks)) as executor:
            future_to_key = {executor.submit(func, *args): key for key, (func, *args) in parsing_tasks.items()}
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    result = future.result()
                    if result: # 결과가 있는 경우에만 메타데이터에 추가
                        if key == 'additional_info':
                            metadata.update(result)
                        # [개선] sbd_info를 ha_cluster_info에 병합
                        # [BUG FIX] ha_cluster_info가 아직 없을 수 있으므로 setdefault를 사용합니다. (KeyError 해결)
                        elif key == 'sbd_info' and result:
                            metadata.setdefault('ha_cluster_info', {})['sbd_status'] = result
                        else:
                            metadata[key] = result

                    # [BUG FIX] RHEL7 폴백 파싱 로직 추가
                    if key == 'ha_cluster_info' and not result:
                        crm_report_content = self._read_file(['sos_commands/pacemaker/crm_report', 'sos_commands/cluster/crm_report'])
                        rhel7_ha_info = self._parse_rhel7_pcs_status(crm_report_content)
                        if rhel7_ha_info: metadata['ha_cluster_info'] = rhel7_ha_info
                except Exception as e:
                    logging.error(f"'{key}' 파싱 중 오류 발생: {e}", exc_info=True)
        logging.info("병렬 데이터 파싱 완료.")
        
        logging.info("SAR 성능 데이터 파싱 시작...")
        sar_data = self._parse_sar_data()
        self.sar_data = sar_data # [BUG FIX] 스마트 로그 분석에서 sar_data를 참조할 수 있도록 self에 저장
        logging.info("SAR 성능 데이터 파싱 완료.")
        
        # [리팩토링] 분석 로직은 AIAnalyzer로 이동. Parser는 순수 데이터만 반환.
        perf_analysis = self._analyze_performance_bottlenecks(sar_data)
        metadata["performance_analysis"] = perf_analysis
        
        # [사용자 요청] 기본 게이트웨이 인터페이스 정보를 파싱하여 메타데이터에 추가
        ip_route_content = self._read_file(['sos_commands/networking/ip_route_show_table_all'])
        if ip_route_content != 'N/A':
            default_route_match = re.search(r'^default via .* dev (\S+)', ip_route_content, re.MULTILINE)
            if default_route_match:
                metadata.setdefault('network', {})['default_gateway_interface'] = default_route_match.group(1)

        return metadata, sar_data
