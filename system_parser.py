# -*- coding: utf-8 -*-
import datetime
import logging
import re
from typing import Dict, Any, List


def parse_system_details(parser_instance) -> Dict[str, Any]:
    logging.debug("시스템 기본 정보 파싱 중...")
    lscpu_output = parser_instance._read_file(['lscpu', 'sos_commands/processor/lscpu'])
    meminfo = parser_instance._read_file(['proc/meminfo'])
    dmidecode = parser_instance._read_file(['dmidecode', 'sos_commands/hardware/dmidecode'])
    mem_total_match = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo)
    cpu_model_match = re.search(r'Model name:\s+(.+)', lscpu_output)
    model_match = re.search(r'Product Name:\s*(.*)', dmidecode)
    cpu_str = f"{parser_instance.cpu_cores_count} x {cpu_model_match.group(1).strip()}" if parser_instance.cpu_cores_count > 0 and cpu_model_match else 'N/A'
    uptime_content = parser_instance._read_file(['uptime', 'sos_commands/general/uptime'])
    uptime_str = "N/A"
    uptime_match = re.search(r'up\s+(.*?),\s*\d+\s+user', uptime_content)
    if uptime_match: uptime_str = uptime_match.group(1).strip()
    uname_content = parser_instance._read_file(['uname', 'sos_commands/kernel/uname_-a'])
    kernel_str = uname_content.split()[2] if len(uname_content.split()) >= 3 else uname_content

    os_release_str = parser_instance._read_file(['etc/redhat-release'])

    proc_stat_content = parser_instance._read_file(['proc/stat'])
    boot_time_str = "N/A"
    btime_match = re.search(r'^btime\s+(\d+)', proc_stat_content, re.MULTILINE)
    if btime_match:
        try:
            epoch_time = int(btime_match.group(1))
            boot_dt = datetime.datetime.fromtimestamp(epoch_time)
            boot_time_str = f"{boot_dt.strftime('%a %b %d %H:%M:%S %Z %Y')} (epoch: {epoch_time})"
        except (ValueError, TypeError) as e:
            logging.warning(f"부팅 시간 변환 중 오류 발생: {e}")
            boot_time_str = parser_instance._read_file(['sos_commands/general/uptime_-s']).strip()

    return {'hostname': parser_instance._read_file(['hostname']), 'os_release': os_release_str, 'kernel': kernel_str,
            'system_model': model_match.group(1).strip() if model_match else 'N/A', 'cpu': cpu_str,
            'memory': f"{int(mem_total_match.group(1)) / 1024 / 1024:.1f} GiB" if mem_total_match else "N/A",
            'uptime': uptime_str, 'boot_time': boot_time_str,
            'report_creation_date': parser_instance.report_date.strftime(
                '%a %b %d %H:%M:%S %Z %Y') if parser_instance.report_date else 'N/A'}


def parse_storage(parser_instance) -> List[Dict[str, Any]]:
    logging.debug("스토리지 및 파일 시스템 정보 파싱 중...")
    df_output = parser_instance._read_file(['df', 'sos_commands/filesys/df_-alPh', 'sos_commands/filesys/df_-h'])
    storage_list = []
    for line in df_output.strip().split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[0].startswith('/'):
            storage_list.append(
                {"filesystem": parts[0], "size": parts[1], "used": parts[2], "avail": parts[3], "use_pct": parts[4],
                 "mounted_on": parts[5]})
    return storage_list


def parse_process_stats(parser_instance) -> Dict[str, Any]:
    logging.debug("프로세스 통계 파싱 중...")
    ps_content = parser_instance._read_file(['ps', 'sos_commands/process/ps_auxwww'])
    processes = []
    for line in ps_content.split('\n')[1:]:
        parts = line.split(maxsplit=10)
        if len(parts) >= 11:
            try:
                processes.append({'user': parts[0], 'pid': int(parts[1]), 'cpu_pct': float(parts[2]),
                                  'mem_pct': float(parts[3]), 'rss_kb': int(parts[5]), 'stat': parts[7],
                                  'command': parts[10]})
            except (ValueError, IndexError):
                continue
    user_stats = {}
    for p in processes:
        user = p['user']
        if user not in user_stats: user_stats[user] = {'count': 0, 'cpu_pct': 0.0, 'mem_pct': 0.0, 'rss_kb': 0}
        user_stats[user]['count'] += 1
        user_stats[user]['cpu_pct'] += p['cpu_pct']
        user_stats[user]['mem_pct'] += p['mem_pct']
        user_stats[user]['rss_kb'] += p['rss_kb']
    top_users = sorted(user_stats.items(), key=lambda item: item[1]['cpu_pct'], reverse=True)[:5]
    return {'total': len(processes), 'top_cpu': sorted(processes, key=lambda p: p['cpu_pct'], reverse=True)[:5],
            'top_mem': sorted(processes, key=lambda p: p['rss_kb'], reverse=True)[:5],
            'uninterruptible': [p for p in processes if 'D' in p['stat']],
            'zombie': [p for p in processes if 'Z' in p['stat']],
            'by_user': [{'user': user, **stats} for user, stats in top_users]}


def parse_additional_info(parser_instance) -> Dict[str, Any]:
    logging.debug("추가 시스템 정보(커널 파라미터, SELinux 등) 파싱 중...")
    sestatus = {k.strip().lower().replace(' ', '_'): v.strip() for k, v in
                (l.split(':', 1) for l in
                 parser_instance._read_file(['sos_commands/selinux/sestatus_-v']).split('\n') if ':' in l)}

    rpm_content = parser_instance._read_file(['installed-rpms', './installed-rpms'])
    packages: List[Dict[str, str]] = []
    for line in rpm_content.strip().split('\n'):
        if not line or line.startswith('gpg-pubkey'):
            continue
        full_package_string = line.split()[0]
        package_string_no_arch = re.sub(r'\.(x86_64|i686|noarch|aarch64|ppc64le|s390x)$', '', full_package_string)
        parts = package_string_no_arch.rsplit('-', 2)
        if len(parts) == 3 and re.search(r'[\d.]', parts[1]):
            name, version, release = parts
            packages.append({'name': name, 'version': f"{version}-{release}"})

    failed_services = [l.strip().split()[0] for l in
                       parser_instance._read_file(['sos_commands/systemd/systemctl_list-units_--all']).split('\n') if
                       'failed' in l]

    sshd_config_content = parser_instance._read_file(['etc/ssh/sshd_config'])
    sshd_config = {k.strip(): v.strip() for k, v in
                   (re.split(r'\s+', line, 1) for line in sshd_config_content.split('\n') if
                    line.strip() and not line.strip().startswith('#')) if len(re.split(r'\s+', line, 1)) == 2}

    boot_cmdline = parser_instance._read_file(['proc/cmdline'])
    dmsetup_info = parser_instance._read_file(['sos_commands/devicemapper/dmsetup_info_-c'])
    sudoers_content = parser_instance._read_file(['etc/sudoers'])

    return {"boot_cmdline": boot_cmdline, "selinux_status": sestatus, "installed_packages": packages,
            "failed_services": failed_services,
            "configurations": {"sshd_config": sshd_config, "dmsetup_info": dmsetup_info,
                               "sudoers_content": sudoers_content}}
