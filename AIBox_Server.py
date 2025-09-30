#!/usr/bin/env python3

# -*- coding: utf-8 -*-
# ==============================================================================
# Unified AI Server (v7.2 - LLM 응답 안정성 강화)
# ------------------------------------------------------------------------------
# 기능:
# 1. 원본 서버의 모든 기능 완벽 복원
# 2. sos_analyzer.py 연동 기능 통합
# 3. LLM 모델 조회 기능 추가
# 4. [수정] LLM으로부터 비어있는 응답을 받았을 때 발생하는 JSON 파싱 오류 해결
# ==============================================================================

# --- 1. 라이브러리 임포트 ---
import argparse
import json
import os
import sys
import uuid
import time
import threading
import subprocess
import logging
import logging.handlers
from collections import OrderedDict
import traceback
import atexit
import re

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import requests
from werkzeug.utils import secure_filename
from waitress import serve
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore

# --- 2. 로깅 및 Flask 앱 설정 ---
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        return 'GET /api/health' not in record.getMessage()

log = logging.getLogger('werkzeug')
log.addFilter(HealthCheckFilter())
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# --- 3. 전역 변수 및 설정 ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG = {}
PROMPTS = {}
PROMPTS_FILE = os.path.join(SCRIPT_DIR, 'prompts.json')
LEARNING_DATA_FILE = os.path.join(SCRIPT_DIR, 'learning_data.json')
SERVER_INSTANCE_ID = str(uuid.uuid4())
PROMPT_SEPARATOR = "\n---USER_TEMPLATE---\n"
PROMPT_FILE_MTIME = 0
PROMPT_LOCK = threading.Lock()
UPLOAD_FOLDER = '/data/iso/AIBox/upload'
OUTPUT_FOLDER = '/data/iso/AIBox/output'
SOS_ANALYZER_SCRIPT = "/data/iso/AIBox/sos_analyzer.py"
scheduler = None

CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024 # 100 GB

# --- 4. 핵심 헬퍼 함수 ---

def sanitize_value(value):
    if isinstance(value, str):
        return CONTROL_CHAR_REGEX.sub('', value)
    return value

def sanitize_loaded_json(data):
    if isinstance(data, dict):
        return OrderedDict((k, sanitize_loaded_json(v)) for k, v in data.items())
    elif isinstance(data, list):
        return [sanitize_loaded_json(item) for item in data]
    else:
        return sanitize_value(data)

def resolve_chat_endpoint(llm_url, token):
    if llm_url.endswith(('/v1/chat/completions', '/api/chat')):
        logging.info(f"Provided LLM URL '{llm_url}' is already a full endpoint.")
        return llm_url

    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    base_url = llm_url.rstrip('/')
    logging.info(f"Probing for LLM API type at base URL: {base_url}")
    try:
        response = requests.head(f"{base_url}/v1/models", headers=headers, timeout=3)
        if response.status_code < 500:
            resolved_url = f"{base_url}/v1/chat/completions"
            logging.info(f"OpenAI-compatible API detected. Using endpoint: {resolved_url}")
            return resolved_url
    except requests.exceptions.RequestException: pass
    try:
        response = requests.head(f"{base_url}/api/tags", headers=headers, timeout=3)
        if response.status_code < 500:
            resolved_url = f"{base_url}/api/chat"
            logging.info(f"Ollama API detected. Using endpoint: {resolved_url}")
            return resolved_url
    except requests.exceptions.RequestException: pass
    return None

def get_available_models(llm_url, token):
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = f'Bearer {token}'
    try:
        base_url = llm_url.split('/v1/')[0].split('/api/')[0]
        models_url = f"{base_url.rstrip('/')}/v1/models"
        response = requests.get(models_url, headers=headers, timeout=10)
        response.raise_for_status()
        models_data = response.json().get('data', [])
        models = sorted([m.get('id') for m in models_data if m.get('id')])
        if models:
            logging.info(f"Found {len(models)} models at OpenAI-compatible endpoint.")
            return models
    except Exception as e:
        logging.warning(f"Could not connect to OpenAI-style models endpoint: {e}")
    try:
        base_url = llm_url.split('/api/')[0]
        tags_url = f"{base_url.rstrip('/')}/api/tags"
        response = requests.get(tags_url, headers=headers, timeout=10)
        response.raise_for_status()
        models_data = response.json().get('models', [])
        models = sorted([m.get('name') for m in models_data if m.get('name')])
        if models:
            logging.info(f"Found {len(models)} models at Ollama endpoint.")
            return models
    except Exception as e:
        logging.warning(f"Could not connect to Ollama-style tags endpoint: {e}")
    return []

def list_available_models(llm_url, token):
    print(f"Fetching available models from {llm_url}...")
    models = get_available_models(llm_url, token)
    if models:
        print("\n--- Available Models ---")
        for model_name in models: print(f"  - {model_name}")
    else:
        print("\n[ERROR] Could not retrieve any models.")

def make_request_generic(method, url, **kwargs):
    try:
        kwargs.setdefault('timeout', 20)
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Generic request failed for {url}: {e}")
        return None

def _parse_llm_json_response(llm_response_str: str):
    if not llm_response_str or not llm_response_str.strip():
        raise ValueError("LLM 응답이 비어 있습니다.")
    try:
        cleaned_response = re.sub(r'^```(json)?\s*|\s*```$', '', llm_response_str.strip())
        return json.loads(cleaned_response)
    except json.JSONDecodeError as e:
        error_msg = f"LLM 응답 JSON 파싱 실패: {e}"
        logging.error(f"{error_msg}.\n--- 원본 응답 ---\n{llm_response_str}\n----------------")
        raise ValueError(error_msg)

def call_llm_blocking(system_message, user_message, max_tokens=16384):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": max_tokens, "temperature": 0.1, "stream": False}
    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=300)
        response.raise_for_status()
        result = response.json()
        
        content = result.get('choices', [{}])[0].get('message', {}).get('content')
        if content is None:
            content = result.get('message', {}).get('content')
        
        if content is None or not content.strip():
            logging.error(f"LLM returned an empty or invalid content response. Full response: {result}")
            return json.dumps({"error": "LLM이 비어있는 응답을 반환했습니다.", "details": "No content from LLM."})
            
        return content
    except Exception as e:
        logging.error(f"LLM 서버 연결 또는 응답 처리 실패: {e}")
        return json.dumps({"error": "LLM 서버 연결 실패", "details": str(e)})

def call_llm_stream(system_message, user_message):
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"): headers['Authorization'] = f'Bearer {CONFIG["token"]}'
    payload = {"model": CONFIG["model"], "messages": [{"role": "system", "content": system_message}, {"role": "user", "content": user_message}], "max_tokens": 8192, "temperature": 0.2, "stream": True}
    try:
        response = requests.post(CONFIG["llm_url"], headers=headers, json=payload, timeout=180, stream=True)
        response.raise_for_status()
        for line in response.iter_lines():
            if not line: continue
            decoded_line = line.decode('utf-8')
            json_str = decoded_line[len('data: '):].strip() if decoded_line.startswith('data: ') else decoded_line
            if json_str == '[DONE]': break
            if json_str:
                try:
                    data = json.loads(json_str)
                    content = data.get('choices', [{}])[0].get('delta', {}).get('content')
                    if content is None: content = data.get('message', {}).get('content')
                    if content: yield content
                except (json.JSONDecodeError, KeyError, IndexError): pass
    except Exception as e:
        yield f"\n\n**Error:** LLM 서버 통신 오류: {e}"

def initialize_and_monitor_prompts():
    def load_prompts(force_reload=False):
        global PROMPTS, PROMPT_FILE_MTIME
        try:
            current_mtime = os.path.getmtime(PROMPTS_FILE)
            if not force_reload and current_mtime == PROMPT_FILE_MTIME: return
            with PROMPT_LOCK:
                if not force_reload and current_mtime == PROMPT_FILE_MTIME: return
                logging.info(f"'{PROMPTS_FILE}' 프롬프트 파일 다시 로드 중...")
                with open(PROMPTS_FILE, 'rb') as f: raw_data = f.read()
                content = raw_data.decode('utf-8-sig')
                start_idx, end_idx = content.find('{'), content.rfind('}')
                if start_idx == -1 or end_idx == -1: raise json.JSONDecodeError("유효한 JSON 객체를 찾을 수 없음", content, 0)
                PROMPTS = sanitize_loaded_json(json.loads(content[start_idx:end_idx+1], object_pairs_hook=OrderedDict))
                PROMPT_FILE_MTIME = current_mtime
                logging.info("프롬프트 파일 로드 및 정제 완료.")
        except Exception as e:
            logging.error(f"프롬프트 로드 실패: {e}", exc_info=True)

    if not os.path.exists(PROMPTS_FILE) or os.path.getsize(PROMPTS_FILE) == 0:
        with open(PROMPTS_FILE, 'w', encoding='utf-8') as f: json.dump(OrderedDict([("시스템 문제 해결 전문가", {"system_message": "...", "user_template": "..."})]), f, ensure_ascii=False, indent=4)
    load_prompts(force_reload=True)
    monitor_thread = threading.Thread(target=lambda: [time.sleep(5) for _ in iter(int, 1) if not load_prompts()], daemon=True)
    monitor_thread.start()

def setup_scheduler():
    global scheduler
    jobstores = {'default': SQLAlchemyJobStore(url=f'sqlite:///{os.path.join(SCRIPT_DIR, "jobs.sqlite")}')}
    scheduler = BackgroundScheduler(jobstores=jobstores, timezone='Asia/Seoul')
    logger = logging.getLogger('scheduler')
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(CONFIG["scheduler_log_file"], maxBytes=1024*1024, backupCount=5)
    logger.addHandler(handler)
    try:
        scheduler.start()
        logging.info("APScheduler 시작 완료.")
        jobs_loaded = sync_jobs_from_file()
        logging.info(f"파일에서 {jobs_loaded}개의 스케줄 작업을 로드했습니다.")
    except Exception as e:
        logging.error(f"APScheduler 시작 실패: {e}", exc_info=True)
    atexit.register(lambda: scheduler.shutdown())

def run_scheduled_script(script_path):
    log = logging.getLogger('scheduler')
    log.info(f"스크립트 실행 시도: {script_path}")
    if not os.path.isfile(script_path):
        log.error(f"스크립트 실행 실패: 파일을 찾을 수 없음 '{script_path}'")
        return
    try:
        process = subprocess.Popen(['/bin/bash', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        stdout, stderr = process.communicate()
        log.info(f"'{script_path}' 스크립트 실행 완료 (종료 코드: {process.returncode}).")
        if stdout: log.info(f"[stdout] for {script_path}:\n{stdout.strip()}")
        if stderr: log.warning(f"[stderr] for {script_path}:\n{stderr.strip()}")
    except Exception as e:
        log.error(f"스크립트 실행 중 예외 발생 '{script_path}': {e}", exc_info=True)

def sync_jobs_from_file():
    schedule_file = CONFIG.get("schedule_file")
    if not os.path.isfile(schedule_file): return 0
    try:
        with open(schedule_file, 'r', encoding='utf-8') as f: schedules = json.load(f)
        current_job_ids = {job.id for job in scheduler.get_jobs()}
        desired_job_ids = {s['script'] for s in schedules}
        for job_id in current_job_ids - desired_job_ids: scheduler.remove_job(job_id)
        for schedule in schedules:
            hour, minute = schedule['time'].split(':')
            scheduler.add_job(run_scheduled_script, 'cron', args=[schedule['script']], id=schedule['script'], hour=hour, minute=minute, replace_existing=True)
        return len(schedules)
    except Exception: return 0

# --- 5. 웹 페이지 및 API 라우팅 ---
@app.before_request
def log_request_info():
    if '/api/health' not in request.path:
        logging.info(f"Request ===> Path: {request.path}, Method: {request.method}, From: {request.remote_addr}")

@app.route('/')
def route_index_user(): return send_from_directory(SCRIPT_DIR, 'upload.html')
@app.route('/user')
def route_user(): return send_from_directory(SCRIPT_DIR, 'user.html')
@app.route('/admin')
def route_admin(): return send_from_directory(SCRIPT_DIR, 'admin.html')
@app.route('/cve')
def route_cve(): return send_from_directory(SCRIPT_DIR, 'cve_report.html')
@app.route('/cron')
def route_cron(): return send_from_directory(SCRIPT_DIR, 'cron.html')
@app.route('/output/<path:filename>')
def route_output(filename): return send_from_directory(app.config['OUTPUT_FOLDER'], filename)

@app.route('/api/health', methods=['GET'])
def api_health(): return jsonify({"status": "ok", "instance_id": SERVER_INSTANCE_ID})
@app.route('/api/config', methods=['GET'])
def api_config(): return jsonify({"model": CONFIG.get("model", "N/A")})

@app.route('/api/models', methods=['GET'])
def api_get_models():
    models = get_available_models(CONFIG["llm_url"], CONFIG.get("token"))
    if not models:
        return jsonify({"error": "Could not retrieve models from the LLM server."}), 502
    return jsonify(models)

# --- 이하 코드는 이전과 동일 ... ---

@app.route('/api/verify-password', methods=['POST'])
def api_verify_password():
    return jsonify({"success": request.json.get('password') == CONFIG.get("password")})

@app.route('/api/prompts', methods=['GET', 'POST'])
def api_prompts():
    if request.method == 'POST':
        data = request.json
        if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        try:
            prompts_to_save = OrderedDict()
            for item in data.get('prompts', []):
                key, value = item['key'], item['value']
                parts = value.split(PROMPT_SEPARATOR, 1)
                prompts_to_save[key] = {"system_message": parts[0], "user_template": parts[1] if len(parts) > 1 else ""}
            with PROMPT_LOCK:
                with open(PROMPTS_FILE, 'w', encoding='utf-8') as f: json.dump(prompts_to_save, f, ensure_ascii=False, indent=4)
            return jsonify({"success": True})
        except Exception as e: return jsonify({"error": str(e)}), 500
    else: # GET
        with PROMPT_LOCK:
            data_to_send = [{"key": k, "value": f"{v.get('system_message', '')}{PROMPT_SEPARATOR}{v.get('user_template', '')}"} for k, v in PROMPTS.items()]
            return Response(json.dumps(data_to_send, ensure_ascii=False), mimetype='application/json; charset=utf-8')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.json
    with PROMPT_LOCK: prompt_config = PROMPTS.get(data.get('prompt_key'), {})
    system_msg = prompt_config.get('system_message', '').replace('{user_query}', data.get('user_query'))
    user_msg = prompt_config.get('user_template', '{user_query}').replace('{user_query}', data.get('user_query'))
    return Response(call_llm_stream(system_msg, user_msg), mimetype='text/plain; charset=utf-8')

@app.route('/api/cve/analyze', methods=['POST'])
def api_cve_analyze_for_script():
    try:
        cve_data = request.json
        prompt = f"[CVE Data]\n{json.dumps(cve_data, indent=2, ensure_ascii=False)}\n\n[Task]\nAnalyze and return JSON with keys: 'threat_tags', 'affected_components', 'concise_summary', 'selection_reason'."
        response_str = call_llm_blocking("You are an RHEL security analyst. Return only a single, valid JSON object.", prompt)
        return jsonify(_parse_llm_json_response(response_str))
    except Exception as e:
        logging.error(f"CVE 분석 오류: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/cve/executive_summary', methods=['POST'])
def api_cve_summary_for_script():
    prompt = f"[Vulnerabilities]\n{json.dumps(request.json.get('top_cves', []), indent=2, ensure_ascii=False)}\n\n[Task]\nWrite a professional Executive Summary in Korean."
    summary = call_llm_blocking("You are a cybersecurity expert.", prompt)
    return Response(summary.replace("\n", "<br>") if summary else "", mimetype='text/html')

@app.route('/api/cve/report', methods=['POST'])
def api_cve_report_for_html():
    cve_id = request.json.get('cve_id')
    rh_data = {}
    response = make_request_generic('get', f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json")
    if response: rh_data = response.json()
    prompt = f"Generate a comprehensive Korean Markdown security report for {cve_id} based on this data and web search for recent info/PoCs.\n[Data]\n{json.dumps(rh_data, indent=2)}"
    summary = call_llm_blocking("You are an elite cybersecurity analyst.", prompt)
    final_data = rh_data.copy()
    final_data["comprehensive_summary"] = summary
    return jsonify(final_data)

@app.route('/api/schedules', methods=['GET', 'POST'])
def api_schedules():
    schedule_file = CONFIG.get("schedule_file")
    if request.method == 'POST':
        data = request.json
        if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        with open(schedule_file, 'w', encoding='utf-8') as f: json.dump(data.get('schedules', []), f, indent=4)
        sync_jobs_from_file()
        return jsonify({"success": True})
    else: # GET
        if not os.path.isfile(schedule_file): return jsonify([])
        with open(schedule_file, 'r', encoding='utf-8') as f: return jsonify(json.load(f))

@app.route('/api/schedules/execute', methods=['POST'])
def api_execute_schedule():
    data = request.json
    if data.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
    threading.Thread(target=run_scheduled_script, args=(data.get('script'),)).start()
    return jsonify({"success": True, "message": f"Execution started for {data.get('script')}"})

@app.route('/api/logs/scheduler', methods=['GET', 'DELETE'])
def api_scheduler_logs():
    log_file = CONFIG.get("scheduler_log_file")
    if request.method == 'DELETE':
        if not request.json or request.json.get('password') != CONFIG.get("password"): return jsonify({"error": "Unauthorized"}), 401
        if os.path.isfile(log_file): open(log_file, 'w').close()
        return jsonify({"success": True})
    else: # GET
        if not os.path.isfile(log_file): return jsonify([])
        with open(log_file, 'r', encoding='utf-8') as f: return jsonify(f.readlines()[-100:])

@app.route('/api/upload', methods=['POST'])
def api_upload():
    file = request.files.get('sosreportFile')
    if not file: return jsonify({"error": "No file part."}), 400
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    host_parts = request.host.split(':', 1)
    server_host = host_parts[0]
    server_port = CONFIG.get('port', 5000) 
    server_callback_url = f"http://{server_host}:{server_port}"
    
    logging.info(f"sos_analyzer 실행 (콜백 URL: {server_callback_url})")
    command = ["python3", SOS_ANALYZER_SCRIPT, "--server-url", server_callback_url, file_path]
    subprocess.Popen(command)
    analysis_id = filename.rsplit('.', 2)[0]
    return jsonify({"message": "Analysis started.", "analysis_id": analysis_id})

@app.route('/api/status/<analysis_id>', methods=['GET'])
def api_status(analysis_id):
    report_path = os.path.join(app.config['OUTPUT_FOLDER'], f"{analysis_id}_report.html")
    if os.path.exists(report_path):
        return jsonify({"status": "complete"})
    return jsonify({"status": "running"})

@app.route('/api/reports', methods=['GET', 'DELETE'])
def api_list_reports():
    if request.method == 'DELETE':
        filename = request.args.get('file')
        if not filename: return jsonify({"error": "File parameter is missing"}), 400
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"success": True})
        return jsonify({"error": "File not found"}), 404
    else: # GET
        try:
            reports = []
            for f in os.listdir(OUTPUT_FOLDER):
                if f.endswith('_report.html'):
                    file_path = os.path.join(OUTPUT_FOLDER, f)
                    mtime = os.path.getmtime(file_path)
                    reports.append({"name": f, "mtime": mtime})
            
            sorted_reports = sorted(reports, key=lambda r: r['mtime'], reverse=True)
            return jsonify(sorted_reports)
        except Exception as e:
            logging.error(f"/api/reports 오류: {e}", exc_info=True)
            return jsonify({"error": "리포트 목록을 가져오는 데 실패했습니다."}), 500

@app.route('/api/sos/analyze_system', methods=['POST'])
def api_sos_analyze_system():
    try:
        data_str = json.dumps(request.json, indent=2, ensure_ascii=False, default=str)
        prompt = f"""당신은 Red Hat Enterprise Linux 시스템의 문제를 해결하는 최고 수준의 전문가입니다. 다음 sosreport에서 추출한 상세 데이터를 종합적으로 검토하여, 전문가 수준의 진단과 해결책을 한국어로 제공해주세요.

## 분석 데이터
```json
{data_str}
{{
  "system_status": "정상|주의|위험", "overall_health_score": 100,
  "critical_issues": ["상세한 문제 설명"], "warnings": ["주의가 필요한 사항"],
  "recommendations": [{{"priority": "높음|중간|낮음", "category": "성능|보안|안정성", "issue": "문제점", "solution": "해결 방안"}}],
  "summary": "종합 요약"
}}
```"""
        response_str = call_llm_blocking("You are a helpful assistant designed to output JSON.", prompt)
        return jsonify(_parse_llm_json_response(response_str))
    except Exception as e:
        logging.error(f"/api/sos/analyze_system 오류: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/api/sos/rank_cves', methods=['POST'])
def api_sos_rank_cves():
    try:
        data = request.json
        prompt = f"[시스템 역할] RHEL 보안 분석가.\n[시스템 정보] OS: {data.get('system_info', {}).get('os_version', 'N/A')}\n[임무] 아래 CVE 목록에서 가장 시급한 최대 {data.get('max_cves', 10)}개를 선정하라.\n[입력 데이터] {json.dumps(data.get('cves_for_ranking', []), indent=2, ensure_ascii=False)}\n[출력 형식] \"most_urgent_cves\": [\"CVE-...\", ...] 키를 포함하는 JSON 객체만 출력."
        response_str = call_llm_blocking("You are a helpful assistant designed to output JSON.", prompt, max_tokens=4096)
        return jsonify(_parse_llm_json_response(response_str))
    except Exception as e:
        logging.error(f"/api/sos/rank_cves 오류: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/api/sos/summarize_cves', methods=['POST'])
def api_sos_summarize_cves():
    try:
        prompt = f"[시스템 역할] RHEL 보안 전문가. 주어진 각 CVE의 영문 설명을 분석하여 한국어로 요약 설명하라.\n[입력 데이터] {json.dumps(request.json.get('cves_to_process', []), indent=2, ensure_ascii=False)}\n[출력 형식] \"processed_cves\": [{{\"cve_id\": \"...\", \"translated_description\": \"...\"}}] 키를 포함하는 JSON 객체만 출력."
        response_str = call_llm_blocking("You are a helpful assistant designed to output JSON.", prompt)
        return jsonify(_parse_llm_json_response(response_str))
    except Exception as e:
        logging.error(f"/api/sos/summarize_cves 오류: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

# --- 7. 서버 실행 ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Unified AI Server", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--llm-url', help='Full URL for LLM server API')
    parser.add_argument('--model', help='LLM model name')
    parser.add_argument('--list-models', action='store_true', help='List available models and exit')
    parser.add_argument('--token', default=os.getenv('LLM_API_TOKEN'), help='API token for LLM server')
    parser.add_argument('--password', default='s-core', help='Password for admin functions')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--schedule-file', default='./schedule.json', help='Path to schedule JSON file')
    parser.add_argument('--scheduler-log-file', default='./scheduler.log', help='Path to scheduler log file')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.FileHandler("aibox_debug.log"), logging.StreamHandler()])

    if args.list_models:
        if not args.llm_url: parser.error("--llm-url is required to list models.")
        list_available_models(args.llm_url, args.token)
        sys.exit(0)

    if not args.llm_url:
        parser.error("--llm-url is required to start the server.")

    CONFIG.update(vars(args))
    
    resolved_llm_url = resolve_chat_endpoint(CONFIG['llm_url'], CONFIG.get('token'))
    if resolved_llm_url: CONFIG['llm_url'] = resolved_llm_url
    else: logging.warning(f"Could not automatically determine API type for '{CONFIG['llm_url']}'. Using as is.")

    if not args.model and not args.list_models:
        logging.warning("No --model specified. Attempting to use the first available model.")
        models = get_available_models(CONFIG['llm_url'], CONFIG.get('token'))
        if models:
            CONFIG['model'] = models[0]
            logging.info(f"Automatically selected model: {CONFIG['model']}")
        else:
            parser.error("--model is required as no models could be auto-detected.")

    CONFIG["schedule_file"] = os.path.abspath(args.schedule_file)
    CONFIG["scheduler_log_file"] = os.path.abspath(args.scheduler_log_file)
    
    initialize_and_monitor_prompts()
    setup_scheduler()

    logging.info(f"--- Unified AI Server starting on http://{args.host}:{args.port} ---")
    serve(app, host=args.host, port=args.port, threads=16)
