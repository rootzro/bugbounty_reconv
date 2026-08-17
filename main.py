import os
import json
import shutil
import subprocess
import re
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel

from tasks import celery_app, run_recon_task

# Load environment variables from .env file
load_dotenv()

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-pd-recon")

# Enforce strict requirement of environment variables
if not ADMIN_USER or not ADMIN_PASSWORD:
    raise RuntimeError("Critical Error: ADMIN_USER and ADMIN_PASSWORD must be defined in the .env file")

app = FastAPI(title="BugBounty Recon Dashboard")

app.mount("/static", StaticFiles(directory="static"), name="static")

# Middleware for session management and login cookies using .env SECRET_KEY
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# jinja2 Template Engine
templates = Jinja2Templates(directory="templates")

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, "bugbounty_recon", "config", "bugbounty_config.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

def is_valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    ignore_keywords = [
        "report", "scan", "target", "started", "completed", "output", 
        "directory", "generated", "vulnerabilities", "====="
    ]
    if any(kw in host.lower() for kw in ignore_keywords):
        return False
    return bool(DOMAIN_REGEX.match(host) or IP_REGEX.match(host))


class TargetRequest(BaseModel):
    target: str


def get_current_user(request: Request):
    return request.session.get("user")


def get_scanned_targets():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        return []
    
    dirs = [
        d for d in os.listdir(OUTPUT_DIR)
        if os.path.isdir(os.path.join(OUTPUT_DIR, d)) and not d.startswith(".")
    ]
    dirs.sort(key=lambda d: os.path.getmtime(os.path.join(OUTPUT_DIR, d)), reverse=True)
    return dirs


# --------------------------------------------------------------------------
# AUTHENTICATION PATHS
# --------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    login_template_path = os.path.join(BASE_DIR, "templates", "login.html")
    if os.path.exists(login_template_path):
        return templates.TemplateResponse(request=request, name="login.html")

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Login - PD Recon</title>
        <style>
            body { background: #08090a; color: #f3f4f6; font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .card { background: #0f1115; border: 1px solid #1e222d; padding: 30px; border-radius: 12px; width: 300px; }
            h2 { margin-bottom: 20px; color: #06b6d4; text-align: center; }
            input { width: 100%; padding: 10px; margin-bottom: 15px; background: #08090a; border: 1px solid #1e222d; color: white; border-radius: 6px; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #7c3aed; color: white; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; }
            button:hover { background: #6d28d9; }
        </style>
        <link rel="icon" type="image/png" sizes="16x16" href="/static/favicon.png">
    </head>
    <body>
        <div class="card">
            <h2>PD Recon Login</h2>
            <form action="/login" method="post">
                <input type="text" name="username" placeholder="User" required>
                <input type="password" name="password" placeholder="password" required>
                <button type="submit">access</button>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    # Strict credential validation against environment variables (.env)
    if username == ADMIN_USER and password == ADMIN_PASSWORD:
        request.session["user"] = username
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    
    # Re-render login template with error message on authentication failure
    login_template_path = os.path.join(BASE_DIR, "templates", "login.html")
    if os.path.exists(login_template_path):
        return templates.TemplateResponse(
            request=request, 
            name="login.html", 
            context={"error": "Invalid credentials. Please check your username or password."}
        )

    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------
# DASHBOARD AND NAVIGATION ROUTES
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def get_index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    targets = get_scanned_targets()

    raw_active_targets = []
    try:
        inspect = celery_app.control.inspect()
        active_workers = inspect.active() or {}
        for worker_name, tasks in active_workers.items():
            for task in tasks:
                if task.get("name") == "tasks.run_recon_task":
                    args = task.get("args", [])
                    if args:
                        raw_active_targets.append(args[0])
    except Exception as e:
        print(f"Error querying active tasks in Celery: {e}")

    active_targets = []
    for folder in targets:
        for at in raw_active_targets:
            if at in folder:
                active_targets.append(folder)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "targets": targets,
            "active_targets": active_targets
        }
    )


@app.get("/results", response_class=HTMLResponse)
def get_results_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    targets = get_scanned_targets()
    return templates.TemplateResponse(
        request=request,
        name="results.html",
        context={"user": user, "targets": targets}
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    config_data = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except Exception:
            config_data = {}

    settings_template_path = os.path.join(BASE_DIR, "templates", "settings.html")
    if os.path.exists(settings_template_path):
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={"user": user, "config_json": json.dumps(config_data, indent=4)}
        )

    return HTMLResponse(content=f"<h1>Recon Settings</h1><pre>{json.dumps(config_data, indent=4)}</pre>")


# --------------------------------------------------------------------------
# API ENDPOINTS
# --------------------------------------------------------------------------

@app.get("/api/targets")
def get_targets_api(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")
    return {"targets": get_scanned_targets()}


@app.get("/api/target/{target_name}/details")
@app.get("/api/details/{target_name}")
def get_target_details(target_name: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    safe_target = os.path.basename(target_name)
    target_dir = os.path.join(OUTPUT_DIR, safe_target)

    if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
        raise HTTPException(status_code=404, detail="The scan directory does not exist.")

    vulnerabilities = []
    endpoints = []
    wafs = []
    seen_subdomains = {}
    seen_endpoints = set()
    vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def get_or_create_asset(subdomain: str):
        sub = subdomain.lower().strip()
        if sub not in seen_subdomains:
            seen_subdomains[sub] = {
                "subdomain": sub,
                "status_code": "-",
                "ip": "-",
                "ports": [],
                "title": "-",
                "webserver": "-",
                "waf": "-",
                "techs": []
            }
        return seen_subdomains[sub]

    EXCLUDED_DIRS = {"reports", "temp", "logs"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d.lower() not in EXCLUDED_DIRS]

        for file in files:
            filepath = os.path.join(root, file)
            fname_lower = file.lower()

            # 0. Robust specific parsing for HTTPX files (JSON lines or plain text)
            if "httpx" in fname_lower or "web" in fname_lower or "active_webservers" in fname_lower:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as hf:
                        for line in hf:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            try:
                                entry = json.loads(line_str)
                                if isinstance(entry, dict):
                                    raw_host = entry.get("input") or entry.get("url") or entry.get("host") or ""
                                    sub = str(raw_host).replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
                                    if is_valid_host(sub):
                                        asset = get_or_create_asset(sub)
                                        
                                        ip_val = entry.get("ip") or entry.get("a") or entry.get("host-ip") or ""
                                        if isinstance(ip_val, list) and ip_val:
                                            asset["ip"] = str(ip_val[0]).strip()
                                        elif isinstance(ip_val, str) and ip_val.strip():
                                            asset["ip"] = ip_val.strip()
                                            
                                        code = entry.get("status_code") or entry.get("status-code")
                                        try:
                                            if code is not None and str(code).strip() != "":
                                                asset["status_code"] = int(code)
                                        except:
                                            pass
                                            
                                        tech_val = entry.get("tech") or entry.get("technologies") or entry.get("webserver") or entry.get("server")
                                        if tech_val:
                                            if isinstance(tech_val, list):
                                                if tech_val:
                                                    asset["webserver"] = ", ".join(str(t) for t in tech_val)
                                                    asset["techs"] = [str(t) for t in tech_val]
                                            else:
                                                asset["webserver"] = str(tech_val)
                                                asset["techs"] = [str(tech_val)]
                                        continue
                            except json.JSONDecodeError:
                                pass
                except Exception as e:
                    print(f"Error processing httpx file {filepath}: {e}")

            # 1. Parsing of Nuclei
            if "nuclei" in fname_lower:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as vf:
                        for line in vf:
                            line_str = line.strip()
                            if not line_str:
                                continue
                            parsed = False
                            try:
                                entry = json.loads(line_str)
                                if isinstance(entry, dict):
                                    info = entry.get("info", {})
                                    severity = str(info.get("severity", "info")).lower()
                                    
                                    if severity not in vuln_stats:
                                        vuln_stats[severity] = 0
                                    vuln_stats[severity] += 1

                                    vulnerabilities.append({
                                        "template_id": entry.get("template-id") or "Unknown",
                                        "name": info.get("name", "Vulnerability detected"),
                                        "severity": severity,
                                        "matched_at": entry.get("matched-at") or entry.get("host") or "-",
                                        "type": entry.get("type", "nuclei")
                                    })
                                    parsed = True
                            except json.JSONDecodeError:
                                pass

                            if not parsed and line_str.startswith("["):
                                try:
                                    parts = line_str.split("]")
                                    if len(parts) >= 3:
                                        template_id = parts[0].replace("[", "").strip()
                                        severity = "info"
                                        valid_severities = {"critical", "high", "medium", "low", "info"}
                                        for p in parts[:4]:
                                            clean_p = p.replace("[", "").strip().lower()
                                            if clean_p in valid_severities:
                                                severity = clean_p
                                                break

                                        if severity not in vuln_stats:
                                            vuln_stats[severity] = 0
                                        vuln_stats[severity] += 1

                                        matched_at_candidate = "]".join(parts[3:]).strip()
                                        url_match = re.search(r'https?://[^\s]+', matched_at_candidate)
                                        matched_at = url_match.group(0) if url_match else (matched_at_candidate.split()[0] if matched_at_candidate else "-")

                                        vulnerabilities.append({
                                            "template_id": template_id or "Unknown",
                                            "name": f"Vulnerability {template_id}",
                                            "severity": severity,
                                            "matched_at": matched_at,
                                            "type": "nuclei"
                                        })
                                except Exception as e:
                                    print(f"Error parsing nuclei line in plain text: {e}")
                except Exception as e:
                    print(f"Error processing nuclei file {filepath}: {e}")
                continue

            # 2. Parsing Endpoints
            if any(k in fname_lower for k in ["katana", "endpoint", "url", "wayback", "gau", "js_files"]):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as ef:
                        for line in ef:
                            line_str = line.strip()
                            if line_str and line_str.startswith("http") and line_str not in seen_endpoints:
                                seen_endpoints.add(line_str)
                                host_match = line_str.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                                endpoints.append({
                                    "url": line_str,
                                    "subdomain": host_match
                                })
                except Exception:
                    pass
                continue

            # 3. TXT file parsing
            if file.endswith(".txt"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        current_nmap_target = None
                        for line in f:
                            line_str = line.strip()
                            if not line_str or line_str.startswith("#") or line_str.startswith("====="):
                                continue

                            found_ips = IP_REGEX.findall(line_str)

                            potential_host = None
                            tokens = line_str.replace("https://", "").replace("http://", "").split()
                            for token in tokens:
                                clean_token = token.split("/")[0].split(":")[0].lower()
                                if is_valid_host(clean_token):
                                    potential_host = clean_token
                                    break

                            if potential_host:
                                asset = get_or_create_asset(potential_host)
                                if found_ips and asset["ip"] == "-":
                                    asset["ip"] = found_ips[0]

                                status_match = re.search(r'\[(\d{3})\]|\((\d{3})\)', line_str)
                                if status_match:
                                    code_val = status_match.group(1) or status_match.group(2)
                                    try:
                                        asset["status_code"] = int(code_val)
                                    except:
                                        pass

                                line_lower = line_str.lower()
                                servers_to_check = ["nginx", "apache", "iis", "cloudflare", "caddy", "tomcat", "express", "openresty", "gunicorn", "uvicorn", "litespeed"]
                                for srv in servers_to_check:
                                    if srv in line_lower and asset["webserver"] == "-":
                                        asset["webserver"] = srv.capitalize()
                                        if srv.capitalize() not in asset["techs"]:
                                            asset["techs"].append(srv.capitalize())
                                        break

                                if ":" in line_str and not line_str.startswith("http://") and not line_str.startswith("https://"):
                                    parts = line_str.split(":", 1)
                                    ports_part = parts[1].strip()
                                    for p_token in ports_part.split(","):
                                        p_token = p_token.strip()
                                        if "/" in p_token:
                                            p_num = p_token.split("/")[0].strip()
                                            if p_num.isdigit() and p_num not in asset["ports"]:
                                                asset["ports"].append(p_num)

                            is_waf_file = "waf" in fname_lower
                            has_waf_keyword = any(w in line_str.lower() for w in ["cloudflare", "akamai", "incapsula", "cloudfront", "sucuri", "barracuda", "imperva", "f5", "fortinet", "waf"])
                            if is_waf_file or has_waf_keyword:
                                parts = line_str.split()
                                for i, part in enumerate(parts):
                                    clean_p = part.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
                                    if is_valid_host(clean_p):
                                        waf_desc = " ".join(parts[i+1:]) if i+1 < len(parts) else "WAF"
                                        waf_desc = waf_desc.replace("is behind", "").strip(" .")
                                        if waf_desc:
                                            if {"target": clean_p, "waf": waf_desc} not in wafs:
                                                wafs.append({"target": clean_p, "waf": waf_desc})
                                            asset = get_or_create_asset(clean_p)
                                            asset["waf"] = waf_desc

                            if "Nmap scan report for" in line_str:
                                host_parts = line_str.split("for ")
                                if len(host_parts) > 1:
                                    current_nmap_target = host_parts[1].split("(")[0].strip().lower()

                            if found_ips and current_nmap_target:
                                asset = get_or_create_asset(current_nmap_target)
                                if asset["ip"] == "-":
                                    asset["ip"] = found_ips[0]

                            if ("/tcp" in line_str or "/udp" in line_str) and "open" in line_str:
                                p_parts = line_str.split()
                                if p_parts:
                                    port_num = p_parts[0].split("/")[0]
                                    target_to_use = current_nmap_target if (current_nmap_target and is_valid_host(current_nmap_target)) else safe_target
                                    asset = get_or_create_asset(target_to_use)
                                    if port_num not in asset["ports"]:
                                        asset["ports"].append(port_num)

                except Exception as e:
                    print(f"Error processing TXT {filepath}: {e}")

            # 4. JSON file parsing
            elif file.endswith(".json"):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().strip()
                        if not content:
                            continue

                        def parse_json_entry(entry):
                            if not isinstance(entry, dict):
                                val_str = str(entry).strip()
                                sub_cand = val_str.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
                                if is_valid_host(sub_cand):
                                    get_or_create_asset(sub_cand)
                                return
                            
                            if "template-id" in entry or "info" in entry:
                                return

                            raw_host = entry.get("input") or entry.get("url") or entry.get("host") or entry.get("domain") or ""
                            sub = str(raw_host).replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
                            if not is_valid_host(sub):
                                return

                            asset = get_or_create_asset(sub)

                            ip_val = entry.get("ip") or entry.get("a") or entry.get("host-ip") or entry.get("resolver") or ""
                            if isinstance(ip_val, list) and ip_val:
                                asset["ip"] = str(ip_val[0]).strip()
                            elif isinstance(ip_val, str) and ip_val.strip():
                                asset["ip"] = ip_val.strip()

                            code = entry.get("status_code") or entry.get("status-code")
                            try:
                                if code is not None and str(code).strip() != "":
                                    asset["status_code"] = int(code)
                            except:
                                pass

                            if entry.get("title"):
                                asset["title"] = str(entry.get("title"))
                            
                            webserver_val = entry.get("webserver") or entry.get("server") or entry.get("tech") or entry.get("technologies")
                            if webserver_val:
                                if isinstance(webserver_val, list):
                                    if webserver_val:
                                        asset["webserver"] = ", ".join(str(t) for t in webserver_val)
                                        asset["techs"] = [str(t) for t in webserver_val]
                                else:
                                    asset["webserver"] = str(webserver_val)
                                    asset["techs"] = [str(webserver_val)]
                            
                            tech_val = entry.get("tech") or entry.get("technologies")
                            if tech_val and isinstance(tech_val, list) and tech_val:
                                asset["techs"] = [str(t) for t in tech_val]
                                if asset["webserver"] == "-":
                                    asset["webserver"] = ", ".join(str(t) for t in tech_val)

                            waf_val = entry.get("waf") or entry.get("waf_name")
                            if waf_val and str(waf_val).lower() != "none":
                                asset["waf"] = str(waf_val)
                                if {"target": sub, "waf": str(waf_val)} not in wafs:
                                    wafs.append({"target": sub, "waf": str(waf_val)})

                            ports_val = entry.get("port") or entry.get("ports")
                            if isinstance(ports_val, (int, str)):
                                p_str = str(ports_val)
                                if p_str and p_str != "-" and p_str not in asset["ports"]:
                                    asset["ports"].append(p_str)
                            elif isinstance(ports_val, list):
                                for p in ports_val:
                                    if str(p) not in asset["ports"]:
                                        asset["ports"].append(str(p))

                        try:
                            parsed_json = json.loads(content)
                            if isinstance(parsed_json, list):
                                for item in parsed_json:
                                    parse_json_entry(item)
                            elif isinstance(parsed_json, dict):
                                parse_json_entry(parsed_json)
                        except json.JSONDecodeError:
                            for line in content.splitlines():
                                if line.strip():
                                    try:
                                        parse_json_entry(json.loads(line.strip()))
                                    except:
                                        pass
                except Exception as e:
                    print(f"Error processing JSON {filepath}: {e}")

    items = list(seen_subdomains.values())

    return {
        "target": safe_target,
        "summary": {
            "total_subdomains": len(items),
            "http_200": sum(1 for i in items if i["status_code"] == 200),
            "unique_ips": len(set(i["ip"] for i in items if i["ip"] != "-")),
            "total_endpoints": len(endpoints),
            "vuln_stats": vuln_stats
        },
        "items": items,
        "vulnerabilities": vulnerabilities,
        "endpoints": endpoints,
        "wafs": wafs
    }


@app.delete("/api/target/{target_name}")
@app.delete("/api/targets/{target_name}")
def delete_target(target_name: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    safe_target = os.path.basename(target_name)
    target_path = os.path.join(OUTPUT_DIR, safe_target)

    if not os.path.exists(target_path) or not os.path.isdir(target_path):
        raise HTTPException(status_code=404, detail="The scan directory does not exist.")

    try:
        shutil.rmtree(target_path)
        return {"status": "ok", "message": f"Scan '{safe_target}' successfully removed."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting folder: {str(e)}")


@app.post("/api/scan")
def start_scan(req: TargetRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="The target cannot be empty.")

    task = run_recon_task.delay(target)
    return {"task_id": task.id, "target": target}


@app.get("/api/scans/active")
def get_active_scans(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    active_scans = []
    try:
        inspect = celery_app.control.inspect()
        active_workers = inspect.active() or {}

        for worker_name, tasks in active_workers.items():
            for task in tasks:
                if task.get("name") == "tasks.run_recon_task":
                    args = task.get("args", [])
                    target = args[0] if args else "Unknown"
                    active_scans.append({
                        "task_id": task.get("id"),
                        "target": target
                    })
    except Exception as e:
        print(f"Error querying active tasks in Celery: {e}")

    return {"active_scans": active_scans}


@app.post("/api/scan/stop/{task_id}")
def stop_scan(task_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    container_name = f"recon_scan_{task_id}"
    container_stopped = False

    try:
        cmd = ["docker", "rm", "-f", container_name]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            container_stopped = True
    except Exception as e:
        print(f"Error deleting container via thread: {e}")

    if not container_stopped:
        try:
            import docker
            client = docker.from_env()
            container = client.containers.get(container_name)
            container.remove(force=True)
            container_stopped = True
        except Exception as e:
            print(f"Error deleting container via Docker SDK: {e}")

    try:
        celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    except Exception as e:
        print(f"Error revoking task in Celery: {e}")

    return {
        "status": "ok",
        "message": f"Scan {task_id} and container '{container_name}' stopped correctly."
    }


@app.get("/api/scan/status/{task_id}")
@app.get("/api/status/{task_id}")
def get_task_status(task_id: str):
    task = celery_app.AsyncResult(task_id)

    if task.state == "PROGRESS":
        info = task.info or {}
        return {
            "state": "PROGRESS",
            "phase": info.get("phase", "Running scan..."),
            "status": info.get("status", ""),
            "logs": info.get("logs", ""),
            "target": info.get("target", "")
        }
    elif task.state == "SUCCESS":
        result = task.result or {}
        return {
            "state": "SUCCESS",
            "phase": "Scan Completed",
            "status": "Successfully completed",
            "logs": result.get("logs", ""),
            "result": result
        }
    elif task.state == "REVOKED":
        return {
            "state": "REVOKED",
            "phase": "Canceled",
            "status": "The scan was stopped by the user",
            "logs": "Task revoked."
        }
    elif task.state == "FAILURE":
        info = task.info or {}
        return {
            "state": "FAILURE",
            "phase": "Error",
            "status": "The task has failed",
            "error": str(info)
        }

    return {
        "state": task.state,
        "phase": "In line",
        "status": "Waiting for worker assignment..."
    }


@app.get("/api/config")
def get_config(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading settings: {str(e)}")


@app.post("/api/config")
def update_config(req: dict, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authorized")

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(req, f, indent=4)
        return {"status": "ok", "message": "Saved settings."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving settings: {str(e)}")