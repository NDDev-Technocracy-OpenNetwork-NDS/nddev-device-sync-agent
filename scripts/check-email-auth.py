#!/usr/bin/env python3
"""Actual CLI email OTP and native-session acceptance on an explicitly owned fixture."""
import argparse,json,os,re,secrets,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
from urllib.parse import urlparse

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fixture",type=Path,required=True)
parser.add_argument("--cli",type=Path,required=True)
parser.add_argument("--source",required=True)
parser.add_argument("--evidence",type=Path,required=True)
parser.add_argument("--worker",type=Path,help=argparse.SUPPRESS)
args=parser.parse_args()
repo=Path(__file__).resolve().parents[1]
for path in [args.fixture,args.cli,args.evidence]:
    assert path.is_absolute() and not path.resolve().is_relative_to(repo)
assert re.fullmatch("[0-9a-f]{40}",args.source)
fixture=json.loads(args.fixture.read_text())
assert fixture["status"]=="running" and fixture["expires_at_unix"]>time.time()+180
assert fixture["owner_email"].endswith("@example.invalid")
for key in ["base_url","mailpit_url"]:
    url=urlparse(fixture[key])
    assert url.scheme=="http" and url.hostname=="127.0.0.1" and url.port
    assert not url.username and not url.password and not url.query and not url.fragment
    assert url.path in ["","/"]
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def get(path):
    with http.open(path,timeout=3) as response:
        assert response.status==200
        raw=response.read(65537)
        assert len(raw)<=65536
        return json.loads(raw)

def result(path):
    raw=path.read_text()
    assert len(raw)<=2*1024*1024
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    assert len(rows)==1 and isinstance(rows[0],dict)
    return rows[0]

def command(name,words,env):
    with (args.evidence/(name+".out")).open("wb") as out,(args.evidence/(name+".log")).open("wb") as log:
        code=subprocess.run([str(args.cli),"--server",fixture["base_url"],"auth",*words],
                            stdout=out,stderr=log,env=env,timeout=45).returncode
    return code,result(args.evidence/(name+".out"))

def worker():
    root=args.worker
    assert root is not None and root.is_dir()
    daemon=None;child=None
    try:
        with (args.evidence/"keyring.log").open("wb") as log:
            daemon=subprocess.Popen(["gnome-keyring-daemon","--foreground","--components=secrets","--unlock",
                                     "--control-directory",str(root/"control")],
                                    stdin=subprocess.PIPE,stdout=log,stderr=log)
            daemon.stdin.write(secrets.token_urlsafe(32).encode());daemon.stdin.close()
            end=time.monotonic()+10
            while time.monotonic()<end:
                assert daemon.poll() is None
                ready=subprocess.run(["gdbus","call","--session","--dest","org.freedesktop.DBus",
                                      "--object-path","/org/freedesktop/DBus","--method",
                                      "org.freedesktop.DBus.GetConnectionUnixProcessID","org.freedesktop.secrets"],
                                     capture_output=True,timeout=2)
                if ready.returncode==0:
                    assert int(re.findall(rb"\d+",ready.stdout)[-1])==daemon.pid
                    break
                time.sleep(.1)
            else:raise TimeoutError("owned credential service")
            old={item["ID"] for item in get(fixture["mailpit_url"]+"/api/v1/messages")["messages"]}
            with (args.evidence/"email.out").open("wb") as out,(args.evidence/"email.log").open("wb") as err:
                child=subprocess.Popen([str(args.cli),"--server",fixture["base_url"],"auth","email",fixture["owner_email"]],
                                       stdin=subprocess.PIPE,stdout=out,stderr=err)
                deadline=time.monotonic()+40;code=None
                while time.monotonic()<deadline:
                    assert child.poll() is None
                    for item in get(fixture["mailpit_url"]+"/api/v1/messages")["messages"]:
                        if item["ID"] in old:continue
                        message=get(fixture["mailpit_url"]+"/api/v1/message/"+item["ID"])
                        if not any(row["Address"]==fixture["owner_email"] for row in message["To"]):continue
                        found=re.search(r"\b[0-9]{8}\b",message["Text"])
                        if found:code=found[0];break
                    if code:break
                    time.sleep(.1)
                assert code is not None,"owned OTP delivery"
                child.stdin.write((code+"\n").encode());child.stdin.close()
                assert child.wait(timeout=45)==0
            signed=result(args.evidence/"email.out")
            assert signed["operation"]=="auth.email"
            session=signed["session"]
            assert session["authenticated"] and session["session_verified"] and session["credential_store_ready"]
            assert session["user_id"] and session["tenant_id"] and session["device_id"]
            for path in [args.evidence/"email.out",args.evidence/"email.log"]:
                raw=path.read_text()
                assert code not in raw and fixture["owner_email"] not in raw
            code=None
            status,observed=command("restored",["status"],os.environ)
            assert status==0 and observed["session"]["authenticated"]
            assert observed["session"]["user_id"]==session["user_id"]
            assert observed["session"]["device_id"]==session["device_id"]
            status,ended=command("logout",["logout"],os.environ)
            assert status==0 and not ended["session"]["authenticated"]
            status,anonymous=command("anonymous",["status"],os.environ)
            assert status==0 and not anonymous["session"]["authenticated"]
            proof={"source":args.source,"actual_email_otp":True,"code_absent_from_args_and_output":True,
                   "native_session_restored_in_new_process":True,"same_principal_and_device":True,
                   "logout_confirmed_in_new_process":True,"scope":"Owned loopback PG/SMTP fixture and private native Secret Service; no live mailbox claim."}
            (args.evidence/"proof.json").write_text(json.dumps(proof,indent=2)+"\n")
            print("PASS: actual CLI email OTP, native session restoration and logout",flush=True)
    finally:
        for process in [child,daemon]:
            if process is not None and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()

if args.worker is not None:
    worker()
else:
    args.evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="nds-email-") as temporary:
        root=Path(temporary);env=dict(os.environ)
        for key,name in [("XDG_DATA_HOME","data"),("XDG_STATE_HOME","state"),("XDG_CONFIG_HOME","config"),
                         ("XDG_CACHE_HOME","cache"),("XDG_RUNTIME_DIR","runtime")]:
            (root/name).mkdir(mode=0o700);env[key]=str(root/name)
        (root/"data/keyrings").mkdir(mode=0o700);(root/"control").mkdir(mode=0o700)
        for key in ["DBUS_SESSION_BUS_ADDRESS","GNOME_KEYRING_CONTROL","SSH_AUTH_SOCK","GH_TOKEN","GITHUB_TOKEN"]:
            env.pop(key,None)
        subprocess.run(["dbus-run-session","--",sys.executable,__file__,*sys.argv[1:],"--worker",str(root)],
                       env=env,check=True,timeout=180)
    print("Owned credential session exited; temporary root removed",flush=True)
