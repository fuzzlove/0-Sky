import Foundation

public actor SSHManager {
    public enum RemoteOperation: Sendable {
        case rootProbe
        case workerHeartbeat
        case linkStatus
        case linkAppRegistration
        case controlStatus
        case controlInstalled
        case controlRunning
        case cryptexHealth
        case bootstrapHealth
        case fridaHealth
        case defaultCredentialsHealth
        case vncDefaultCredentialsHealth
        case deviceStorage

        private static func bridgeStatusCommand(_ endpoint: String) -> String {
            // Read the token inside device Python. Passing its value through a
            // shell variable and wget --header exposes it in process argv.
            let program = "import pathlib,urllib.request; "
                + "token=pathlib.Path(\"/var/jb/etc/trollstorelite-srd-bridge.token\").read_text(encoding=\"ascii\").strip(); "
                + "url=\"http://127.0.0.1:48654\(endpoint)\"; "
                + "request=urllib.request.Request(url,headers={\"X-TrollStore-Bridge-Token\":token}); "
                + "print(urllib.request.urlopen(request,timeout=8).read().decode(\"utf-8\"))"
            return "/var/jb/usr/bin/python3 -c '\(program)'"
        }

        private static let linkAppProbeScript = #"""
import json,pathlib,plistlib,subprocess
bundle="codes.liquidsky.research.zerosky"
answer={"registered":False,"executable":False,"icon":False,"version":"","build":""}
try:
    listing=subprocess.run(["/var/jb/usr/bin/uicache","-l"],capture_output=True,text=True,timeout=8,check=True)
    prefix=bundle+" : "
    paths=[line[len(prefix):].strip() for line in listing.stdout.splitlines() if line.startswith(prefix)]
    if len(paths)==1:
        app=pathlib.Path(paths[0])
        path=str(app)
        allowed=path.startswith(("/private/var/containers/Bundle/Application/","/var/containers/Bundle/Application/","/private/var/run/com.apple.security.cryptexd/mnt/"))
        info=plistlib.loads((app/"Info.plist").read_bytes()) if allowed else {}
        executable=str(info.get("CFBundleExecutable",""))
        icons=info.get("CFBundleIcons",{}).get("CFBundlePrimaryIcon",{}).get("CFBundleIconFiles",[])
        answer["registered"]=allowed and info.get("CFBundleIdentifier")==bundle
        answer["executable"]=answer["registered"] and bool(executable) and "/" not in executable and (app/executable).is_file()
        answer["icon"]=answer["registered"] and isinstance(icons,list) and any(
            isinstance(name,str) and "/" not in name and any(
                (app/(name+suffix)).is_file() and (app/(name+suffix)).stat().st_size>8
                for suffix in ("@2x.png","@3x.png",".png")) for name in icons)
        answer["version"]=str(info.get("CFBundleShortVersionString",""))
        answer["build"]=str(info.get("CFBundleVersion",""))
except Exception as error:
    answer["error"]=type(error).__name__
print(json.dumps(answer,separators=(",",":"),sort_keys=True))
"""#

        private static let vncProbeScript = #"""
import ctypes,json,socket,struct

def recv_exact(sock,count):
    data=b''
    while len(data)<count:
        block=sock.recv(count-len(data))
        if not block: raise OSError('unexpected EOF')
        data+=block
    return data

def des_empty_response(challenge):
    cc=ctypes.CDLL('/usr/lib/system/libcommonCrypto.dylib')
    crypt=cc.CCCrypt
    crypt.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    crypt.restype=ctypes.c_int
    key=(ctypes.c_ubyte*8)(*([0]*8))
    source=(ctypes.c_ubyte*len(challenge)).from_buffer_copy(challenge)
    output=(ctypes.c_ubyte*len(challenge))()
    moved=ctypes.c_size_t()
    status=crypt(0,1,2,key,8,None,source,len(challenge),output,len(challenge),ctypes.byref(moved))
    if status!=0 or moved.value!=len(challenge): raise OSError('DES unavailable')
    return bytes(output)

def rfb_probe():
    value={'open':False,'protocol':None,'none_auth':False,'empty_password':False,'measured':False}
    s=socket.socket(); s.settimeout(2.0)
    try:
        s.connect(('127.0.0.1',5900)); value['open']=True
        banner=recv_exact(s,12)
        if len(banner)!=12 or not banner.startswith(b'RFB ') or banner[-1:]!=b'\n':
            value['error']='not_rfb'; return value
        value['protocol']=banner.decode('ascii','replace').strip()
        try: minor=int(banner[8:11])
        except Exception: value['error']='invalid_version'; return value
        client=b'RFB 003.008\n' if minor>=8 else (b'RFB 003.007\n' if minor>=7 else b'RFB 003.003\n')
        s.sendall(client)
        if minor>=7:
            count=recv_exact(s,1)[0]
            if count==0:
                value['error']='server_rejected'; return value
            types=list(recv_exact(s,count)); value['security_types']=types
            if 1 in types:
                s.sendall(b'\x01'); value['none_auth']=True; value['measured']=True; return value
            if 2 not in types:
                value['measured']=True; return value
            s.sendall(b'\x02')
        else:
            security=struct.unpack('>I',recv_exact(s,4))[0]; value['security_types']=[security]
            if security==1:
                value['none_auth']=True; value['measured']=True; return value
            if security!=2:
                value['measured']=True; return value
        challenge=recv_exact(s,16)
        s.sendall(des_empty_response(challenge))
        status=struct.unpack('>I',recv_exact(s,4))[0]
        value['empty_password']=(status==0); value['measured']=True
        return value
    except (OSError,ValueError,struct.error) as error:
        value['error']=type(error).__name__; return value
    finally: s.close()

def http_probe():
    value={'open':False,'unauthenticated':False,'status':None,'measured':False}
    s=socket.socket(); s.settimeout(2.0)
    try:
        s.connect(('127.0.0.1',5800)); value['open']=True
        s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        line=b''
        while b'\n' not in line and len(line)<256:
            block=s.recv(1)
            if not block: break
            line+=block
        text=line.decode('iso-8859-1','replace').strip()
        parts=text.split(' ')
        status=int(parts[1]) if len(parts)>1 and parts[1].isdigit() else None
        value['status']=status
        value['unauthenticated']=status is not None and 200<=status<400
        value['measured']=status is not None
        return value
    except (OSError,ValueError) as error:
        value['error']=type(error).__name__; return value
    finally:s.close()

rfb=rfb_probe(); http=http_probe()
unsafe=rfb.get('none_auth',False) or rfb.get('empty_password',False) or (http.get('unauthenticated',False) and not rfb.get('open',False))
measured=rfb.get('measured',False) or http.get('measured',False) or (not rfb.get('open',False) and not http.get('open',False))
print(json.dumps({'measured':measured,'unsafe':unsafe,'port_5900_open':rfb.get('open',False),'port_5800_open':http.get('open',False),'rfb_none_auth':rfb.get('none_auth',False),'rfb_empty_password':rfb.get('empty_password',False),'rfb_protocol':rfb.get('protocol'),'http_unauthenticated':http.get('unauthenticated',False),'http_status':http.get('status')},separators=(',',':'),sort_keys=True))
"""#

        fileprivate var command: String {
            switch self {
            case .rootProbe:
                return "test \"$(id -u)\" = 0 && printf '0_SKY_ROOT_READY\\n'"
            case .workerHeartbeat:
                return "test -s /var/jb/var/run/crypstore-worker.json"
            case .linkStatus:
                return Self.bridgeStatusCommand("/v1/pairing/status")
            case .linkAppRegistration:
                let payload = Data(Self.linkAppProbeScript.utf8).base64EncodedString()
                return "test -x /var/jb/usr/bin/python3 -a -x /var/jb/usr/bin/base64 || exit 127; printf '%s' '\(payload)' | /var/jb/usr/bin/base64 -d | /var/jb/usr/bin/python3 -"
            case .controlStatus:
                // The authenticated runtime endpoint reports registration,
                // mount, process and version independently from Link pairing.
                return Self.bridgeStatusCommand("/v1/runtime")
            case .controlInstalled:
                return "grep -q '\"com.liquidsky.CrypStore\"' /var/jb/var/lib/crypstore/state.json"
            case .controlRunning:
                return "ps ax -o command= | grep -q '[/]CrypStore.app/'"
            case .cryptexHealth:
                return "M=$(find /private/var/run/com.apple.security.cryptexd/mnt -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1); if test -n \"$M\"; then printf '{\"mounted\":true,\"mount\":\"%s\"}\\n' \"$(basename \"$M\")\"; else printf '{\"mounted\":false}\\n'; exit 1; fi"
            case .bootstrapHealth:
                return "P=/var/jb/Library/dpkg/status; if test -d /var/jb -a -s \"$P\" -a -x /var/jb/usr/bin/python3; then C=$(grep -c '^Status: install ok installed$' \"$P\" 2>/dev/null || true); printf '{\"root\":\"/var/jb\",\"python\":true,\"installed_packages\":%s}\\n' \"$C\"; else printf '{\"root\":\"/var/jb\",\"python\":false}\\n'; exit 1; fi"
            case .fridaHealth:
                // The upstream rootless package installs the daemon in sbin.
                // iOS 27 may expose an older /var/jb overlay before the
                // compatibility Cryptex. Select the first executable whose
                // version probe actually succeeds instead of stopping at the
                // first pathname. This also prevents a killed stale binary
                // from being reported as a usable Frida installation.
                return "F=; V=; for P in /var/jb/usr/sbin/frida-server /var/jb/usr/bin/frida-server /private/var/run/com.apple.security.cryptexd/mnt/codes.openai.research.ellekitloader.*/usr/sbin/frida-server; do test -x \"$P\" || continue; T=$(\"$P\" --version 2>/dev/null | head -n 1); test $? -eq 0 -a -n \"$T\" || continue; F=$P; V=$T; break; done; if test -z \"$F\"; then P=$(command -v frida-server 2>/dev/null || true); if test -x \"$P\"; then T=$(\"$P\" --version 2>/dev/null | head -n 1); test $? -eq 0 -a -n \"$T\" && F=$P && V=$T; fi; fi; if test -n \"$F\"; then R=false; G=/var/jb/usr/bin/grep; test -x \"$G\" || G=/usr/bin/grep; ps ax -o command= 2>/dev/null | \"$G\" -q '[f]rida-server$' && R=true; printf '{\"available\":true,\"running\":%s,\"version\":\"%s\",\"path\":\"%s\"}\\n' \"$R\" \"$V\" \"$F\"; else printf '{\"available\":false,\"running\":false}\\n'; exit 1; fi"
            case .defaultCredentialsHealth:
                // Compare only against the fixed legacy default hash. Never
                // transmit, print, or record a plaintext password.
                return "G=/var/jb/usr/bin/grep; C=/var/jb/usr/bin/cut; H=/smx7MYTQIi2M; R=false; M=false; N=0; test -x \"$G\" -a -x \"$C\" || { printf '{\"measured\":false,\"root_default\":false,\"mobile_default\":false}\\n'; exit 0; }; for F in /etc/master.passwd /private/etc/master.passwd /var/jb/etc/master.passwd; do test -r \"$F\" || continue; RH=$(\"$G\" '^root:' \"$F\" 2>/dev/null | \"$C\" -d: -f2 | head -n 1); MH=$(\"$G\" '^mobile:' \"$F\" 2>/dev/null | \"$C\" -d: -f2 | head -n 1); if test -n \"$RH\"; then N=$((N+1)); test \"$RH\" = \"$H\" && R=true; fi; if test -n \"$MH\"; then N=$((N+1)); test \"$MH\" = \"$H\" && M=true; fi; done; if test \"$N\" -eq 0; then printf '{\"measured\":false,\"root_default\":false,\"mobile_default\":false}\\n'; else printf '{\"measured\":true,\"root_default\":%s,\"mobile_default\":%s,\"accounts_measured\":%s}\\n' \"$R\" \"$M\" \"$N\"; fi"
            case .vncDefaultCredentialsHealth:
                // Probe only loopback device services, use a bounded RFB
                // handshake, and test the null-password response in-memory.
                // No password, challenge, or key material is logged.
                let payload = Data(Self.vncProbeScript.utf8).base64EncodedString()
                return "test -x /var/jb/usr/bin/python3 -a -x /var/jb/usr/bin/base64 || exit 127; printf '%s' '\(payload)' | /var/jb/usr/bin/base64 -d | /var/jb/usr/bin/python3 -"
            case .deviceStorage:
                return "A=/var/jb/usr/bin/awk; G=/var/jb/usr/bin/grep; test -x \"$A\" || A=/usr/bin/awk; test -x \"$G\" || G=/usr/bin/grep; if test -x \"$A\"; then K=$(df -Pk /private/var 2>/dev/null | $A 'NR==2 {print $4}'); else T=/var/jb/usr/bin/tail; R=/var/jb/usr/bin/tr; C=/var/jb/usr/bin/cut; test -x \"$T\" -a -x \"$R\" -a -x \"$C\" || { printf '{\"available_kib\":null}\\n'; exit 1; }; K=$(df -Pk /private/var 2>/dev/null | $T -n 1 | $R -s ' ' | $C -d ' ' -f 4); fi; test -x \"$G\" && printf '%s' \"$K\" | $G -Eq '^[0-9]+$' && printf '{\"available_kib\":%s}\\n' \"$K\" || { printf '{\"available_kib\":null}\\n'; exit 1; }"
            }
        }
    }

    private let runner: ScriptRunner

    public init(runner: ScriptRunner) { self.runner = runner }

    public func arguments(for profile: DeviceProfile, operation: RemoteOperation? = nil) throws -> [String] {
        try arguments(
            for: profile,
            operation: operation,
            host: profile.sshHost,
            port: profile.localPort
        )
    }

    private func arguments(
        for profile: DeviceProfile,
        operation: RemoteOperation?,
        host: String,
        port: Int
    ) throws -> [String] {
        _ = try BridgeValidation.validateUDID(profile.udid)
        if port != 22 { _ = try BridgeValidation.validatePort(port) }
        _ = try BridgeValidation.validateHostAlias(profile.sshHostAlias)
        guard host == "127.0.0.1" || host == "localhost"
                || host == "\(profile.udid).coredevice.local" else {
            throw BridgeCoreError.invalidPath(host)
        }
        guard profile.knownHostsPath.hasPrefix("/"), profile.sshKeyPath.hasPrefix("/") else {
            throw BridgeCoreError.invalidPath("SSH trust paths must be absolute")
        }
        var values = [
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            "-o", "ConnectionAttempts=1",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=\"\(profile.knownHostsPath)\"",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "HostKeyAlias=\(profile.sshHostAlias)",
            "-o", "IdentitiesOnly=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-i", profile.sshKeyPath,
            "-p", String(port),
            "root@\(host)",
        ]
        if let operation {
            values.append(operation.command)
        }
        return values
    }

    public func probe(_ profile: DeviceProfile) async -> BridgeOperationResult {
        let primary = await execute(profile: profile, operation: .rootProbe, suffix: "probe")
        guard !primary.succeeded, profile.sshHost == "127.0.0.1" || profile.sshHost == "localhost" else {
            return primary
        }
        return await execute(
            profile: profile,
            operation: .rootProbe,
            suffix: "probe.wireless",
            host: "\(profile.udid).coredevice.local",
            port: 22
        )
    }

    private func execute(
        profile: DeviceProfile,
        operation: RemoteOperation,
        suffix: String,
        host: String? = nil,
        port: Int? = nil
    ) async -> BridgeOperationResult {
        do {
            return try await runner.run(ScriptSpecification(
                identifier: "ssh.\(suffix).\(profile.instanceName)",
                executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
                arguments: try arguments(for: profile, operation: operation,
                                         host: host ?? profile.sshHost,
                                         port: port ?? profile.localPort),
                timeout: .seconds(15)
            ))
        } catch {
            let now = Date()
            return BridgeOperationResult(
                identifier: "ssh.\(suffix).\(profile.instanceName)",
                startedAt: now, finishedAt: now, exitCode: 255,
                stdout: "", stderr: error.localizedDescription
            )
        }
    }

    public func run(_ operation: RemoteOperation, profile: DeviceProfile) async -> BridgeOperationResult {
        let suffix = String(describing: operation)
        let primary = await execute(profile: profile, operation: operation, suffix: suffix)
        guard !primary.succeeded, profile.sshHost == "127.0.0.1" || profile.sshHost == "localhost" else {
            return primary
        }
        return await execute(
            profile: profile,
            operation: operation,
            suffix: "\(suffix).wireless",
            host: "\(profile.udid).coredevice.local",
            port: 22
        )
    }

    public func listRecentCrashReports(profile: DeviceProfile, since: Date) async -> BridgeOperationResult {
        let minutes = max(1, min(24 * 60, Int(ceil(Date().timeIntervalSince(since) / 60)) + 1))
        let command = "for R in /var/mobile/Library/Logs/CrashReporter /Library/Logs/CrashReporter; do test -d \"$R\" && find \"$R\" -type f -mmin -\(minutes) -size -8388608c 2>/dev/null; done"
        return await executeCommand(profile: profile, command: command, suffix: "crash-list", timeout: .seconds(20))
    }

    public func readCrashReport(profile: DeviceProfile, path: String) async -> BridgeOperationResult {
        guard path.count <= 1_024, !path.contains("\0"), !path.contains("\n"), !path.contains("\r"),
              !path.split(separator: "/").contains(".."),
              path.hasPrefix("/var/mobile/Library/Logs/CrashReporter/")
                || path.hasPrefix("/Library/Logs/CrashReporter/") else {
            let now = Date()
            return BridgeOperationResult(identifier: "ssh.crash-read.rejected", startedAt: now,
                                         finishedAt: now, exitCode: 126, stdout: "",
                                         stderr: "Rejected unsafe crash report path.")
        }
        let encoded = Data(path.utf8).base64EncodedString()
        let command = "P=$(printf '%s' '\(encoded)' | /usr/bin/base64 -d); case \"$P\" in /var/mobile/Library/Logs/CrashReporter/*|/Library/Logs/CrashReporter/*) test -f \"$P\" -a ! -L \"$P\" && cat -- \"$P\";; *) exit 126;; esac"
        return await executeCommand(profile: profile, command: command, suffix: "crash-read", timeout: .seconds(20))
    }

    private func executeCommand(profile: DeviceProfile, command: String, suffix: String,
                                timeout: Duration) async -> BridgeOperationResult {
        func run(host: String, port: Int) async -> BridgeOperationResult? {
            try? await runner.run(ScriptSpecification(
                identifier: "ssh.\(suffix).\(profile.instanceName)",
                executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
                arguments: try arguments(for: profile, operation: nil, host: host, port: port) + [command],
                timeout: timeout
            ))
        }
        if let primary = await run(host: profile.sshHost, port: profile.localPort), primary.succeeded {
            return primary
        }
        if profile.sshHost == "127.0.0.1" || profile.sshHost == "localhost",
           let wireless = await run(host: "\(profile.udid).coredevice.local", port: 22) {
            return wireless
        }
        let now = Date()
        return BridgeOperationResult(identifier: "ssh.\(suffix).\(profile.instanceName)",
                                     startedAt: now, finishedAt: now, exitCode: 255,
                                     stdout: "", stderr: "Crash report SSH operation failed.")
    }
}
