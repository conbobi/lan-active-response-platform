// ============================================================================
// LARP C++ Agent — Fixed version with proper ACK, pending_commands parsing
// ============================================================================

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef WINVER
#define WINVER 0x0602
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <map>
#include <regex>
#include <ctime>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#ifndef WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS
#define WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS 1000
#endif
class WSClient;  // ← THÊM DÒNG NÀY — forward declaration

std::string g_agent_id, g_hostname, g_ip, g_mac, g_manager_url;
int g_interval = 15;
std::atomic<bool> g_connected{false};
std::atomic<time_t> g_last_message{0};
WSClient* g_ws = nullptr;          // ← OK vì đã forward declare
std::mutex g_ws_mutex;
std::mutex g_ws_send_mutex;
std::mutex g_ws_recv_mutex;
// ============ LOG ============
std::mutex g_log_mutex;
void Log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    localtime_s(&tm_buf, &t);
    printf("[%02d:%02d:%02d] %s\n", tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msg.c_str());
    fflush(stdout);
}

// ============ STRING ============
std::string WStringToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], size, nullptr, nullptr);
    return result;
}

std::string EscapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) out += '?';  // control char → replace
                else out += c;
        }
    }
    return out;
}

std::string GetEnv(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string();
}

// ============ JSON HELPERS (minimal, for heartbeat response) ============
// Extract string value for "key": "value"
std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    while (pos < json.size() && isspace((unsigned char)json[pos])) pos++;
    if (pos >= json.size() || json[pos] != '"') return "";
    pos++;  // skip opening quote
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            char n = json[pos + 1];
            switch (n) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += n;
            }
            pos += 2;
        } else {
            result += json[pos++];
        }
    }
    return result;
}

// Extract array value for "key": [...]  (returns raw JSON between brackets)
std::string JsonGetArrayRaw(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    while (pos < json.size() && isspace((unsigned char)json[pos])) pos++;
    if (pos >= json.size() || json[pos] != '[') return "";
    int depth = 0;
    size_t start = pos;
    bool in_str = false;
    bool escape = false;
    for (size_t i = pos; i < json.size(); i++) {
        char c = json[i];
        if (in_str) {
            if (escape) { escape = false; }
            else if (c == '\\') { escape = true; }
            else if (c == '"') { in_str = false; }
        } else {
            if (c == '"') in_str = true;
            else if (c == '[') depth++;
            else if (c == ']') {
                depth--;
                if (depth == 0) return json.substr(start, i - start + 1);
            }
        }
    }
    return "";
}

// Split array of objects: "[{...}, {...}]" → ["{...}", "{...}"]
std::vector<std::string> SplitJsonObjects(const std::string& arr_raw) {
    std::vector<std::string> result;
    if (arr_raw.size() < 2) return result;
    size_t i = 1;  // skip '['
    while (i < arr_raw.size() - 1) {  // skip ']'
        while (i < arr_raw.size() && (isspace((unsigned char)arr_raw[i]) || arr_raw[i] == ',')) i++;
        if (i >= arr_raw.size() - 1) break;
        if (arr_raw[i] != '{') break;
        int depth = 0;
        bool in_str = false, escape = false;
        size_t start = i;
        for (; i < arr_raw.size(); i++) {
            char c = arr_raw[i];
            if (in_str) {
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') in_str = false;
            } else {
                if (c == '"') in_str = true;
                else if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) { i++; break; }
                }
            }
        }
        result.push_back(arr_raw.substr(start, i - start));
    }
    return result;
}

// ============ MACHINE INFO ============
std::string GetMachineGuid() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return "";
    wchar_t buf[256] = {0};
    DWORD size = sizeof(buf), type = 0;
    RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(hKey);
    return WStringToUTF8(buf);
}

std::string GetHostname() {
    wchar_t buf[256] = {0};
    DWORD size = sizeof(buf) / sizeof(wchar_t);
    GetComputerNameW(buf, &size);
    return WStringToUTF8(buf);
}

std::string GetLocalIP() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    DWORD ret = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (addrs) free(addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!addrs) return "127.0.0.1";
        ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, addrs, &outBufLen);
        if (ret == NO_ERROR) break;
        if (ret != ERROR_BUFFER_OVERFLOW) { free(addrs); return "127.0.0.1"; }
    }
    if (ret != NO_ERROR || !addrs) { if (addrs) free(addrs); return "127.0.0.1"; }
    std::string best;
    for (auto a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((sockaddr_in*)u->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
            std::string s = ip;
            if (s.rfind("169.254.", 0) == 0 || s == "127.0.0.1") continue;
            if (a->IfType == IF_TYPE_ETHERNET_CSMACD) { best = s; goto done; }
            if (best.empty()) best = s;
        }
    }
done:
    free(addrs);
    return best.empty() ? "127.0.0.1" : best;
}

std::string GetMacAddress() {
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    DWORD ret = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (addrs) free(addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!addrs) return "";
        ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, addrs, &outBufLen);
        if (ret == NO_ERROR) break;
        if (ret != ERROR_BUFFER_OVERFLOW) { free(addrs); return ""; }
    }
    if (ret != NO_ERROR || !addrs) { if (addrs) free(addrs); return ""; }
    std::string result;
    for (auto a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength != 6) continue;
        bool all_zero = true;
        for (int i = 0; i < 6; i++) if (a->PhysicalAddress[i] != 0) { all_zero = false; break; }
        if (all_zero) continue;
        char buf[32];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                 a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
        result = buf;
        break;
    }
    free(addrs);
    return result;
}

std::string LoadOrCreateAgentId() {
    std::string env_id = GetEnv("AGENT_ID");
    if (!env_id.empty()) { Log("[*] AGENT_ID from ENV: " + env_id); return env_id; }
    std::string config_dir = "C:\\ProgramData\\LARP";
    std::string config_file = config_dir + "\\agent_id.txt";
    CreateDirectoryA(config_dir.c_str(), nullptr);
    std::ifstream f(config_file);
    if (f.is_open()) {
        std::string id; std::getline(f, id); f.close();
        if (!id.empty()) return id;
    }
    std::string guid = GetMachineGuid(), id;
    if (!guid.empty()) {
        std::string clean;
        for (char c : guid) if (c != '-') clean += c;
        id = "win-" + clean.substr(0, 16);
    } else {
        id = "win-" + GetHostname();
    }
    std::ofstream out(config_file);
    out << id << std::endl;
    return id;
}

// ============ PROCESS COLLECTOR ============
typedef LONG(NTAPI* NtQueryInformationProcess_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
NtQueryInformationProcess_t g_NtQueryInformationProcess = nullptr;

struct ProcessInfo {
    DWORD pid;
    DWORD ppid;
    std::string name;
    std::string exe;
    std::string cmdline;
};

std::string GetProcessCmdline(HANDLE hProc) {
    if (!g_NtQueryInformationProcess) return "";
    ULONG size = 0;
    g_NtQueryInformationProcess(hProc, 60, nullptr, 0, &size);
    if (size == 0 || size > 64 * 1024) return "";
    std::vector<BYTE> buf(size);
    ULONG returned_size = size;
    if (g_NtQueryInformationProcess(hProc, 60, buf.data(), size, &returned_size) != 0) return "";
    auto* us = (UNICODE_STRING*)buf.data();
    if (!us->Buffer || us->Length == 0) return "";
    BYTE* buf_start = buf.data();
    BYTE* buf_end = buf.data() + buf.size();
    BYTE* us_buf = (BYTE*)us->Buffer;
    if (us_buf < buf_start || us_buf + us->Length > buf_end) return "";
    return WStringToUTF8(std::wstring(us->Buffer, us->Length / sizeof(wchar_t)));
}

std::vector<ProcessInfo> CollectProcesses() {
    std::vector<ProcessInfo> result;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.ppid = pe.th32ParentProcessID;
            pi.name = WStringToUTF8(pe.szExeFile);
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                        FALSE, pi.pid);
            if (hProc) {
                wchar_t path[MAX_PATH] = {0};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, path, &pathLen)) pi.exe = WStringToUTF8(path);
                pi.cmdline = GetProcessCmdline(hProc);
                CloseHandle(hProc);
            }
            result.push_back(pi);
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return result;
}

// ============ NETWORK COLLECTOR ============
struct NetConn {
    DWORD pid;
    std::string process_name;
    std::string src_ip, dst_ip;
    int src_port, dst_port;
    std::string protocol;
};

std::map<DWORD, std::string> GetProcessNameMap() {
    std::map<DWORD, std::string> m;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return m;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do { m[pe.th32ProcessID] = WStringToUTF8(pe.szExeFile); }
        while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return m;
}

std::vector<NetConn> CollectNetwork() {
    std::vector<NetConn> result;
    auto nameMap = GetProcessNameMap();
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return result;
    std::vector<BYTE> buf(size);
    auto* table = (PMIB_TCPTABLE_OWNER_PID)buf.data();
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        return result;
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto& row = table->table[i];
        if (row.dwState != MIB_TCP_STATE_ESTAB) continue;
        NetConn nc;
        nc.pid = row.dwOwningPid;
        nc.src_ip = std::to_string(row.dwLocalAddr & 0xFF) + "." +
                    std::to_string((row.dwLocalAddr >> 8) & 0xFF) + "." +
                    std::to_string((row.dwLocalAddr >> 16) & 0xFF) + "." +
                    std::to_string((row.dwLocalAddr >> 24) & 0xFF);
        nc.src_port = ntohs((u_short)row.dwLocalPort);
        nc.dst_ip = std::to_string(row.dwRemoteAddr & 0xFF) + "." +
                    std::to_string((row.dwRemoteAddr >> 8) & 0xFF) + "." +
                    std::to_string((row.dwRemoteAddr >> 16) & 0xFF) + "." +
                    std::to_string((row.dwRemoteAddr >> 24) & 0xFF);
        nc.dst_port = ntohs((u_short)row.dwRemotePort);
        nc.protocol = "TCP";
        auto it = nameMap.find(nc.pid);
        nc.process_name = (it != nameMap.end()) ? it->second : "unknown";
        result.push_back(nc);
    }
    return result;
}

// ============ COMMAND RESULT ============
struct CommandResult {
    std::string status;   // "success" | "failed"
    std::string error_message;
};

// ============ COMMAND HANDLERS (return CommandResult with proper status) ============
CommandResult HandleKillProcess(DWORD pid, bool tree) {
    std::wstring cmd = L"taskkill /F ";
    if (tree) cmd += L"/T ";
    cmd += L"/PID " + std::to_wstring(pid);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
    cmdBuf.push_back(0);

    if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if (exitCode == 0) return {"success", ""};
        return {"failed", "taskkill returned non-zero exit code " + std::to_string(exitCode)};
    }
    return {"failed", "CreateProcessW failed: " + std::to_string(GetLastError())};
}

// FIX B3: Parse manager host from g_manager_url instead of hardcoded
CommandResult HandleIsolate() {
    // Parse host from g_manager_url (e.g. "ws://192.168.30.105:8005/ws/agent")
    std::string url = g_manager_url;
    size_t proto_end = url.find("://");
    if (proto_end != std::string::npos) url = url.substr(proto_end + 3);
    size_t path_start = url.find('/');
    if (path_start != std::string::npos) url = url.substr(0, path_start);
    size_t port_start = url.find(':');
    std::string manager_host = (port_start != std::string::npos) ? url.substr(0, port_start) : url;
    std::string manager_port = (port_start != std::string::npos) ? url.substr(port_start + 1) : "443";

    Log("[*] HandleIsolate: manager=" + manager_host + ":" + manager_port);

    std::string cmd =
        "netsh advfirewall firewall delete rule name=LARP_BLOCK_OUT >nul 2>&1 & "
        "netsh advfirewall firewall delete rule name=LARP_ALLOW_MANAGER >nul 2>&1 & "
        "netsh advfirewall firewall add rule name=LARP_BLOCK_OUT dir=out action=block "
        "enable=yes profile=any & "
        "netsh advfirewall firewall add rule name=LARP_ALLOW_MANAGER dir=out action=allow "
        "remoteip=" + manager_host + " enable=yes profile=any";

    int rc = system(cmd.c_str());
    if (rc != 0) {
        return {"failed", "netsh isolate returned code " + std::to_string(rc)};
    }
    return {"success", "Host isolated (manager=" + manager_host + " whitelisted)"};
}

CommandResult HandleUnisolate() {
    std::string cmd =
        "netsh advfirewall firewall delete rule name=LARP_BLOCK_OUT >nul 2>&1 & "
        "netsh advfirewall firewall delete rule name=LARP_ALLOW_MANAGER >nul 2>&1";
    int rc = system(cmd.c_str());
    // rc sẽ khác 0 nếu rule không tồn tại, nhưng coi như success vì đích đã đạt
    return {"success", "Host unisolated"};
}

// FIX B4/B5: Proper command dispatch với try/catch
CommandResult ExecuteCommand(const std::string& action, const std::string& payload_json) {
    try {
        if (action == "isolate" || action == "auto_isolate") {
            return HandleIsolate();
        }
        if (action == "unisolate") {
            return HandleUnisolate();
        }
        if (action == "kill_process" || action == "kill_process_tree") {
            bool tree = (action == "kill_process_tree");
            // Extract pid from payload
            std::string pid_str;
            auto pos = payload_json.find("\"pid\":");
            if (pos != std::string::npos) {
                pos += 6;
                while (pos < payload_json.size() && isspace((unsigned char)payload_json[pos])) pos++;
                while (pos < payload_json.size() && isdigit((unsigned char)payload_json[pos])) {
                    pid_str += payload_json[pos++];
                }
            }
            if (pid_str.empty()) return {"failed", "missing 'pid' param"};
            DWORD pid = 0;
            try {
                pid = (DWORD)std::stoul(pid_str);
            } catch (...) {
                return {"failed", "invalid pid: " + pid_str};
            }
            return HandleKillProcess(pid, tree);
        }
        return {"failed", "No handler for action '" + action + "'"};
    } catch (const std::exception& e) {
        return {"failed", std::string("Exception: ") + e.what()};
    } catch (...) {
        return {"failed", "Unknown exception in handler"};
    }
}

// ============ WS CLIENT ============
class WSClient {
public:
    HINTERNET m_session = nullptr, m_connect = nullptr, m_ws = nullptr;
    std::string m_host, m_path;
    int m_port = 443;
    bool m_secure = true;

    bool ParseUrl(const std::string& url) {
        if (url.rfind("wss://", 0) == 0) { m_secure = true; m_host = url.substr(6); }
        else if (url.rfind("ws://", 0) == 0) { m_secure = false; m_host = url.substr(5); }
        else return false;
        auto slash = m_host.find('/');
        if (slash != std::string::npos) {
            m_path = m_host.substr(slash);
            m_host = m_host.substr(0, slash);
        } else m_path = "/";
        auto colon = m_host.find(':');
        if (colon != std::string::npos) {
            m_port = std::stoi(m_host.substr(colon + 1));
            m_host = m_host.substr(0, colon);
        } else {
            m_port = m_secure ? 443 : 80;
        }
        return true;
    }

    bool Connect(const std::string& url) {
        if (!ParseUrl(url)) return false;
        std::wstring whost(m_host.begin(), m_host.end());
        std::wstring wpath(m_path.begin(), m_path.end());
        m_session = WinHttpOpen(L"LARP-Agent/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!m_session) return false;
        m_connect = WinHttpConnect(m_session, whost.c_str(), (INTERNET_PORT)m_port, 0);
        if (!m_connect) return false;
        HINTERNET req = WinHttpOpenRequest(m_connect, L"GET", wpath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            m_secure ? WINHTTP_FLAG_SECURE : 0);
        if (!req) return false;
        if (!WinHttpSetOption(req, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
            WinHttpCloseHandle(req); return false;
        }
        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpCloseHandle(req); return false;
        }
        if (!WinHttpReceiveResponse(req, nullptr)) { WinHttpCloseHandle(req); return false; }
        m_ws = WinHttpWebSocketCompleteUpgrade(req, 0);
        WinHttpCloseHandle(req);
        return m_ws != nullptr;
    }

    bool Send(const std::string& msg) {
        if (!m_ws) return false;
        DWORD err = WinHttpWebSocketSend(m_ws, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                     (PVOID)msg.c_str(), (DWORD)msg.size());
        return err == ERROR_SUCCESS;
    }

    bool Receive(std::string& out, DWORD timeout_ms = 5000) {
        if (!m_ws) return false;
        std::vector<char> buf(65536);
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        DWORD start = GetTickCount();
        // Poll with small sleeps (WinHTTP doesn't have direct timeout for Receive)
        while (GetTickCount() - start < timeout_ms) {
            DWORD err = WinHttpWebSocketReceive(m_ws, buf.data(), (DWORD)buf.size(),
                                                &bytesRead, &type);
            if (err == ERROR_SUCCESS) {
                if (bytesRead > 0) out.assign(buf.data(), bytesRead);
                else out.clear();
                return true;
            }
            if (err == ERROR_WINHTTP_TIMEOUT) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
            return false;  // other error → connection broken
        }
        return false;  // timeout
    }

    void Close() {
        if (m_ws) { WinHttpWebSocketClose(m_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
                    WinHttpCloseHandle(m_ws); m_ws = nullptr; }
        if (m_connect) { WinHttpCloseHandle(m_connect); m_connect = nullptr; }
        if (m_session) { WinHttpCloseHandle(m_session); m_session = nullptr; }
    }

    ~WSClient() { Close(); }
};


// ============ JSON BUILDERS ============
std::string BuildHeartbeat() {
    std::ostringstream ss;
    ss << "{\"type\":\"HEARTBEAT\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(g_agent_id) << "\","
       << "\"hostname\":\"" << EscapeJson(g_hostname) << "\","
       << "\"platform\":\"windows\","
       << "\"ip_address\":\"" << EscapeJson(g_ip) << "\","
       << "\"mac_address\":\"" << EscapeJson(g_mac) << "\"}}";
    return ss.str();
}

std::string BuildProcessList(const std::vector<ProcessInfo>& procs) {
    std::ostringstream ss;
    ss << "{\"type\":\"PROCESS_LIST\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(g_agent_id) << "\","
       << "\"processes\":[";
    for (size_t i = 0; i < procs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"pid\":" << procs[i].pid
           << ",\"ppid\":" << procs[i].ppid
           << ",\"name\":\"" << EscapeJson(procs[i].name) << "\""
           << ",\"exe\":\"" << EscapeJson(procs[i].exe) << "\""
           << ",\"cmdline\":\"" << EscapeJson(procs[i].cmdline) << "\""
           << ",\"is_suspicious\":false}";
    }
    ss << "],\"timestamp\":" << time(nullptr) << "}}";
    return ss.str();
}

std::string BuildTelemetry(const std::vector<ProcessInfo>& procs,
                           const std::vector<NetConn>& conns) {
    std::ostringstream ss;
    ss << "{\"type\":\"TELEMETRY_RISK\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(g_agent_id) << "\","
       << "\"platform\":\"windows\",\"process_list\":[";
    for (size_t i = 0; i < procs.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"pid\":" << procs[i].pid << ",\"ppid\":" << procs[i].ppid
           << ",\"name\":\"" << EscapeJson(procs[i].name) << "\""
           << ",\"exe\":\"" << EscapeJson(procs[i].exe) << "\""
           << ",\"cmdline\":\"" << EscapeJson(procs[i].cmdline) << "\"}";
    }
    ss << "],\"network_connections\":[";
    for (size_t i = 0; i < conns.size(); i++) {
        if (i > 0) ss << ",";
        ss << "{\"pid\":" << conns[i].pid
           << ",\"process_name\":\"" << EscapeJson(conns[i].process_name) << "\""
           << ",\"src_ip\":\"" << EscapeJson(conns[i].src_ip) << "\""
           << ",\"src_port\":" << conns[i].src_port
           << ",\"dst_ip\":\"" << EscapeJson(conns[i].dst_ip) << "\""
           << ",\"dst_port\":" << conns[i].dst_port
           << ",\"protocol\":\"" << EscapeJson(conns[i].protocol) << "\"}";
    }
    ss << "],\"timestamp\":" << time(nullptr) << "}}";
    return ss.str();
}

std::string BuildAck(const std::string& command_id, const CommandResult& res) {
    std::ostringstream ss;
    ss << "{\"type\":\"COMMAND_ACK\",\"payload\":{"
       << "\"command_id\":\"" << EscapeJson(command_id) << "\","
       << "\"status\":\"" << EscapeJson(res.status) << "\","
       << "\"executed_at\":" << time(nullptr);
    if (!res.error_message.empty()) {
        ss << ",\"error_message\":\"" << EscapeJson(res.error_message) << "\"";
    }
    ss << "}}";
    return ss.str();
}

// ============ PROCESS PENDING COMMANDS (FIX B1 + B2) ============
void ProcessPendingCommands(WSClient* ws, const std::string& heartbeat_response) {
    // Parse: {"status":"ack","pending_commands":[{...}]}
    std::string arr = JsonGetArrayRaw(heartbeat_response, "pending_commands");
    if (arr.empty()) return;

    auto cmds = SplitJsonObjects(arr);
    if (cmds.empty()) return;
    Log("[*] Received " + std::to_string(cmds.size()) + " pending command(s)");

    for (auto& cmd_json : cmds) {
        std::string cmd_id = JsonGetString(cmd_json, "command_id");
        std::string action = JsonGetString(cmd_json, "action");
        // payload có thể là object — extract raw
        std::string payload_raw;
        auto payload_pos = cmd_json.find("\"payload\":");
        if (payload_pos != std::string::npos) {
            payload_pos += 10;
            while (payload_pos < cmd_json.size() && isspace((unsigned char)cmd_json[payload_pos])) payload_pos++;
            if (payload_pos < cmd_json.size() && cmd_json[payload_pos] == '{') {
                int depth = 0;
                bool in_str = false, escape = false;
                size_t start = payload_pos;
                for (size_t i = payload_pos; i < cmd_json.size(); i++) {
                    char c = cmd_json[i];
                    if (in_str) {
                        if (escape) escape = false;
                        else if (c == '\\') escape = true;
                        else if (c == '"') in_str = false;
                    } else {
                        if (c == '"') in_str = true;
                        else if (c == '{') depth++;
                        else if (c == '}') { depth--; if (depth == 0) { payload_raw = cmd_json.substr(start, i - start + 1); break; } }
                    }
                }
            }
        }
        if (cmd_id.empty() || action.empty()) {
            Log("[!] Skipping malformed command: id='" + cmd_id + "' action='" + action + "'");
            continue;
        }

        Log("[*] Executing command " + cmd_id + ": " + action);

        // Execute handler
        CommandResult res = ExecuteCommand(action, payload_raw);

        // Send ACK (FIX B2)
        std::string ack = BuildAck(cmd_id, res);
        {
            std::lock_guard<std::mutex> lock(g_ws_send_mutex);
            bool ok = ws->Send(ack);
            Log("[*] Sent ACK for " + cmd_id + ": " + res.status +
                (ok ? "" : " (SEND FAILED)") +
                (res.error_message.empty() ? "" : " — " + res.error_message));
        }
    }
}

// ============ SENDER LOOP (FIX B1: synchronous HB + process pending) ============
void SenderLoop() {
    Log("[*] SenderLoop started");
    while (true) {
        if (!g_connected.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        WSClient* ws = g_ws;   // snapshot
        if (!ws) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        // --- Step 1: Send HEARTBEAT ---
        {
            std::lock_guard<std::mutex> lock(g_ws_send_mutex);
            if (!ws->Send(BuildHeartbeat())) {
                Log("[!] Failed to send heartbeat");
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }

        // --- Step 2: Wait for heartbeat response (FIX B7: use recv mutex) ---
        std::string hb_response;
        bool got_response = false;
        {
            std::lock_guard<std::mutex> lock(g_ws_recv_mutex);
            got_response = ws->Receive(hb_response, 5000);
        }
        if (got_response && !hb_response.empty()) {
            g_last_message.store(time(nullptr));
            Log("[*] HB response: " + hb_response.substr(0, 200));

            // --- Step 3: Parse & execute pending commands (FIX B1 + B2) ---
            ProcessPendingCommands(ws, hb_response);
        } else {
            Log("[!] No heartbeat response within 5s");
        }

        // --- Step 4: Send PROCESS_LIST + TELEMETRY (fire and forget) ---
        std::vector<ProcessInfo> procs = CollectProcesses();
        std::vector<NetConn> conns = CollectNetwork();
        {
            std::lock_guard<std::mutex> lock(g_ws_send_mutex);
            ws->Send(BuildProcessList(procs));
            ws->Send(BuildTelemetry(procs, conns));
        }
        Log("[+] Sent HB + PROCESS_LIST (" + std::to_string(procs.size()) +
            ") + telemetry (" + std::to_string(conns.size()) + " conns)");

        // --- Sleep for interval ---
        std::this_thread::sleep_for(std::chrono::seconds(g_interval));
    }
}

// ============ RECEIVER LOOP — REMOVED (moved into SenderLoop) ============
// ReceiverLoop cũ bị xóa vì gây race condition với SenderLoop.
// Tất cả command giờ được xử lý trong SenderLoop sau heartbeat response.

// ============ WATCHDOG ============
void WatchdogLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_connected.load()) continue;
        time_t last = g_last_message.load();
        if (last > 0 && (time(nullptr) - last) > 90) {
            Log("[!] WATCHDOG: No response from Manager in 90s — forcing reconnect");
            std::lock_guard<std::mutex> lock(g_ws_mutex);
            if (g_ws) g_ws->Close();
            g_connected.store(false);
        }
    }
}

// ============ MAIN ============
int main() {
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        printf("[!] WSAStartup failed: %d\n", wsaResult);
        return 1;
    }

    g_agent_id = LoadOrCreateAgentId();
    g_hostname = GetHostname();
    g_ip = GetLocalIP();
    g_mac = GetMacAddress();

    g_manager_url = GetEnv("MANAGER_URL");
    if (g_manager_url.empty()) g_manager_url = "wss://edr.alwayready.id.vn/ws/agent";

    std::string interval_str = GetEnv("AGENT_INTERVAL");
    if (!interval_str.empty()) g_interval = std::atoi(interval_str.c_str());

    Log("=== LARP Agent C++ (fixed) ===");
    Log("Agent ID: " + g_agent_id);
    Log("Hostname: " + g_hostname);
    Log("IP:       " + g_ip);
    Log("MAC:      " + g_mac);
    Log("Manager:  " + g_manager_url);
    Log("Interval: " + std::to_string(g_interval) + "s");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        g_NtQueryInformationProcess = (NtQueryInformationProcess_t)
            GetProcAddress(ntdll, "NtQueryInformationProcess");
    }

    std::thread(SenderLoop).detach();
    std::thread(WatchdogLoop).detach();

    int retry = 1;
    while (true) {
        Log("[*] Connecting to " + g_manager_url + " ...");
        auto* ws = new WSClient();

        if (!ws->Connect(g_manager_url)) {
            Log("[!] Connect failed");
            delete ws;
            std::this_thread::sleep_for(std::chrono::seconds(retry));
            retry = std::min(retry * 2, 30);
            continue;
        }
        Log("[+] Connected");

        {
            std::lock_guard<std::mutex> lock(g_ws_mutex);
            g_ws = ws;
            g_connected.store(true);
            g_last_message.store(time(nullptr));
        }
        retry = 1;

        while (g_connected.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        {
            std::lock_guard<std::mutex> lock(g_ws_mutex);
            g_ws = nullptr;
        }
        ws->Close();
        delete ws;
        Log("[!] Disconnected");

        std::this_thread::sleep_for(std::chrono::seconds(retry));
        retry = std::min(retry * 2, 30);
    }
    return 0;
}