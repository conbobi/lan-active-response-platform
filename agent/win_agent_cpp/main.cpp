// ============================================================================
// HEADER ORDER — QUAN TRỌNG: KHÔNG ĐƯỢC ĐẢO THỨ TỰ
// ============================================================================

// 1. Define _WIN32_WINNT TRƯỚC windows.h (bắt buộc cho GetAdaptersAddresses, WebSocket)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602   // Windows 8+
#endif

#ifndef WINVER
#define WINVER 0x0602
#endif

// 2. Winsock2 phải TRƯỚC windows.h (tránh conflict winsock1 vs winsock2)
#include <winsock2.h>
#include <ws2tcpip.h>   // ← Cần cho inet_ntop, INET_ADDRSTRLEN, sockaddr_in

// 3. Windows headers
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>   // GetAdaptersAddresses, GetExtendedTcpTable
#include <tlhelp32.h>   // CreateToolhelp32Snapshot
#include <winternl.h>   // ← Cần cho UNICODE_STRING

// 4. C++ stdlib
#include <algorithm>    // std::min
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

// 5. Link libraries (chỉ áp dụng cho MSVC, MinGW dùng -l flags)
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}
// Helper: portable env var (thay _dupenv_s cho MinGW)
std::string GetEnv(const char* name) {
    const char* val = std::getenv(name);
    return val ? std::string(val) : std::string();
}
// ============ MACHINE INFO (personalization) ============
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
    ULONG family = AF_INET;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES addrs = nullptr;
    DWORD ret = ERROR_BUFFER_OVERFLOW;
    
    // Retry với buffer lớn hơn nếu overflow
    for (int attempt = 0; attempt < 3; attempt++) {
        if (addrs) free(addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!addrs) return "127.0.0.1";
        ret = GetAdaptersAddresses(family, flags, nullptr, addrs, &outBufLen);
        if (ret == NO_ERROR) break;
        if (ret != ERROR_BUFFER_OVERFLOW) {
            Log("[!] GetAdaptersAddresses error: " + std::to_string(ret));
            free(addrs);
            return "127.0.0.1";
        }
    }
    if (ret != NO_ERROR || !addrs) { if (addrs) free(addrs); return "127.0.0.1"; }
    
    std::string best_wired, best_wifi, best_other;
    for (auto a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        
        Log("[*] Adapter: " + WStringToUTF8(a->FriendlyName) + 
            " IfType=" + std::to_string(a->IfType));
        
        for (auto u = a->FirstUnicastAddress; u; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((sockaddr_in*)u->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
            std::string s = ip;
            Log("[*]   IPv4: " + s);
            if (s.rfind("169.254.", 0) == 0 || s == "127.0.0.1") continue;
            if (a->IfType == IF_TYPE_ETHERNET_CSMACD && best_wired.empty()) best_wired = s;
            else if (a->IfType == IF_TYPE_IEEE80211 && best_wifi.empty()) best_wifi = s;
            else if (best_other.empty()) best_other = s;
        }
    }
    free(addrs);
    if (!best_wired.empty()) return best_wired;
    if (!best_wifi.empty()) return best_wifi;
    if (!best_other.empty()) return best_other;
    return "127.0.0.1";
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
        // Skip MAC có first byte = 0 (rác)
        // Chỉ skip nếu TẤT CẢ 6 bytes = 0 (invalid MAC)
        bool all_zero = true;
        for (int i = 0; i < 6; i++) {
            if (a->PhysicalAddress[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) continue;
        
        char buf[32];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->PhysicalAddress[0], a->PhysicalAddress[1], a->PhysicalAddress[2],
                 a->PhysicalAddress[3], a->PhysicalAddress[4], a->PhysicalAddress[5]);
        result = buf;
        Log("[+] MAC: " + result + " from " + WStringToUTF8(a->FriendlyName));
        break;
    }
    free(addrs);
    return result;
}



// Personalization: 4-layer ID resolution
std::string LoadOrCreateAgentId() {
    std::string env_id = GetEnv("AGENT_ID");
    if (!env_id.empty()) { Log("[*] AGENT_ID from ENV: " + env_id); return env_id; }
    
    std::string config_dir = "C:\\ProgramData\\LARP";
    std::string config_file = config_dir + "\\agent_id.txt";
    CreateDirectoryA(config_dir.c_str(), nullptr);
    
    std::ifstream f(config_file);
    if (f.is_open()) {
        std::string id; std::getline(f, id); f.close();
        if (!id.empty()) { Log("[*] AGENT_ID from file: " + id); return id; }
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
    out << id << std::endl; out.close();
    Log("[+] Generated new AGENT_ID: " + id);
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
    
    // SAFETY: Buffer phải nằm trong buf để tránh crash
    BYTE* buf_start = buf.data();
    BYTE* buf_end = buf.data() + buf.size();
    BYTE* us_buf = (BYTE*)us->Buffer;
    if (us_buf < buf_start || us_buf + us->Length > buf_end) {
        return "";  // Invalid pointer — reject
    }
    
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
                if (QueryFullProcessImageNameW(hProc, 0, path, &pathLen)) {
                    pi.exe = WStringToUTF8(path);
                }
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

// ============ JSON BUILDERS ============
std::string BuildHeartbeat(const std::string& agent_id, const std::string& hostname,
                           const std::string& ip, const std::string& mac) {
    std::ostringstream ss;
    ss << "{\"type\":\"HEARTBEAT\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(agent_id) << "\","
       << "\"hostname\":\"" << EscapeJson(hostname) << "\","
       << "\"platform\":\"windows\","
       << "\"ip_address\":\"" << EscapeJson(ip) << "\","
       << "\"mac_address\":\"" << EscapeJson(mac) << "\"}}";
    return ss.str();
}

std::string BuildProcessList(const std::string& agent_id,
                              const std::vector<ProcessInfo>& procs) {
    std::ostringstream ss;
    ss << "{\"type\":\"PROCESS_LIST\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(agent_id) << "\","
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

std::string BuildTelemetry(const std::string& agent_id,
                           const std::vector<ProcessInfo>& procs,
                           const std::vector<NetConn>& conns) {
    std::ostringstream ss;
    ss << "{\"type\":\"TELEMETRY_RISK\",\"payload\":{"
       << "\"agent_id\":\"" << EscapeJson(agent_id) << "\","
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

// ============ COMMAND HANDLERS ============
std::string HandleKillProcess(DWORD pid, bool tree) {
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
        if (exitCode == 0) return "{\"status\":\"success\"}";
    }
    return "{\"status\":\"error\",\"message\":\"taskkill failed\"}";
}

std::string HandleIsolate(const std::string& manager_ip, int manager_port) {
    std::string cmd =
        "netsh advfirewall firewall delete rule name=LARP_ALLOW_MGR_OUT & "
        "netsh advfirewall firewall delete rule name=LARP_ALLOW_MGR_IN & "
        "netsh advfirewall firewall add rule name=LARP_ALLOW_MGR_OUT dir=out action=allow "
        "remoteip=" + manager_ip + " remoteport=" + std::to_string(manager_port) +
        " protocol=TCP & "
        "netsh advfirewall firewall add rule name=LARP_ALLOW_MGR_IN dir=in action=allow "
        "remoteip=" + manager_ip + " protocol=TCP & "
        "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound";
    system(cmd.c_str());
    return "{\"status\":\"success\"}";
}

std::string HandleUnisolate() {
    system("netsh advfirewall firewall delete rule name=LARP_ALLOW_MGR_OUT & "
           "netsh advfirewall firewall delete rule name=LARP_ALLOW_MGR_IN & "
           "netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound");
    return "{\"status\":\"success\"}";
}

// ============ WINHTTP WEBSOCKET ============
class WSClient {
public:
    HINTERNET m_session = nullptr, m_connect = nullptr, m_ws = nullptr;
    std::string m_host, m_path;
    int m_port = 443;
    bool m_secure = true;
    
    bool ParseUrl(const std::string& url) {
        // wss://host/path hoặc ws://host/path
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
    
    // Receive with timeout (ms). Returns true if got message.
    bool Receive(std::string& out, DWORD timeout_ms = 5000) {
        if (!m_ws) return false;
        WinHttpSetOption(m_ws, WINHTTP_OPTION_WEB_SOCKET_CLOSE_TIMEOUT,
                         &timeout_ms, sizeof(timeout_ms));
        
        std::vector<char> buf(65536);
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type;
        DWORD err = WinHttpWebSocketReceive(m_ws, buf.data(), (DWORD)buf.size(),
                                            &bytesRead, &type);
        if (err != ERROR_SUCCESS) return false;
        if (bytesRead > 0) {
            out.assign(buf.data(), bytesRead);
            return true;
        }
        return false;
    }
    
    void Close() {
        if (m_ws) { WinHttpWebSocketClose(m_ws, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
                    WinHttpCloseHandle(m_ws); m_ws = nullptr; }
        if (m_connect) { WinHttpCloseHandle(m_connect); m_connect = nullptr; }
        if (m_session) { WinHttpCloseHandle(m_session); m_session = nullptr; }
    }
    
    ~WSClient() { Close(); }
};

// ============ GLOBAL STATE ============
std::string g_agent_id, g_hostname, g_ip, g_mac, g_manager_url;
int g_interval = 15;
std::atomic<bool> g_connected{false};
std::atomic<time_t> g_last_message{0};
WSClient* g_ws = nullptr;
std::mutex g_ws_mutex;

// ============ SENDER THREAD ============
void SenderLoop() {
    Log("[*] SenderLoop started");
    while (true) {
        if (!g_connected.load()) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
        
        std::vector<ProcessInfo> procs;
        std::vector<NetConn> conns;
        
        try { procs = CollectProcesses(); } 
        catch (...) { std::this_thread::sleep_for(std::chrono::seconds(2)); continue; }
        
        try { conns = CollectNetwork(); } 
        catch (...) { conns.clear(); }
        
        Log("[*] Sending HB + PL + TL...");
        
        // ⚠️ KHÔNG lock mutex khi Send
        WSClient* ws = g_ws;   // Copy pointer
        if (ws) {
            bool ok1 = ws->Send(BuildHeartbeat(g_agent_id, g_hostname, g_ip, g_mac));
            Log("[*] HB sent: " + std::string(ok1?"OK":"FAIL"));
            bool ok2 = ws->Send(BuildProcessList(g_agent_id, procs));
            Log("[*] PL sent: " + std::string(ok2?"OK":"FAIL"));
            bool ok3 = ws->Send(BuildTelemetry(g_agent_id, procs, conns));
            Log("[*] TL sent: " + std::string(ok3?"OK":"FAIL"));
            
            if (ok1 && ok2 && ok3) {
                Log("[+] Sent HB + PROCESS_LIST (" + std::to_string(procs.size()) +
                    ") + telemetry (" + std::to_string(conns.size()) + " conns)");
            }
        } else {
            Log("[!] g_ws null");
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(g_interval));
    }
}



// ============ RECEIVER THREAD ============
void ReceiverLoop() {
    Log("[*] ReceiverLoop started");
    while (true) {
        if (!g_connected.load()) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
        
        WSClient* ws = g_ws;   // Copy pointer
        if (!ws) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
        
        std::string msg;
        bool got = ws->Receive(msg, 5000);   // ⚠️ KHÔNG lock
        
        if (got && !msg.empty()) {
            g_last_message.store(time(nullptr));
            Log("[*] Received: " + msg.substr(0, 200));
            
            // Parse command
            auto pos = msg.find("\"kill_process");
            if (pos != std::string::npos) {
                auto pid_pos = msg.find("\"pid\":");
                if (pid_pos != std::string::npos) {
                    DWORD pid = std::stoul(msg.substr(pid_pos + 6));
                    bool tree = msg.find("kill_process_tree") != std::string::npos;
                    Log("[*] Executing kill PID " + std::to_string(pid) + (tree ? " (tree)" : ""));
                    HandleKillProcess(pid, tree);
                }
            }
            
            // Isolate command
            if (msg.find("\"isolate\"") != std::string::npos) {
                Log("[*] Executing isolate");
                HandleIsolate("edr.alwayready.id.vn", 443);
            }
        }
    }
}

// ============ WATCHDOG ============
void WatchdogLoop() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_connected.load()) continue;
        time_t last = g_last_message.load();
        if (last > 0 && (time(nullptr) - last) > 90) {
            Log("[!] WATCHDOG: No message from Manager in 90s — forcing reconnect");
            std::lock_guard<std::mutex> lock(g_ws_mutex);
            if (g_ws) g_ws->Close();
            g_connected.store(false);
        }
    }
}

// ============ MAIN ============
int main() {
    // 1. Init Winsock
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        printf("[!] WSAStartup failed: %d\n", wsaResult);
        return 1;
    }
    
    // 2. Personalization
    g_agent_id = LoadOrCreateAgentId();
    g_hostname = GetHostname();
    g_ip = GetLocalIP();
    g_mac = GetMacAddress();
    
    g_manager_url = GetEnv("MANAGER_URL");
    if (g_manager_url.empty()) g_manager_url = "wss://edr.alwayready.id.vn/ws/agent";
    
    std::string interval_str = GetEnv("AGENT_INTERVAL");
    if (!interval_str.empty()) g_interval = std::atoi(interval_str.c_str());
    
    Log("=== LARP Agent C++ ===");
    Log("Agent ID: " + g_agent_id);
    Log("Hostname: " + g_hostname);
    Log("IP:       " + g_ip);
    Log("MAC:      " + g_mac);
    Log("Manager:  " + g_manager_url);
    Log("Interval: " + std::to_string(g_interval) + "s");
    
    // 3. Load NtQueryInformationProcess
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        g_NtQueryInformationProcess = (NtQueryInformationProcess_t)
            GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
    
    // 4. Start background threads
    std::thread(SenderLoop).detach();
    std::thread(ReceiverLoop).detach();
    std::thread(WatchdogLoop).detach();
    
    // 5. Reconnect loop (main thread)
    int retry = 1;
    while (true) {
        Log("[*] Connecting to " + g_manager_url + " ...");
        auto* ws = new WSClient();
        
        if (!ws->Connect(g_manager_url)) {
            Log("[!] Connect failed");
            delete ws;
            Log("[*] Reconnect in " + std::to_string(retry) + "s...");
            std::this_thread::sleep_for(std::chrono::seconds(retry));
            retry = std::min(retry * 2, 30);
            continue;
        }
        
        Log("[+] Connected");
        
        // Test send
        std::string test_hb = BuildHeartbeat(g_agent_id, g_hostname, g_ip, g_mac);
        bool test_ok = ws->Send(test_hb);
        Log("[*] Test send size=" + std::to_string(test_hb.size()) + 
            " result=" + std::string(test_ok?"OK":"FAIL"));
        
        {
            std::lock_guard<std::mutex> lock(g_ws_mutex);
            g_ws = ws;
            g_connected.store(true);
            g_last_message.store(time(nullptr));
        }
        retry = 1;
        
        // Wait until disconnected
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
        
        Log("[*] Reconnect in " + std::to_string(retry) + "s...");
        std::this_thread::sleep_for(std::chrono::seconds(retry));
        retry = std::min(retry * 2, 30);
    }
    return 0;
}
