// network.cpp — полный файл с исправленной валидацией маски подсети
#include "network.h"
#include "upnp_simple.h"
#include <vector>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <stack>
#include <unordered_map>
#include <sstream>
#include <objbase.h>
#include <cctype>
#include <bitset> // добавлено для подсчёта единиц в маске

WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = nullptr;
WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;
WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;

// Globals
std::atomic<uint32_t> g_MaxClients(0); // 0 = no configured client limit
std::atomic<bool> g_TunnelActive(false);
std::mutex g_ClientsMutex;
std::vector<SOCKET> g_ServerClients;
std::vector<std::thread> g_ClientThreads;
SOCKET g_ListenSocket = INVALID_SOCKET;
SOCKET g_ClientActiveSocket = INVALID_SOCKET;
HANDLE g_WintunAdapter = nullptr;
HANDLE g_WintunSession = nullptr;
HWND hLogZone = nullptr;
std::atomic<bool> g_UseUPnP(false);
std::atomic<uint16_t> g_CurrentServerPort(0);

// Custom subnet globals
std::atomic<bool> g_UseCustomSubnetMask(false);
std::string g_CustomSubnetMask;
std::mutex g_CustomMaskMutex;

// Address pool structures
static std::mutex g_ipMutex;
static uint32_t g_nextIpId = 2; // reserve id=1 for server (10.8.0.1)
static std::stack<uint32_t> g_freeIpIds; // reuse on disconnect
static std::unordered_map<uint32_t, SOCKET> g_IpToSocketMap; // host-order ip -> socket

// Simple XOR key (placeholder)
static const uint8_t ENCRYPTION_KEY = 'X';

namespace Encryption {
    void Init() { /* no-op */ }
    void Encrypt(uint8_t* buf, uint32_t size) {
        for (uint32_t i = 0; i < size; ++i) buf[i] ^= ENCRYPTION_KEY;
    }
    void Decrypt(uint8_t* buf, uint32_t size) {
        Encrypt(buf, size);
    }
}

// Helper utilities (Safe recv/send, IP helpers)

bool SafeRecvFully(SOCKET sock, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    int total = 0;
    while (total < len) {
        int r = recv(sock, p + total, len - total, 0);
        if (r == 0) return false; // closed
        if (r == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINTR) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
            return false;
        }
        total += r;
    }
    return true;
}

bool SafeSendFully(SOCKET sock, const void* buf, int len) {
    const char* p = static_cast<const char*>(buf);
    int total = 0;
    while (total < len) {
        int s = send(sock, p + total, len - total, 0);
        if (s == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAEINTR) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
            return false;
        }
        if (s == 0) return false;
        total += s;
    }
    return true;
}

std::string IPv4ToString(uint32_t ipHostOrder) {
    uint8_t a = static_cast<uint8_t>((ipHostOrder >> 24) & 0xFF);
    uint8_t b = static_cast<uint8_t>((ipHostOrder >> 16) & 0xFF);
    uint8_t c = static_cast<uint8_t>((ipHostOrder >> 8) & 0xFF);
    uint8_t d = static_cast<uint8_t>(ipHostOrder & 0xFF);
    char buf[32];
    sprintf_s(buf, "%u.%u.%u.%u", a, b, c, d);
    return std::string(buf);
}

static uint32_t makeIpFromId(uint32_t id) {
    uint8_t a = ADDRESS_PREFIX_A;
    uint8_t b = ADDRESS_PREFIX_B;
    uint8_t c = static_cast<uint8_t>((id >> 8) & 0xFF);
    uint8_t d = static_cast<uint8_t>(id & 0xFF);
    uint32_t ip = (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(b) << 16) | (static_cast<uint32_t>(c) << 8) | (static_cast<uint32_t>(d));
    return ip;
}

uint32_t AllocateClientIP() {
    std::lock_guard<std::mutex> lock(g_ipMutex);
    if (!g_freeIpIds.empty()) {
        uint32_t id = g_freeIpIds.top(); g_freeIpIds.pop();
        return makeIpFromId(id);
    }
    if (g_nextIpId == 0 || g_nextIpId >= ADDRESS_POOL_SIZE) {
        return 0;
    }
    uint32_t id = g_nextIpId++;
    return makeIpFromId(id);
}

void ReleaseClientIP(uint32_t ipHostOrder) {
    std::lock_guard<std::mutex> lock(g_ipMutex);
    uint8_t c = static_cast<uint8_t>((ipHostOrder >> 8) & 0xFF);
    uint8_t d = static_cast<uint8_t>(ipHostOrder & 0xFF);
    uint32_t id = (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
    if (id >= 2 && id < ADDRESS_POOL_SIZE) {
        g_freeIpIds.push(id);
    }
}

// Logging helper
void LogMessage(const std::wstring& msg) {
    if (!hLogZone) {
        // fallback to OutputDebugString
        OutputDebugStringW((msg + L"\r\n").c_str());
        return;
    }
    std::wstring dynamicMsg = msg + L"\r\n";
    int len = GetWindowTextLengthW(hLogZone);
    SendMessageW(hLogZone, EM_SETSEL, len, len);
    SendMessageW(hLogZone, EM_REPLACESEL, 0, (LPARAM)dynamicMsg.c_str());
}

// Wintun loader
bool InitializeWintunDLL() {
    HMODULE wintunLib = LoadLibraryW(L"wintun.dll");
    if (!wintunLib) return false;
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(wintunLib, "WintunCreateAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(wintunLib, "WintunStartSession");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(wintunLib, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(wintunLib, "WintunSendPacket");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(wintunLib, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(wintunLib, "WintunReleaseReceivePacket");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC)GetProcAddress(wintunLib, "WintunCloseAdapter");
    return (WintunCreateAdapter && WintunStartSession && WintunAllocateSendPacket && WintunSendPacket && WintunReceivePacket && WintunReleaseReceivePacket && WintunCloseAdapter);
}

// Encryption send helper
static void EncryptAndSend(SOCKET sock, const uint8_t* data, uint32_t size) {
    if (sock == INVALID_SOCKET) return;
    if (size == 0 || size > MAX_PACKET_SIZE) return;
    std::vector<uint8_t> tmp(data, data + size);
    Encryption::Encrypt(tmp.data(), size);
    uint32_t netSize = htonl(size);
    if (!SafeSendFully(sock, &netSize, sizeof(netSize))) return;
    SafeSendFully(sock, tmp.data(), static_cast<int>(size));
}

// Server runners (Wintun->network)
void ServerOsToNetworkWorker() {
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (!packetData || packetSize == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        if (packetSize > MAX_PACKET_SIZE) { WintunReleaseReceivePacket(g_WintunSession, packetData); continue; }

        if (packetSize >= 20) {
            uint32_t destNet = 0;
            memcpy(&destNet, packetData + 16, sizeof(destNet));
            uint32_t destHost = ntohl(destNet);

            SOCKET target = INVALID_SOCKET;
            {
                std::lock_guard<std::mutex> lock(g_ipMutex);
                auto it = g_IpToSocketMap.find(destHost);
                if (it != g_IpToSocketMap.end()) target = it->second;
            }
            if (target != INVALID_SOCKET) {
                EncryptAndSend(target, packetData, packetSize);
            }
            else {
                std::lock_guard<std::mutex> lock(g_ClientsMutex);
                for (SOCKET s : g_ServerClients) EncryptAndSend(s, packetData, packetSize);
            }
        }
        else {
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            for (SOCKET s : g_ServerClients) EncryptAndSend(s, packetData, packetSize);
        }

        WintunReleaseReceivePacket(g_WintunSession, packetData);
    }
}

// Client OS -> network
void ClientOsToNetworkWorker() {
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (!packetData || packetSize == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        if (packetSize > MAX_PACKET_SIZE) { WintunReleaseReceivePacket(g_WintunSession, packetData); continue; }

        if (g_ClientActiveSocket != INVALID_SOCKET) {
            EncryptAndSend(g_ClientActiveSocket, packetData, packetSize);
        }
        WintunReleaseReceivePacket(g_WintunSession, packetData);
    }
}

// Per-client worker
void ServerSingleClientWorker(SOCKET clientSock) {
    SOCKET sock = clientSock;
    uint32_t assignedIp = 0;
    {
        std::lock_guard<std::mutex> lock(g_ipMutex);
        for (auto& p : g_IpToSocketMap) {
            if (p.second == sock) { assignedIp = p.first; break; }
        }
    }

    while (g_TunnelActive) {
        uint32_t netSize = 0;
        if (!SafeRecvFully(sock, &netSize, sizeof(netSize))) break;
        uint32_t packetSize = ntohl(netSize);
        if (packetSize == 0 || packetSize > MAX_PACKET_SIZE) break;

        std::vector<uint8_t> buffer(packetSize);
        if (!SafeRecvFully(sock, buffer.data(), static_cast<int>(packetSize))) break;
        Encryption::Decrypt(buffer.data(), packetSize);

        // inject into OS
        if (g_WintunSession && WintunAllocateSendPacket && WintunSendPacket) {
            BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
            if (osPacket) {
                memcpy(osPacket, buffer.data(), packetSize);
                WintunSendPacket(g_WintunSession, osPacket);
            }
        }

        // forward to destination if known, else broadcast
        if (packetSize >= 20) {
            uint32_t destNet = 0;
            memcpy(&destNet, buffer.data() + 16, sizeof(destNet));
            uint32_t destHost = ntohl(destNet);

            SOCKET target = INVALID_SOCKET;
            {
                std::lock_guard<std::mutex> lock(g_ipMutex);
                auto it = g_IpToSocketMap.find(destHost);
                if (it != g_IpToSocketMap.end()) target = it->second;
            }
            if (target != INVALID_SOCKET && target != sock) {
                EncryptAndSend(target, buffer.data(), packetSize);
            }
            else {
                std::lock_guard<std::mutex> lock(g_ClientsMutex);
                for (SOCKET other : g_ServerClients) {
                    if (other == sock) continue;
                    EncryptAndSend(other, buffer.data(), packetSize);
                }
            }
        }
        else {
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            for (SOCKET other : g_ServerClients) {
                if (other == sock) continue;
                EncryptAndSend(other, buffer.data(), packetSize);
            }
        }
    }

    // cleanup mapping & socket
    {
        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        auto it = std::find(g_ServerClients.begin(), g_ServerClients.end(), sock);
        if (it != g_ServerClients.end()) g_ServerClients.erase(it);
    }
    {
        std::lock_guard<std::mutex> lock(g_ipMutex);
        uint32_t ipToRelease = 0;
        for (auto it = g_IpToSocketMap.begin(); it != g_IpToSocketMap.end(); ++it) {
            if (it->second == sock) {
                ipToRelease = it->first; g_IpToSocketMap.erase(it); break;
            }
        }
        if (ipToRelease != 0) ReleaseClientIP(ipToRelease);
    }

    shutdown(sock, SD_BOTH); closesocket(sock);
    LogMessage(L"[CONNECT] Клиент отключился.");
}

// Stop network and cleanup
void StopNetwork() {
    g_TunnelActive = false;
    LogMessage(L"[STATUS] Остановка сети...");

    // remove UPnP mapping if any
    uint16_t port = g_CurrentServerPort.load();
    if (port != 0 && g_UseUPnP.load()) {
        std::string control, svc, base;
        if (UPnP_Discover(control, svc, base, 3000)) {
            if (UPnP_DeletePortMapping(control, svc, port, "TCP")) {
                LogMessage(L"[UPnP] Проброс порта удалён.");
            }
            else {
                LogMessage(L"[UPnP] Не удалось удалить проброс порта.");
            }
        }
    }
    g_CurrentServerPort.store(0);

    if (g_ListenSocket != INVALID_SOCKET) { shutdown(g_ListenSocket, SD_BOTH); closesocket(g_ListenSocket); g_ListenSocket = INVALID_SOCKET; }

    {
        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        for (SOCKET s : g_ServerClients) { shutdown(s, SD_BOTH); closesocket(s); }
        g_ServerClients.clear();
    }

    for (std::thread& t : g_ClientThreads) {
        if (t.joinable()) t.join();
    }
    g_ClientThreads.clear();

    if (g_ClientActiveSocket != INVALID_SOCKET) { shutdown(g_ClientActiveSocket, SD_BOTH); closesocket(g_ClientActiveSocket); g_ClientActiveSocket = INVALID_SOCKET; }

    if (g_WintunAdapter && WintunCloseAdapter) { WintunCloseAdapter(g_WintunAdapter); g_WintunAdapter = nullptr; g_WintunSession = nullptr; }

    WSACleanup();
    LogMessage(L"[STATUS] Сеть остановлена.");
}

// Execute netsh via CreateProcessW
bool ExecuteNetshCommand(const std::wstring& cmd) {
    std::wstring full = L"netsh " + cmd;
    std::vector<wchar_t> buf(full.begin(), full.end());
    buf.push_back(0);

    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return true;
}

// ---------- New, robust helpers for mask parsing & GetEffectiveSubnetMask ----------

// trim helpers
static inline std::string trim_str(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && isspace((unsigned char)s[a])) ++a;
    size_t b = s.size();
    while (b > a && isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

static bool IsDigitsStrict(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (!std::isdigit((unsigned char)c)) return false;
    return true;
}

static bool PrefixToMaskUint(int prefix, uint32_t& outMask) {
    if (prefix < 0 || prefix > 32) return false;
    if (prefix == 0) { outMask = 0u; return true; }
    if (prefix == 32) { outMask = 0xFFFFFFFFu; return true; }
    outMask = (~0u) << (32 - prefix);
    return true;
}

static bool DottedToMaskUint(const std::string& dotted, uint32_t& outMask) {
    std::stringstream ss(dotted);
    std::string tok;
    uint32_t parts[4];
    int idx = 0;
    while (std::getline(ss, tok, '.')) {
        if (idx >= 4) return false;
        if (!IsDigitsStrict(tok)) return false;
        int v = std::stoi(tok);
        if (v < 0 || v > 255) return false;
        parts[idx++] = static_cast<uint32_t>(v);
    }
    if (idx != 4) return false;
    outMask = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return true;
}

static int CountOnesUint(uint32_t x) {
    return static_cast<int>(std::bitset<32>(x).count());
}

static std::string MaskUintToDotted(uint32_t mask) {
    char buf[32];
    uint8_t a = (mask >> 24) & 0xFF;
    uint8_t b = (mask >> 16) & 0xFF;
    uint8_t c = (mask >> 8) & 0xFF;
    uint8_t d = mask & 0xFF;
    sprintf_s(buf, "%u.%u.%u.%u", a, b, c, d);
    return std::string(buf);
}

static std::string GetEffectiveSubnetMask() {
    const std::string defaultMask = "255.255.0.0"; // default kept for gamers/others

    std::string s;
    {
        std::lock_guard<std::mutex> lg(g_CustomMaskMutex);
        s = g_CustomSubnetMask;
    }
    // trim
    auto trim_str = [](std::string t) {
        size_t a = 0; while (a < t.size() && isspace((unsigned char)t[a])) ++a;
        size_t b = t.size(); while (b > a && isspace((unsigned char)t[b - 1])) --b;
        return t.substr(a, b - a);
        };
    s = trim_str(s);
    if (s.empty()) return defaultMask;

    // accept "/24" or "24" or dotted "255.255.255.0"
    if (s[0] == '/') s = s.substr(1);

    auto is_digits = [](const std::string& x) {
        if (x.empty()) return false;
        for (char c : x) if (!std::isdigit((unsigned char)c)) return false;
        return true;
        };

    auto prefix_to_mask = [](int prefix, uint32_t& outMask)->bool {
        if (prefix < 0 || prefix > 32) return false;
        if (prefix == 0) { outMask = 0u; return true; }
        if (prefix == 32) { outMask = 0xFFFFFFFFu; return true; }
        outMask = (~0u) << (32 - prefix);
        return true;
        };

    auto dotted_to_uint = [&](const std::string& dotted, uint32_t& outMask)->bool {
        std::stringstream ss(dotted);
        std::string tok; uint32_t parts[4]; int idx = 0;
        while (std::getline(ss, tok, '.')) {
            if (idx >= 4) return false;
            if (!is_digits(tok)) return false;
            int v = std::stoi(tok);
            if (v < 0 || v > 255) return false;
            parts[idx++] = static_cast<uint32_t>(v);
        }
        if (idx != 4) return false;
        outMask = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        return true;
        };

    auto mask_to_dotted = [](uint32_t m)->std::string {
        char buf[32];
        sprintf_s(buf, "%u.%u.%u.%u", (m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF);
        return std::string(buf);
        };

    if (is_digits(s)) {
        int prefix = std::stoi(s);
        uint32_t mu;
        if (!prefix_to_mask(prefix, mu)) return defaultMask;
        return mask_to_dotted(mu);
    }

    if (s.find('.') != std::string::npos) {
        uint32_t mu;
        if (!dotted_to_uint(s, mu)) return defaultMask;
        // проверим непрерывность единиц
        int ones = static_cast<int>(std::bitset<32>(mu).count());
        uint32_t recon;
        if (!prefix_to_mask(ones, recon)) return defaultMask;
        if (recon != mu) return defaultMask;
        return mask_to_dotted(mu);
    }

    return defaultMask;
}
// ---------- end of mask helpers --------------------------------------------------

// Setup Wintun adapter + netsh IP assignment
bool SetupVirtualAdapter(int mode) {
    if (!WintunCreateAdapter || !WintunStartSession) return false;
    GUID adapterGuid; CoCreateGuid(&adapterGuid);
    g_WintunAdapter = WintunCreateAdapter(L"P2P_Virtual_LAN", L"WintunTunnel", &adapterGuid);
    if (!g_WintunAdapter) { LogMessage(L"[ERR] Не создан Wintun адаптер (требуются права)."); return false; }
    g_WintunSession = WintunStartSession(g_WintunAdapter, 0x400000);
    if (!g_WintunSession) { if (WintunCloseAdapter) WintunCloseAdapter(g_WintunAdapter); g_WintunAdapter = nullptr; return false; }

    LogMessage(L"[OK] Wintun адаптер запущен.");
    if (mode == 1) {
        uint32_t srvIp = makeIpFromId(1);
        std::string srvIpStr = IPv4ToString(srvIp);
        std::string mask = GetEffectiveSubnetMask();
        std::wstring wSrvIp(srvIpStr.begin(), srvIpStr.end());
        std::wstring wMask(mask.begin(), mask.end());
        std::wstring cmdEnable = L"interface set interface name=\"P2P_Virtual_LAN\" admin=enabled";
        ExecuteNetshCommand(cmdEnable);
        std::wstring cmdIp = L"interface ip set address name=\"P2P_Virtual_LAN\" static " + wSrvIp + L" " + wMask;
        ExecuteNetshCommand(cmdIp);
        LogMessage(L"[NET] Серверный IP назначен: " + std::wstring(srvIpStr.begin(), srvIpStr.end()) + L" Маска: " + std::wstring(mask.begin(), mask.end()));
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return true;
}

// Start server
void StartServer(int port) {
    if (!InitializeWintunDLL()) { LogMessage(L"[ERR] wintun.dll не загружен."); return; }
    if (!SetupVirtualAdapter(1)) return;

    WSADATA wsa; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { LogMessage(L"[ERR] WSAStartup failed."); return; }

    g_ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ListenSocket == INVALID_SOCKET) { LogMessage(L"[ERR] Не удалось создать слушающий сокет."); StopNetwork(); return; }
    int nodelay = 1; setsockopt(g_ListenSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(static_cast<u_short>(port));
    if (bind(g_ListenSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) { LogMessage(L"[ERR] bind() failed."); StopNetwork(); return; }
    if (listen(g_ListenSocket, SOMAXCONN) == SOCKET_ERROR) { LogMessage(L"[ERR] listen() failed."); StopNetwork(); return; }

    g_TunnelActive = true;
    g_CurrentServerPort.store(static_cast<uint16_t>(port));

    // UPnP: attempt mapping if requested
    if (g_UseUPnP.load()) {
        std::string control, svc, base;
        if (UPnP_Discover(control, svc, base, 3000)) {
            std::string ext = UPnP_GetExternalIPAddress(control, svc, base);
            if (!ext.empty()) LogMessage(L"[UPnP] External IP: " + std::wstring(ext.begin(), ext.end()));
            bool mapped = UPnP_AddPortMapping(control, svc, "0.0.0.0", static_cast<uint16_t>(port), static_cast<uint16_t>(port), "TCP", "CreateLAN auto mapping", 0);
            if (mapped) LogMessage(L"[UPnP] Проброс порта успешно создан.");
            else LogMessage(L"[UPnP] Не удалось создать проброс порта через UPnP.");
        }
        else {
            LogMessage(L"[UPnP] UPnP discovery failed.");
        }
    }

    std::thread osWorker(ServerOsToNetworkWorker);
    osWorker.detach();

    LogMessage(L"[HUB] Сервер запущен. Ожидание подключений...");

    while (g_TunnelActive) {
        SOCKET client = accept(g_ListenSocket, nullptr, nullptr);
        if (!g_TunnelActive) break;
        if (client == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }

        uint32_t assignedIp = AllocateClientIP();
        if (assignedIp == 0) {
            closesocket(client);
            LogMessage(L"[HUB] Отказ: пул адресов исчерпан.");
            continue;
        }

        uint32_t netIp = htonl(assignedIp);
        if (!SafeSendFully(client, &netIp, sizeof(netIp))) {
            closesocket(client);
            ReleaseClientIP(assignedIp);
            LogMessage(L"[HUB] Отказ: не удалось отправить IP клиенту.");
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            g_ServerClients.push_back(client);
            {
                std::lock_guard<std::mutex> ipLock(g_ipMutex);
                g_IpToSocketMap[assignedIp] = client;
            }
            LogMessage(std::wstring(L"[CONNECT] Новый участник. IP: ") + std::wstring(IPv4ToString(assignedIp).begin(), IPv4ToString(assignedIp).end()));
            g_ClientThreads.emplace_back(&ServerSingleClientWorker, client);
        }
    }

    StopNetwork();
}

// Start client: connect, receive assigned IP, apply to adapter, then run worker loops
void StartClient(const std::string& serverIp, int serverPort) {
    if (!InitializeWintunDLL()) { LogMessage(L"[ERR] wintun.dll не загружен."); return; }
    if (!SetupVirtualAdapter(2)) return;

    WSADATA wsa; if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { LogMessage(L"[ERR] WSAStartup failed."); return; }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { LogMessage(L"[ERR] Не удалось создать клиентский сокет."); StopNetwork(); return; }
    int nodelay = 1; setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(static_cast<u_short>(serverPort));
    inet_pton(AF_INET, serverIp.c_str(), &addr.sin_addr);

    LogMessage(L"[CONNECT] Попытка подключения...");
    if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LogMessage(L"[ERR] Не удалось подключиться к серверу."); closesocket(sock); StopNetwork(); return;
    }

    uint32_t netIp = 0;
    if (!SafeRecvFully(sock, &netIp, sizeof(netIp))) {
        LogMessage(L"[ERR] Не удалось получить назначенный IP от сервера."); closesocket(sock); StopNetwork(); return;
    }
    uint32_t assignedHostIp = ntohl(netIp);
    std::string assignedIpStr = IPv4ToString(assignedHostIp);
    LogMessage(std::wstring(L"[NET] Получен назначенный IP: ") + std::wstring(assignedIpStr.begin(), assignedIpStr.end()));

    // Apply IP + mask. Use custom mask if enabled.
    std::string mask = GetEffectiveSubnetMask();
    std::wstring cmdEnable = L"interface set interface name=\"P2P_Virtual_LAN\" admin=enabled";
    ExecuteNetshCommand(cmdEnable);
    std::wstring cmdIp = L"interface ip set address name=\"P2P_Virtual_LAN\" static " + std::wstring(assignedIpStr.begin(), assignedIpStr.end()) + L" " + std::wstring(mask.begin(), mask.end());
    ExecuteNetshCommand(cmdIp);

    g_ClientActiveSocket = sock;
    g_TunnelActive = true;

    std::thread osWorker(ClientOsToNetworkWorker);
    osWorker.detach();

    LogMessage(L"[MATRIX] Подключение установлено. IP assigned: " + std::wstring(assignedIpStr.begin(), assignedIpStr.end()));

    while (g_TunnelActive) {
        uint32_t netSize = 0;
        if (!SafeRecvFully(g_ClientActiveSocket, &netSize, sizeof(netSize))) break;
        uint32_t packetSize = ntohl(netSize);
        if (packetSize == 0 || packetSize > MAX_PACKET_SIZE) break;
        std::vector<uint8_t> buf(packetSize);
        if (!SafeRecvFully(g_ClientActiveSocket, buf.data(), static_cast<int>(packetSize))) break;
        Encryption::Decrypt(buf.data(), packetSize);

        if (g_WintunSession && WintunAllocateSendPacket && WintunSendPacket) {
            BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
            if (osPacket) {
                memcpy(osPacket, buf.data(), packetSize);
                WintunSendPacket(g_WintunSession, osPacket);
            }
        }
    }

    StopNetwork();
}