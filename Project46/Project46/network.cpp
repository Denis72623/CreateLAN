// network.cpp — замените на эту версию

#include "network.h"
#include <vector>
#include <algorithm>
#include <chrono>
#include <mutex>
#include <stack>
#include <unordered_map>
#include <sstream>
#include <objbase.h>

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

// Address pool structures
static std::mutex g_ipMutex;
static uint32_t g_nextIpId = 2; // reserve id=1 for server (10.8.0.1)
static std::stack<uint32_t> g_freeIpIds; // reuse on disconnect
// Map: IPv4 (host-order) -> client socket
static std::unordered_map<uint32_t, SOCKET> g_IpToSocketMap;

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

void LogMessage(const std::wstring& msg) {
    if (!hLogZone) return;
    std::wstring dynamicMsg = msg + L"\r\n";
    int len = GetWindowTextLengthW(hLogZone);
    SendMessageW(hLogZone, EM_SETSEL, len, len);
    SendMessageW(hLogZone, EM_REPLACESEL, 0, (LPARAM)dynamicMsg.c_str());
}

bool SafeRecvFully(SOCKET sock, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    int total = 0;
    while (total < len) {
        int r = recv(sock, p + total, len - total, 0);
        if (r == 0) return false;
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

// IP pool helpers
static uint32_t makeIpFromId(uint32_t id) {
    // id is 1..65534, map to 10.8.(id>>8).(id&0xff)
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
    // skip id==1 (reserved for server). start from g_nextIpId (initialised to 2)
    if (g_nextIpId == 0 || g_nextIpId >= ADDRESS_POOL_SIZE) {
        // pool exhausted — wraparound behaviour: reuse freed ids if any; else return 0 meaning failure
        return 0;
    }
    uint32_t id = g_nextIpId++;
    return makeIpFromId(id);
}

void ReleaseClientIP(uint32_t ipHostOrder) {
    std::lock_guard<std::mutex> lock(g_ipMutex);
    // extract id from ip
    uint8_t c = static_cast<uint8_t>((ipHostOrder >> 8) & 0xFF);
    uint8_t d = static_cast<uint8_t>(ipHostOrder & 0xFF);
    uint32_t id = (static_cast<uint32_t>(c) << 8) | static_cast<uint32_t>(d);
    if (id >= 2 && id < ADDRESS_POOL_SIZE) {
        g_freeIpIds.push(id);
    }
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

// helper: send allocated ip to client immediately after accept
static bool SendAssignedIPToClient(SOCKET clientSock, uint32_t ipHostOrder) {
    uint32_t netIp = htonl(ipHostOrder);
    return SafeSendFully(clientSock, &netIp, sizeof(netIp));
}

// Encryption send helper
void EncryptAndSend(SOCKET sock, uint8_t* data, uint32_t size) {
    if (sock == INVALID_SOCKET) return;
    if (size == 0 || size > MAX_PACKET_SIZE) return;
    std::vector<uint8_t> tmp(data, data + size);
    Encryption::Encrypt(tmp.data(), size);
    uint32_t netSize = htonl(size);
    if (!SafeSendFully(sock, &netSize, sizeof(netSize))) return;
    SafeSendFully(sock, tmp.data(), static_cast<int>(size));
}

// Server: Wintun -> reach client based on destination IP
void ServerOsToNetworkWorker() {
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (!packetData || packetSize == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(1)); continue; }
        if (packetSize > MAX_PACKET_SIZE) { WintunReleaseReceivePacket(g_WintunSession, packetData); continue; }

        // attempt to parse IPv4 destination (basic check)
        if (packetSize >= 20) {
            uint8_t ver_ihl = packetData[0];
            uint8_t version = ver_ihl >> 4;
            if (version == 4) {
                // destination address at offset 16..19 (network byte order)
                uint32_t destNet = 0;
                memcpy(&destNet, packetData + 16, sizeof(destNet));
                uint32_t destHost = ntohl(destNet);

                // find mapped client
                SOCKET target = INVALID_SOCKET;
                {
                    std::lock_guard<std::mutex> lock(g_ipMutex);
                    auto it = g_IpToSocketMap.find(destHost);
                    if (it != g_IpToSocketMap.end()) target = it->second;
                }
                if (target != INVALID_SOCKET) {
                    // send only to target
                    EncryptAndSend(target, packetData, packetSize);
                }
                else {
                    // broadcast to all clients if target not found
                    std::lock_guard<std::mutex> lock(g_ClientsMutex);
                    for (SOCKET s : g_ServerClients) EncryptAndSend(s, packetData, packetSize);
                }
            }
            else {
                // not IPv4 => fallback broadcast
                std::lock_guard<std::mutex> lock(g_ClientsMutex);
                for (SOCKET s : g_ServerClients) EncryptAndSend(s, packetData, packetSize);
            }
        }
        else {
            // too small => broadcast
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            for (SOCKET s : g_ServerClients) EncryptAndSend(s, packetData, packetSize);
        }

        WintunReleaseReceivePacket(g_WintunSession, packetData);
    }
}

void ClientOsToNetworkWorker() {
    using namespace std::chrono_literals;
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) {
            std::this_thread::sleep_for(100ms);
            continue;
        }

        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (!packetData || packetSize == 0) {
            std::this_thread::sleep_for(1ms);
            continue;
        }

        if (packetSize > MAX_PACKET_SIZE) {
            // too large — skip and release
            WintunReleaseReceivePacket(g_WintunSession, packetData);
            continue;
        }

        // send to server (client's active socket)
        if (g_ClientActiveSocket != INVALID_SOCKET) {
            // EncryptAndSend expects uint8_t* and uint32_t
            EncryptAndSend(g_ClientActiveSocket, reinterpret_cast<uint8_t*>(packetData), static_cast<uint32_t>(packetSize));
        }

        WintunReleaseReceivePacket(g_WintunSession, packetData);
    }
}

// Per-client server worker: when client sends packets -> inject to OS and forward based on dest IP
void ServerSingleClientWorker(SOCKET clientSock) {
    SOCKET sock = clientSock;
    uint32_t assignedIp = 0;
    {
        // find which IP is mapped to this socket
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

        // forward to the specific destination client (if known) otherwise broadcast
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

    // cleanup mappings & socket
    {
        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        auto it = std::find(g_ServerClients.begin(), g_ServerClients.end(), sock);
        if (it != g_ServerClients.end()) g_ServerClients.erase(it);
    }
    {
        std::lock_guard<std::mutex> lock(g_ipMutex);
        // remove ip->socket mapping for this socket and release IP
        uint32_t ipToRelease = 0;
        for (auto it = g_IpToSocketMap.begin(); it != g_IpToSocketMap.end(); ++it) {
            if (it->second == sock) { ipToRelease = it->first; g_IpToSocketMap.erase(it); break; }
        }
        if (ipToRelease != 0) ReleaseClientIP(ipToRelease);
    }

    shutdown(sock, SD_BOTH); closesocket(sock);
    LogMessage(L"[CONNECT] Клиент отключился.");
}

// Stop network and join threads
void StopNetwork() {
    g_TunnelActive = false;
    LogMessage(L"[STATUS] Остановка сети...");

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

// Setup adapter — now server (mode==1) sets server IP .1, clients only create adapter/session and wait for assignment
bool SetupVirtualAdapter(int mode) {
    if (!WintunCreateAdapter || !WintunStartSession) return false;
    GUID adapterGuid; CoCreateGuid(&adapterGuid);
    g_WintunAdapter = WintunCreateAdapter(L"P2P_Virtual_LAN", L"WintunTunnel", &adapterGuid);
    if (!g_WintunAdapter) { LogMessage(L"[ERR] Не создан Wintun адаптер (требуются права)."); return false; }
    g_WintunSession = WintunStartSession(g_WintunAdapter, 0x400000);
    if (!g_WintunSession) { if (WintunCloseAdapter) WintunCloseAdapter(g_WintunAdapter); g_WintunAdapter = nullptr; return false; }

    LogMessage(L"[OK] Wintun адаптер запущен.");
    // server sets .1 (reserved)
    if (mode == 1) {
        std::string srvIp = IPv4ToString(makeIpFromId(1)); // 10.8.0.1
        std::wstring cmdEnable = L"interface set interface name=\"P2P_Virtual_LAN\" admin=enabled";
        ExecuteNetshCommand(cmdEnable);
        std::wstring cmdIp = L"interface ip set address name=\"P2P_Virtual_LAN\" static " + std::wstring(srvIp.begin(), srvIp.end()) + L" 255.255.0.0";
        ExecuteNetshCommand(cmdIp);
        LogMessage(L"[NET] Серверный IP назначен: " + std::wstring(srvIp.begin(), srvIp.end()));
    }
    // clients will receive IP from server
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return true;
}

// Start server: accept loop and spawn client threads (no hard limit). On accept we allocate IP and send it.
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
    std::thread osWorker(ServerOsToNetworkWorker);
    osWorker.detach();

    LogMessage(L"[HUB] Сервер запущен. Ожидание подключений...");

    while (g_TunnelActive) {
        SOCKET client = accept(g_ListenSocket, nullptr, nullptr);
        if (!g_TunnelActive) break;
        if (client == INVALID_SOCKET) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }

        // allocate IP for this client
        uint32_t assignedIp = AllocateClientIP();
        if (assignedIp == 0) {
            // no IP available -> reject
            closesocket(client);
            LogMessage(L"[HUB] Отказ: пул адресов исчерпан.");
            continue;
        }

        // send assigned ip to client (host-order -> network-order)
        if (!SendAssignedIPToClient(client, assignedIp)) {
            closesocket(client);
            ReleaseClientIP(assignedIp);
            LogMessage(L"[HUB] Отказ: не удалось отправить IP клиенту.");
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            g_ServerClients.push_back(client);
            // record mapping
            {
                std::lock_guard<std::mutex> ipLock(g_ipMutex);
                g_IpToSocketMap[assignedIp] = client;
            }

            LogMessage(std::wstring(L"[CONNECT] Новый участник. IP: ") + std::wstring(IPv4ToString(assignedIp).begin(), IPv4ToString(assignedIp).end()));
            // spawn thread
            g_ClientThreads.emplace_back(&ServerSingleClientWorker, client);
        }
    }

    StopNetwork();
}

// Start client: connect, receive assigned IP, apply to adapter, then run worker loops
void StartClient(const std::string& serverIp, int serverPort) {
    if (!InitializeWintunDLL()) { LogMessage(L"[ERR] wintun.dll не загружен."); return; }
    if (!SetupVirtualAdapter(2)) return; // client creates adapter but doesn't set IP yet

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

    // receive assigned IP (4 bytes)
    uint32_t netIp = 0;
    if (!SafeRecvFully(sock, &netIp, sizeof(netIp))) {
        LogMessage(L"[ERR] Не удалось получить назначенный IP от сервера."); closesocket(sock); StopNetwork(); return;
    }
    uint32_t assignedHostIp = ntohl(netIp);
    std::string assignedIpStr = IPv4ToString(assignedHostIp);
    LogMessage(std::wstring(L"[NET] Получен назначенный IP: ") + std::wstring(assignedIpStr.begin(), assignedIpStr.end()));

    // Apply IP to adapter: enable interface and set static IP
    std::wstring cmdEnable = L"interface set interface name=\"P2P_Virtual_LAN\" admin=enabled";
    ExecuteNetshCommand(cmdEnable);
    std::wstring cmdIp = L"interface ip set address name=\"P2P_Virtual_LAN\" static " + std::wstring(assignedIpStr.begin(), assignedIpStr.end()) + L" 255.255.0.0";
    ExecuteNetshCommand(cmdIp);

    g_ClientActiveSocket = sock;
    g_TunnelActive = true;

    // start OS->network thread
    std::thread osWorker(ClientOsToNetworkWorker);
    osWorker.detach();

    LogMessage(L"[MATRIX] Подключение установлено. IP assigned: " + std::wstring(assignedIpStr.begin(), assignedIpStr.end()));

    // main loop: receive from server and inject to OS
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