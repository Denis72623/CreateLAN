#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib") // CoCreateGuid used in SetupVirtualAdapter

// Controls IDs
constexpr int IDC_IP_INPUT = 101;
constexpr int IDC_PORT_INPUT = 102;
constexpr int IDC_BTN_SERVER = 103;
constexpr int IDC_BTN_CLIENT = 104;
constexpr int IDC_BTN_STOP = 105;
constexpr int IDC_LOG_ZONE = 106;
constexpr int IDC_UPNP = 107;

// New controls for custom subnet mask
constexpr int IDC_USE_CUSTOM_MASK = 108; // checkbox
constexpr int IDC_MASK_INPUT = 109;      // edit box for mask text

// Addressing defaults
constexpr uint32_t ADDRESS_POOL_SIZE = 0xFFFF; // use 1..65534
constexpr uint8_t ADDRESS_PREFIX_A = 10; // 10.8.x.y
constexpr uint8_t ADDRESS_PREFIX_B = 8;
constexpr uint32_t MAX_PACKET_SIZE = 65536; // 64 KiB

extern std::atomic<uint32_t> g_MaxClients;
extern std::atomic<bool> g_UseUPnP;
extern std::atomic<uint16_t> g_CurrentServerPort;

// New globals for custom subnet mask UI/state
extern std::atomic<bool> g_UseCustomSubnetMask; // whether to use custom mask
extern std::string g_CustomSubnetMask; // protected by g_CustomMaskMutex when needed
extern std::mutex g_CustomMaskMutex;

// Wintun prototypes (dynamic)
typedef HANDLE(WINAPI* WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR Name, LPCWSTR TunnelType, const GUID* RequestedGUID);
typedef HANDLE(WINAPI* WINTUN_START_SESSION_FUNC)(HANDLE Adapter, DWORD Capacity);
typedef BYTE* (WINAPI* WINTUN_ALLOCATE_SEND_PACKET_FUNC)(HANDLE Session, DWORD PacketSize);
typedef void(WINAPI* WINTUN_SEND_PACKET_FUNC)(HANDLE Session, BYTE* Packet);
typedef BYTE* (WINAPI* WINTUN_RECEIVE_PACKET_FUNC)(HANDLE Session, DWORD* PacketSize);
typedef void(WINAPI* WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(HANDLE Session, BYTE* Packet);
typedef void(WINAPI* WINTUN_CLOSE_ADAPTER_FUNC)(HANDLE Adapter);

// Wintun pointers
extern WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
extern WINTUN_START_SESSION_FUNC WintunStartSession;
extern WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
extern WINTUN_SEND_PACKET_FUNC WintunSendPacket;
extern WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
extern WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
extern WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter;

// Global network state
extern std::atomic<bool> g_TunnelActive;
extern std::mutex g_ClientsMutex;
extern std::vector<SOCKET> g_ServerClients;
extern std::vector<std::thread> g_ClientThreads;
extern SOCKET g_ListenSocket;
extern SOCKET g_ClientActiveSocket;
extern HANDLE g_WintunAdapter;
extern HANDLE g_WintunSession;
extern HWND hLogZone; // for GUI logging

// IP allocation
uint32_t AllocateClientIP();
void ReleaseClientIP(uint32_t ip);
std::string IPv4ToString(uint32_t ipHostOrder);

// UPnP simple functions (defined in upnp_simple.*)
// Note: default argument only in upnp_simple.h
bool UPnP_Discover(std::string& outControlURL, std::string& outServiceType, std::string& outBaseURL, int timeoutMs);
std::string UPnP_GetExternalIPAddress(const std::string& controlURL, const std::string& serviceType, const std::string& baseURL);
bool UPnP_AddPortMapping(const std::string& controlURL, const std::string& serviceType, const std::string& internalClient, uint16_t internalPort, uint16_t externalPort, const std::string& proto, const std::string& description, int leaseDurationSeconds);
bool UPnP_DeletePortMapping(const std::string& controlURL, const std::string& serviceType, uint16_t externalPort, const std::string& proto);

// Encryption abstraction (default: simple XOR - placeholder)
namespace Encryption {
    void Init();
    void Encrypt(uint8_t* buf, uint32_t size);
    void Decrypt(uint8_t* buf, uint32_t size);
}

// RAII wrapper for SOCKET
class SocketHandle {
public:
    SocketHandle() : s(INVALID_SOCKET) {}
    explicit SocketHandle(SOCKET sock) : s(sock) {}
    ~SocketHandle() { Close(); }
    SOCKET Get() const { return s; }
    SOCKET Release() { SOCKET tmp = s; s = INVALID_SOCKET; return tmp; }
    void Reset(SOCKET sock) { Close(); s = sock; }
    void Close() { if (s != INVALID_SOCKET) { shutdown(s, SD_BOTH); closesocket(s); s = INVALID_SOCKET; } }
    explicit operator bool() const { return s != INVALID_SOCKET; }
private:
    SOCKET s;
};

// Utilities
bool InitializeWintunDLL();
void LogMessage(const std::wstring& msg);
void StopNetwork();
void StartServer(int port);
void StartClient(const std::string& ip, int port);

// lower-level helpers
bool SafeRecvFully(SOCKET sock, void* buf, int len);
bool SafeSendFully(SOCKET sock, const void* buf, int len);
void ServerOsToNetworkWorker();
void ClientOsToNetworkWorker();
void ServerSingleClientWorker(SOCKET clientSock);