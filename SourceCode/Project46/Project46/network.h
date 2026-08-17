#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")

// Limits
constexpr DWORD MAX_PACKET_SIZE = 65536; // 64 KiB

// Идентификаторы элементов интерфейса
#define IDC_IP_INPUT    101
#define IDC_PORT_INPUT  102
#define IDC_BTN_SERVER  103
#define IDC_BTN_CLIENT  104
#define IDC_BTN_STOP    105
#define IDC_LOG_ZONE    106
#define IDC_SLOT_INPUT  107

// Прототипы функций драйвера Wintun
typedef HANDLE(WINAPI* WINTUN_CREATE_ADAPTER_FUNC)(LPCWSTR Name, LPCWSTR TunnelType, const GUID* RequestedGUID);
typedef HANDLE(WINAPI* WINTUN_START_SESSION_FUNC)(HANDLE Adapter, DWORD Capacity);
typedef BYTE* (WINAPI* WINTUN_ALLOCATE_SEND_PACKET_FUNC)(HANDLE Session, DWORD PacketSize);
typedef void(WINAPI* WINTUN_SEND_PACKET_FUNC)(HANDLE Session, BYTE* Packet);
typedef BYTE* (WINAPI* WINTUN_RECEIVE_PACKET_FUNC)(HANDLE Session, DWORD* PacketSize);
typedef void(WINAPI* WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(HANDLE Session, BYTE* Packet);
typedef void(WINAPI* WINTUN_CLOSE_ADAPTER_FUNC)(HANDLE Adapter);

extern WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
extern WINTUN_START_SESSION_FUNC WintunStartSession;
extern WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
extern WINTUN_SEND_PACKET_FUNC WintunSendPacket;
extern WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
extern WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
extern WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter;

// Глобальные переменные сетевого состояния
extern std::atomic<bool> g_TunnelActive;
extern SOCKET g_ClientActiveSocket;
extern SOCKET g_ListenSocket;
extern std::vector<SOCKET> g_ServerClients;
extern std::mutex g_ClientsMutex;
extern int g_ClientSlot;
extern const unsigned char ENCRYPTION_KEY;

extern HANDLE g_WintunAdapter;
extern HANDLE g_WintunSession;
extern HWND hBtnServer, hBtnClient, hLogZone;

// Прототипы функций логики
void LogMessage(const std::wstring& msg);
bool InitializeWintunDLL();
void StopNetwork();
void AsyncServerThread(int port);
void AsyncClientThread(std::string ip, int port);

