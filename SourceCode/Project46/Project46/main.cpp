#include "network.h"
#include <ws2tcpip.h>
#include <vector>
#include <atomic>
#include <winsock2.h>
#include <stdint.h>

WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = nullptr;
WINTUN_START_SESSION_FUNC WintunStartSession = nullptr;
WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = nullptr;
WINTUN_SEND_PACKET_FUNC WintunSendPacket = nullptr;
WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = nullptr;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = nullptr;
WINTUN_CLOSE_ADAPTER_FUNC WintunCloseAdapter = nullptr;

std::atomic<bool> g_TunnelActive(false);
SOCKET g_ClientActiveSocket = INVALID_SOCKET;
SOCKET g_ListenSocket = INVALID_SOCKET;
std::vector<SOCKET> g_ServerClients;
std::mutex g_ClientsMutex;
int g_ClientSlot = 2;

HANDLE g_WintunAdapter = nullptr;
HANDLE g_WintunSession = nullptr;
const unsigned char ENCRYPTION_KEY = 'X';

std::thread g_Thread1;
std::thread g_Thread2;

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
    std::wstring dynamicMsg = msg + L"\r\n";
    int len = GetWindowTextLengthW(hLogZone);
    SendMessageW(hLogZone, EM_SETSEL, len, len);
    SendMessageW(hLogZone, EM_REPLACESEL, 0, (LPARAM)dynamicMsg.c_str());
}

// Helper: receive exactly len bytes or fail
static bool SafeRecvFully(SOCKET sock, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    int received = 0;
    while (received < len) {
        int r = recv(sock, p + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

// Helper: send exactly len bytes or fail
static bool SafeSendFully(SOCKET sock, const void* buf, int len) {
    const char* p = static_cast<const char*>(buf);
    int sent = 0;
    while (sent < len) {
        int s = send(sock, p + sent, len - sent, 0);
        if (s == SOCKET_ERROR || s == 0) return false;
        sent += s;
    }
    return true;
}

void EncryptAndSend(SOCKET sock, BYTE* data, DWORD size) {
    if (sock == INVALID_SOCKET) return;
    if (size == 0 || size > MAX_PACKET_SIZE) return; // validate size

    std::vector<char> sendBuffer(size);
    for (DWORD i = 0; i < size; ++i) {
        sendBuffer[i] = data[i] ^ ENCRYPTION_KEY;
    }

    uint32_t netSize = htonl(static_cast<uint32_t>(size));
    if (!SafeSendFully(sock, &netSize, sizeof(netSize))) {
        // send failed
        return;
    }
    if (!SafeSendFully(sock, sendBuffer.data(), static_cast<int>(size))) {
        return;
    }
}

void ServerOsToNetworkWorker() {
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (packetData && packetSize > 0) {
            if (packetSize > MAX_PACKET_SIZE) {
                // skip unexpected large packet
                WintunReleaseReceivePacket(g_WintunSession, packetData);
                continue;
            }
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            for (SOCKET sock : g_ServerClients) {
                EncryptAndSend(sock, packetData, packetSize);
            }
            WintunReleaseReceivePacket(g_WintunSession, packetData);
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void ClientOsToNetworkWorker() {
    while (g_TunnelActive) {
        if (!g_WintunSession || !WintunReceivePacket) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (packetData && packetSize > 0) {
            if (packetSize > MAX_PACKET_SIZE) {
                WintunReleaseReceivePacket(g_WintunSession, packetData);
                continue;
            }
            EncryptAndSend(g_ClientActiveSocket, packetData, packetSize);
            WintunReleaseReceivePacket(g_WintunSession, packetData);
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void ServerSingleClientWorker(SOCKET clientSock) {
    while (g_TunnelActive) {
        uint32_t packetSizeNet = 0;
        if (!SafeRecvFully(clientSock, &packetSizeNet, sizeof(packetSizeNet))) break;
        uint32_t packetSize = ntohl(packetSizeNet);
        if (packetSize == 0 || packetSize > MAX_PACKET_SIZE) break;

        std::vector<char> recvBuffer(packetSize);
        if (!SafeRecvFully(clientSock, recvBuffer.data(), static_cast<int>(packetSize))) break;

        for (DWORD i = 0; i < packetSize; ++i) { recvBuffer[i] ^= ENCRYPTION_KEY; }

        if (g_WintunSession && WintunAllocateSendPacket && WintunSendPacket) {
            BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
            if (osPacket) {
                memcpy(osPacket, recvBuffer.data(), packetSize);
                WintunSendPacket(g_WintunSession, osPacket);
            }
        }

        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        for (SOCKET otherSock : g_ServerClients) {
            if (otherSock != clientSock) {
                // forward to other clients
                std::vector<char> forwardBuffer(packetSize);
                for (DWORD i = 0; i < packetSize; ++i) forwardBuffer[i] = recvBuffer[i] ^ ENCRYPTION_KEY;
                uint32_t fNetSize = htonl(static_cast<uint32_t>(packetSize));
                SafeSendFully(otherSock, &fNetSize, sizeof(fNetSize));
                SafeSendFully(otherSock, forwardBuffer.data(), static_cast<int>(packetSize));
            }
        }
    }

    std::lock_guard<std::mutex> lock(g_ClientsMutex);
    auto it = std::find(g_ServerClients.begin(), g_ServerClients.end(), clientSock);
    if (it != g_ServerClients.end()) g_ServerClients.erase(it);
    closesocket(clientSock);
    LogMessage(L"[СЕТЬ] Один из участников покинул туннель.");
}
