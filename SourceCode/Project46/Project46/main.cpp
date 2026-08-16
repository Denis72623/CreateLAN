#include "network.h"
#include <ws2tcpip.h>
#include <vector>

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
const char ENCRYPTION_KEY = 'X';

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

void EncryptAndSend(SOCKET sock, BYTE* data, DWORD size) {
    std::vector<char> sendBuffer(size);
    for (DWORD i = 0; i < size; ++i) {
        sendBuffer[i] = data[i] ^ ENCRYPTION_KEY;
    }
    send(sock, reinterpret_cast<char*>(&size), sizeof(size), 0);
    send(sock, sendBuffer.data(), static_cast<int>(size), 0);
}

void ServerOsToNetworkWorker() {
    while (g_TunnelActive) {
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (packetData && packetSize > 0) {
            std::lock_guard<std::mutex> lock(g_ClientsMutex);
            for (SOCKET sock : g_ServerClients) {
                EncryptAndSend(sock, packetData, packetSize);
            }
            WintunReleaseReceivePacket(g_WintunSession, packetData);
        }
    }
}

void ClientOsToNetworkWorker() {
    while (g_TunnelActive) {
        DWORD packetSize = 0;
        BYTE* packetData = WintunReceivePacket(g_WintunSession, &packetSize);
        if (packetData && packetSize > 0) {
            EncryptAndSend(g_ClientActiveSocket, packetData, packetSize);
            WintunReleaseReceivePacket(g_WintunSession, packetData);
        }
    }
}

void ServerSingleClientWorker(SOCKET clientSock) {
    while (g_TunnelActive) {
        DWORD packetSize = 0;
        int res = recv(clientSock, reinterpret_cast<char*>(&packetSize), sizeof(packetSize), 0);
        if (res <= 0) break;

        std::vector<char> recvBuffer(packetSize);
        int bytesRead = 0;
        while (bytesRead < static_cast<int>(packetSize)) {
            int currentRead = recv(clientSock, recvBuffer.data() + bytesRead, static_cast<int>(packetSize) - bytesRead, 0);
            if (currentRead <= 0) break;
            bytesRead += currentRead;
        }

        for (DWORD i = 0; i < packetSize; ++i) { recvBuffer[i] ^= ENCRYPTION_KEY; }

        BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
        if (osPacket) {
            memcpy(osPacket, recvBuffer.data(), packetSize);
            WintunSendPacket(g_WintunSession, osPacket);
        }

        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        for (SOCKET otherSock : g_ServerClients) {
            if (otherSock != clientSock) {
                std::vector<char> forwardBuffer(packetSize);
                for (DWORD i = 0; i < packetSize; ++i) forwardBuffer[i] = recvBuffer[i] ^ ENCRYPTION_KEY;
                send(otherSock, reinterpret_cast<char*>(&packetSize), sizeof(packetSize), 0);
                send(otherSock, forwardBuffer.data(), static_cast<int>(packetSize), 0);
            }
        }
    }

    std::lock_guard<std::mutex> lock(g_ClientsMutex);
    auto it = std::find(g_ServerClients.begin(), g_ServerClients.end(), clientSock);
    if (it != g_ServerClients.end()) g_ServerClients.erase(it);
    closesocket(clientSock);
    LogMessage(L"[СЕТЬ] Один из участников покинул туннель.");
}