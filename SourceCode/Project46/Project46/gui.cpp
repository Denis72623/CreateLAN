#include "network.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <clocale>
#include <string>

HWND hIpInput, hPortInput, hBtnServer, hBtnClient, hBtnStop, hLogZone;

HBRUSH hBackBrush = CreateSolidBrush(RGB(5, 15, 5));
COLORREF textGreen = RGB(0, 255, 65);
COLORREF darkBox = RGB(15, 35, 15);

void ServerOsToNetworkWorker();
void ClientOsToNetworkWorker();
void ServerSingleClientWorker(SOCKET clientSock);

void StopNetwork() {
    g_TunnelActive = false;
    LogMessage(L"[MATRIX] Деактивация протоколов. Закрытие портов...");

    if (g_ClientActiveSocket != INVALID_SOCKET) { shutdown(g_ClientActiveSocket, SD_BOTH); closesocket(g_ClientActiveSocket); g_ClientActiveSocket = INVALID_SOCKET; }
    if (g_ListenSocket != INVALID_SOCKET) { closesocket(g_ListenSocket); g_ListenSocket = INVALID_SOCKET; }

    std::lock_guard<std::mutex> lock(g_ClientsMutex);
    for (SOCKET sock : g_ServerClients) { shutdown(sock, SD_BOTH); closesocket(sock); }
    g_ServerClients.clear();

    if (g_WintunAdapter) { if (WintunCloseAdapter) WintunCloseAdapter(g_WintunAdapter); g_WintunAdapter = nullptr; g_WintunSession = nullptr; }
    WSACleanup();

    LogMessage(L"[STATUS] Туннель полностью отключен.");
    EnableWindow(hBtnServer, TRUE);
    EnableWindow(hBtnClient, TRUE);
}

bool ExecuteNetshCommand(const std::wstring& cmd) {
    // Build command line: netsh <cmd>
    std::wstring full = L"netsh ";
    full += cmd;
    // CreateProcess requires writable buffer
    std::vector<wchar_t> buf(full.begin(), full.end());
    buf.push_back(0);

    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    BOOL ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) return false;
    // wait briefly
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return true;
}

bool SetupVirtualAdapter(int mode) {
    GUID adapterGuid;
    CoCreateGuid(&adapterGuid);
    g_WintunAdapter = WintunCreateAdapter(L"P2P_Virtual_LAN", L"WintunTunnel", &adapterGuid);
    if (!g_WintunAdapter) { LogMessage(L"[ERR] Требуются права Ад��инистратора!"); return false; }
    g_WintunSession = WintunStartSession(g_WintunAdapter, 0x400000);
    if (!g_WintunSession) { if (WintunCloseAdapter) WintunCloseAdapter(g_WintunAdapter); return false; }

    LogMessage(L"[OK] Интерфейс Wintun запущен в ядре x64.");
    // Use CreateProcess instead of WinExec
    ExecuteNetshCommand(L"interface set interface name=\"P2P_Virtual_LAN\" admin=enabled");

    // Автоматическое назначение IP: Серверу ставим .1, Клиенту ставим .2
    std::wstring ipStr = (mode == 1) ? L"10.8.0.1" : L"10.8.0.2";
    std::wstring ipCmd = L"interface ip set address name=\"P2P_Virtual_LAN\" static " + ipStr + L" 255.255.255.0";
    ExecuteNetshCommand(ipCmd);

    LogMessage(L"[NET] Системой автоматически выделен IP: " + ipStr);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return true;
}

void AsyncServerThread(int port) {
    if (!SetupVirtualAdapter(1)) return; // 1 = Режим Сервера (IP 10.8.0.1)
    WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

    g_ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ListenSocket == INVALID_SOCKET) { LogMessage(L"[ERR] Не удалось создать слушающий сокет."); StopNetwork(); return; }
    int nodelay = 1; setsockopt(g_ListenSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(int));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(static_cast<u_short>(port));
    if (bind(g_ListenSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) { LogMessage(L"[ERR] bind() failed."); StopNetwork(); return; }
    if (listen(g_ListenSocket, SOMAXCONN) == SOCKET_ERROR) { LogMessage(L"[ERR] listen() failed."); StopNetwork(); return; }

    g_TunnelActive = true;
    std::thread(ServerOsToNetworkWorker).detach();
    LogMessage(L"[HUB] Локальная сеть запущена. Ожидание подключения...");

    while (g_TunnelActive) {
        SOCKET clientSock = accept(g_ListenSocket, nullptr, nullptr);
        if (clientSock == INVALID_SOCKET) break;
        setsockopt(clientSock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(int));

        std::lock_guard<std::mutex> lock(g_ClientsMutex);
        if (g_ServerClients.size() < 253) {
            g_ServerClients.push_back(clientSock);
            std::wstring countStr = std::to_wstring(253 - g_ServerClients.size());
            LogMessage(L"[CONNECT] Новый участник вошел в сеть!");
            std::thread(ServerSingleClientWorker, clientSock).detach();
        }
        else {
            closesocket(clientSock);
        }
    }
    StopNetwork();
}

void AsyncClientThread(std::string ip, int port) {
    if (!SetupVirtualAdapter(2)) return; // 2 = Режим Клиента (IP 10.8.0.2)
    WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

    g_ClientActiveSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ClientActiveSocket == INVALID_SOCKET) { LogMessage(L"[ERR] Не удалось создать клиентский сокет."); StopNetwork(); return; }
    int nodelay = 1; setsockopt(g_ClientActiveSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(int));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    LogMessage(L"[CONNECT] Подключение к локальный сеть");
    if (connect(g_ClientActiveSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LogMessage(L"[ERR] Не удалось связаться с локальный сети."); StopNetwork(); return;
    }

    LogMessage(L"[MATRIX] Вы успешно вошли в локальную сеть!");
    g_TunnelActive = true;
    std::thread(ClientOsToNetworkWorker).detach();

    while (g_TunnelActive) {
        uint32_t packetSizeNet = 0;
        int res = recv(g_ClientActiveSocket, reinterpret_cast<char*>(&packetSizeNet), sizeof(packetSizeNet), 0);
        if (res <= 0) break;
        uint32_t packetSize = ntohl(packetSizeNet);
        if (packetSize == 0 || packetSize > MAX_PACKET_SIZE) break;

        std::vector<char> recvBuffer(packetSize);
        int bytesRead = 0;
        while (bytesRead < static_cast<int>(packetSize)) {
            int r = recv(g_ClientActiveSocket, recvBuffer.data() + bytesRead, static_cast<int>(packetSize) - bytesRead, 0);
            if (r <= 0) break; bytesRead += r;
        }
        for (DWORD i = 0; i < packetSize; ++i) recvBuffer[i] ^= ENCRYPTION_KEY;

        if (g_WintunSession && WintunAllocateSendPacket && WintunSendPacket) {
            BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
            if (osPacket) { memcpy(osPacket, recvBuffer.data(), packetSize); WintunSendPacket(g_WintunSession, osPacket); }
        }
    }
    StopNetwork();
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, textGreen);
        SetBkColor(hdc, msg == WM_CTLCOLOREDIT ? darkBox : RGB(5, 15, 5));
        return (LRESULT)(msg == WM_CTLCOLOREDIT ? CreateSolidBrush(darkBox) : hBackBrush);
    }
    case WM_CREATE: {
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, RUSSIAN_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        HWND t1 = CreateWindowW(L"Static", L"ГЛОБАЛЬНЫЙ IP:", WS_VISIBLE | WS_CHILD, 20, 20, 200, 20, hwnd, NULL, NULL, NULL);
        hIpInput = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 45, 180, 25, hwnd, (HMENU)IDC_IP_INPUT, NULL, NULL);

        HWND t2 = CreateWindowW(L"Static", L"ПОРТ:", WS_VISIBLE | WS_CHILD, 220, 20, 60, 20, hwnd, NULL, NULL, NULL);
        hPortInput = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 220, 45, 70, 25, hwnd, (HMENU)IDC_PORT_INPUT, NULL, NULL);

        hBtnServer = CreateWindowW(L"Button", L"[ СОЗДАТЬ СЕТЬ (СЕРВЕР) ]", WS_VISIBLE | WS_CHILD, 20, 90, 230, 35, hwnd, (HMENU)IDC_BTN_SERVER, NULL, NULL);
        hBtnClient = CreateWindowW(L"Button", L"[ ВОЙТИ К ЛОКАЛЬНЫЙ СЕТЬ ]", WS_VISIBLE | WS_CHILD, 265, 90, 230, 35, hwnd, (HMENU)IDC_BTN_CLIENT, NULL, NULL);
        hBtnStop = CreateWindowW(L"Button", L"[ ОТКЛЮЧИТСЯ ]", WS_VISIBLE | WS_CHILD, 510, 90, 150, 35, hwnd, (HMENU)IDC_BTN_STOP, NULL, NULL);

        HWND t4 = CreateWindowW(L"Static", L" ЖУРНАЛ:", WS_VISIBLE | WS_CHILD, 20, 140, 350, 20, hwnd, NULL, NULL, NULL);
        hLogZone = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 20, 165, 640, 180, hwnd, (HMENU)IDC_LOG_ZONE, NULL, NU[...]

