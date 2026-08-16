#include "network.h"
#include <ws2tcpip.h>
#include <objbase.h>
#include <clocale>

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

    if (g_WintunAdapter) { WintunCloseAdapter(g_WintunAdapter); g_WintunAdapter = nullptr; g_WintunSession = nullptr; }
    WSACleanup();

    LogMessage(L"[STATUS] Туннель полностью отключен.");
    EnableWindow(hBtnServer, TRUE);
    EnableWindow(hBtnClient, TRUE);
}

bool SetupVirtualAdapter(int mode) {
    GUID adapterGuid;
    CoCreateGuid(&adapterGuid);
    g_WintunAdapter = WintunCreateAdapter(L"P2P_Virtual_LAN", L"WintunTunnel", &adapterGuid);
    if (!g_WintunAdapter) { LogMessage(L"[ERR] Требуются права Администратора!"); return false; }
    g_WintunSession = WintunStartSession(g_WintunAdapter, 0x400000);
    if (!g_WintunSession) { WintunCloseAdapter(g_WintunAdapter); return false; }

    LogMessage(L"[OK] Интерфейс Wintun запущен в ядре x64.");
    WinExec("netsh interface set interface name=\"P2P_Virtual_LAN\" admin=enabled", SW_HIDE);

    // Автоматическое назначение IP: Серверу ставим .1, Клиенту ставим .2
    std::string ipStr = (mode == 1) ? "10.8.0.1" : "10.8.0.2";
    std::string ipCmd = "netsh interface ip set address name=\"P2P_Virtual_LAN\" static " + ipStr + " 255.255.255.0";
    WinExec(ipCmd.c_str(), SW_HIDE);

    std::wstring wIpStr(ipStr.begin(), ipStr.end());
    LogMessage(L"[NET] Системой автоматически выделен IP: " + wIpStr);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return true;
}

void AsyncServerThread(int port) {
    if (!SetupVirtualAdapter(1)) return; // 1 = Режим Сервера (IP 10.8.0.1)
    WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

    g_ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int nodelay = 1; setsockopt(g_ListenSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(int));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_ANY); addr.sin_port = htons(static_cast<u_short>(port));
    bind(g_ListenSocket, (SOCKADDR*)&addr, sizeof(addr));
    listen(g_ListenSocket, SOMAXCONN);

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
        DWORD packetSize = 0;
        int res = recv(g_ClientActiveSocket, reinterpret_cast<char*>(&packetSize), sizeof(packetSize), 0);
        if (res <= 0) break;

        std::vector<char> recvBuffer(packetSize);
        int bytesRead = 0;
        while (bytesRead < static_cast<int>(packetSize)) {
            int r = recv(g_ClientActiveSocket, recvBuffer.data() + bytesRead, static_cast<int>(packetSize) - bytesRead, 0);
            if (r <= 0) break; bytesRead += r;
        }
        for (DWORD i = 0; i < packetSize; ++i) recvBuffer[i] ^= ENCRYPTION_KEY;

        BYTE* osPacket = WintunAllocateSendPacket(g_WintunSession, packetSize);
        if (osPacket) { memcpy(osPacket, recvBuffer.data(), packetSize); WintunSendPacket(g_WintunSession, osPacket); }
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
        hLogZone = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 20, 165, 640, 180, hwnd, (HMENU)IDC_LOG_ZONE, NULL, NULL);

        SendMessageW(hIpInput, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(hPortInput, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtnServer, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(hBtnClient, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(hBtnStop, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hLogZone, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(t1, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(t2, WM_SETFONT, (WPARAM)hFont, TRUE); SendMessageW(t4, WM_SETFONT, (WPARAM)hFont, TRUE);

        if (!InitializeWintunDLL()) { LogMessage(L"[ERR] Библиотека wintun.dll x64 не найдена!"); }
        break;
    }
    case WM_COMMAND: {
        int wmId = LOWORD(wp);
        if (wmId == IDC_BTN_SERVER) {
            wchar_t portBuf[32];
            GetWindowTextW(hPortInput, portBuf, 32);
            int port = _wtoi(portBuf);

            EnableWindow(hBtnServer, FALSE); EnableWindow(hBtnClient, FALSE);
            std::thread(AsyncServerThread, port).detach();
        }
        else if (wmId == IDC_BTN_CLIENT) {
            wchar_t ipBuf[64], portBuf[32];
            GetWindowTextW(hIpInput, ipBuf, 64);
            GetWindowTextW(hPortInput, portBuf, 32);

            int port = _wtoi(portBuf);
            std::wstring ws(ipBuf);
            std::string ipStr(ws.begin(), ws.end());

            EnableWindow(hBtnServer, FALSE); EnableWindow(hBtnClient, FALSE);
            std::thread(AsyncClientThread, ipStr, port).detach();
        }
        else if (wmId == IDC_BTN_STOP) {
            StopNetwork();
        }
        break;
    }
    case WM_DESTROY:
        StopNetwork();
        DeleteObject(hBackBrush);
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    std::setlocale(LC_ALL, "Russian");
    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = L"P2P_WINDOW";
    wc.hbrBackground = hBackBrush; wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, L"P2P_WINDOW", L"Объеденение локальных сетей ",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 695, 420, NULL, NULL, hInst, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return (int)msg.wParam;
}