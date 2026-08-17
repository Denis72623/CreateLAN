#include "network.h"
#include <windows.h>
#include <string>
#include <thread>
#include <locale>
#include <codecvt>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// Note: hLogZone is declared extern in network.h and used by LogMessage there.
// Do NOT redeclare hLogZone here; we will assign the control HWND to the extern variable.

HBRUSH g_hBackBrush = nullptr;
COLORREF g_textGreen = RGB(0, 255, 65);
COLORREF g_darkBox = RGB(15, 35, 15);

void StartServerThread(int port) {
    std::thread t([port]() { StartServer(port); });
    t.detach();
}

void StartClientThread(const std::string& ip, int port) {
    std::thread t([ip, port]() { StartClient(ip, port); });
    t.detach();
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, g_textGreen);
        SetBkColor(hdc, (msg == WM_CTLCOLOREDIT) ? g_darkBox : RGB(5, 15, 5));
        HBRUSH brush = (HBRUSH)(msg == WM_CTLCOLOREDIT ? CreateSolidBrush(g_darkBox) : g_hBackBrush);
        return (LRESULT)brush;
    }
    case WM_CREATE: {
        // UI font
        HFONT hFont = CreateFontW(
            16, 0, 0, 0, FW_BOLD,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");

        g_hBackBrush = CreateSolidBrush(RGB(5, 15, 5));

        CreateWindowW(L"Static", L"ГЛОБАЛЬНЫЙ IP:", WS_VISIBLE | WS_CHILD, 20, 20, 200, 20, hwnd, NULL, NULL, NULL);
        HWND hIpInput = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 45, 180, 25, hwnd, (HMENU)IDC_IP_INPUT, NULL, NULL);

        CreateWindowW(L"Static", L"ПОРТ:", WS_VISIBLE | WS_CHILD, 220, 20, 60, 20, hwnd, NULL, NULL, NULL);
        HWND hPortInput = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 220, 45, 70, 25, hwnd, (HMENU)IDC_PORT_INPUT, NULL, NULL);

        HWND hBtnServer = CreateWindowW(L"Button", L"[ СОЗДАТЬ СЕТЬ (СЕРВЕР) ]", WS_VISIBLE | WS_CHILD, 20, 90, 230, 35, hwnd, (HMENU)IDC_BTN_SERVER, NULL, NULL);
        HWND hBtnClient = CreateWindowW(L"Button", L"[ ВОЙТИ К ЛОКАЛЬНЫЙ СЕТЬ ]", WS_VISIBLE | WS_CHILD, 265, 90, 230, 35, hwnd, (HMENU)IDC_BTN_CLIENT, NULL, NULL);
        HWND hBtnStop = CreateWindowW(L"Button", L"[ ОТКЛЮЧИТЬСЯ ]", WS_VISIBLE | WS_CHILD, 510, 90, 150, 35, hwnd, (HMENU)IDC_BTN_STOP, NULL, NULL);

        CreateWindowW(L"Static", L" ЖУРНАЛ:", WS_VISIBLE | WS_CHILD, 20, 140, 350, 20, hwnd, NULL, NULL, NULL);
        HWND hLog = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 20, 165, 640, 180, hwnd, (HMENU)IDC_LOG_ZONE, NULL, NULL);

        // set fonts
        SendMessageW(hIpInput, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hPortInput, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtnServer, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtnClient, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtnStop, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hLog, WM_SETFONT, (WPARAM)hFont, TRUE);

        // expose the log control to network logging
        hLogZone = hLog; // extern from network.h

        if (!InitializeWintunDLL()) {
            LogMessage(L"[ERR] Библиотека wintun.dll x64 не найдена!");
        }
        else {
            LogMessage(L"[OK] wintun.dll загружена.");
        }
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_BTN_SERVER) {
            wchar_t portBuf[32]; GetWindowTextW(GetDlgItem(hwnd, IDC_PORT_INPUT), portBuf, _countof(portBuf));
            int port = _wtoi(portBuf);
            // disable start buttons to avoid double start
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SERVER), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLIENT), FALSE);
            StartServerThread(port);
        }
        else if (id == IDC_BTN_CLIENT) {
            wchar_t ipBuf[64], portBuf[32];
            GetWindowTextW(GetDlgItem(hwnd, IDC_IP_INPUT), ipBuf, _countof(ipBuf));
            GetWindowTextW(GetDlgItem(hwnd, IDC_PORT_INPUT), portBuf, _countof(portBuf));
            int port = _wtoi(portBuf);
            std::wstring ws(ipBuf);
            std::string ipStr(ws.begin(), ws.end());
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SERVER), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLIENT), FALSE);
            StartClientThread(ipStr, port);
        }
        else if (id == IDC_BTN_STOP) {
            StopNetwork();
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SERVER), TRUE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLIENT), TRUE);
        }
        break;
    }
    case WM_DESTROY:
        StopNetwork();
        if (g_hBackBrush) { DeleteObject(g_hBackBrush); g_hBackBrush = nullptr; }
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
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, L"P2P_WINDOW", L"Объединение локальных сетей",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 695, 420, NULL, NULL, hInst, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return static_cast<int>(msg.wParam);
}