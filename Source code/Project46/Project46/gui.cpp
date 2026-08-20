#include "network.h"
#include <windows.h>
#include <string>
#include <thread>
#include <locale>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

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

static std::string WStringToString(const std::wstring& ws) {
    return std::string(ws.begin(), ws.end());
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
        HFONT hFont = CreateFontW(
            16, 0, 0, 0, FW_BOLD,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");

        g_hBackBrush = CreateSolidBrush(RGB(5, 15, 5));

        CreateWindowW(L"Static", L"ГЛОБАЛЬНЫЙ IP:", WS_VISIBLE | WS_CHILD, 20, 20, 200, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 45, 180, 25, hwnd, (HMENU)IDC_IP_INPUT, NULL, NULL);

        CreateWindowW(L"Static", L"ПОРТ:", WS_VISIBLE | WS_CHILD, 220, 20, 60, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER, 220, 45, 70, 25, hwnd, (HMENU)IDC_PORT_INPUT, NULL, NULL);

        CreateWindowW(L"Button", L"[ СОЗДАТЬ СЕТЬ (СЕРВЕР) ]", WS_VISIBLE | WS_CHILD, 20, 90, 230, 35, hwnd, (HMENU)IDC_BTN_SERVER, NULL, NULL);
        CreateWindowW(L"Button", L"[ ВОЙТИ К ЛОКАЛЬНЫЙ СЕТЬ ]", WS_VISIBLE | WS_CHILD, 265, 90, 230, 35, hwnd, (HMENU)IDC_BTN_CLIENT, NULL, NULL);
        CreateWindowW(L"Button", L"[ ОТКЛЮЧИТЬСЯ ]", WS_VISIBLE | WS_CHILD, 510, 90, 150, 35, hwnd, (HMENU)IDC_BTN_STOP, NULL, NULL);

        CreateWindowW(L"Static", L" ЖУРНАЛ:", WS_VISIBLE | WS_CHILD, 20, 140, 350, 20, hwnd, NULL, NULL, NULL);
        HWND hLog = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 20, 165, 640, 180, hwnd, (HMENU)IDC_LOG_ZONE, NULL, NULL);

        // UPnP checkbox (как раньше)
        CreateWindowW(L"Button", L"Использовать UPnP", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            20, 360, 200, 20, hwnd, (HMENU)IDC_UPNP, NULL, NULL);

        // Установить шрифт для новых контролов (предполагается, что hFont уже создан выше)
        SendMessageW(GetDlgItem(hwnd, IDC_UPNP), WM_SETFONT, (WPARAM)hFont, TRUE);
        // метка статическая наследует системный шрифт; если нужно, можно тоже явно задать:
        SendMessageW(GetDlgItem(hwnd, IDC_LOG_ZONE), WM_SETFONT, (WPARAM)hFont, TRUE);

        hLogZone = hLog; // extern used by network logging

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

            // read custom mask value into global
            LRESULT maskLen = GetWindowTextLengthW(GetDlgItem(hwnd, IDC_MASK_INPUT));
            std::wstring wmask(maskLen + 1, L'\0');
            GetWindowTextW(GetDlgItem(hwnd, IDC_MASK_INPUT), &wmask[0], (int)wmask.size());
            wmask.resize(maskLen);
            {
                std::lock_guard<std::mutex> lg(g_CustomMaskMutex);
                g_CustomSubnetMask = WStringToString(wmask);
            }
            // read checkbox state
            LRESULT stateMask = SendMessageW(GetDlgItem(hwnd, IDC_USE_CUSTOM_MASK), BM_GETCHECK, 0, 0);
            g_UseCustomSubnetMask.store(stateMask == BST_CHECKED);

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

            // read custom mask value into global
            LRESULT maskLen = GetWindowTextLengthW(GetDlgItem(hwnd, IDC_MASK_INPUT));
            std::wstring wmask(maskLen + 1, L'\0');
            GetWindowTextW(GetDlgItem(hwnd, IDC_MASK_INPUT), &wmask[0], (int)wmask.size());
            wmask.resize(maskLen);
            {
                std::lock_guard<std::mutex> lg(g_CustomMaskMutex);
                g_CustomSubnetMask = WStringToString(wmask);
            }
            LRESULT stateMask = SendMessageW(GetDlgItem(hwnd, IDC_USE_CUSTOM_MASK), BM_GETCHECK, 0, 0);
            g_UseCustomSubnetMask.store(stateMask == BST_CHECKED);

            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SERVER), FALSE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLIENT), FALSE);
            StartClientThread(ipStr, port);
        }
        else if (id == IDC_BTN_STOP) {
            StopNetwork();
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_SERVER), TRUE);
            EnableWindow(GetDlgItem(hwnd, IDC_BTN_CLIENT), TRUE);
        }
        else if (id == IDC_UPNP) {
            LRESULT state = SendMessageW(GetDlgItem(hwnd, IDC_UPNP), BM_GETCHECK, 0, 0);
            g_UseUPnP.store(state == BST_CHECKED);
            if (g_UseUPnP.load()) LogMessage(L"[SET] UPnP включён");
            else LogMessage(L"[SET] UPnP выключен");
        }
        else if (id == IDC_USE_CUSTOM_MASK) {
            LRESULT state = SendMessageW(GetDlgItem(hwnd, IDC_USE_CUSTOM_MASK), BM_GETCHECK, 0, 0);
            g_UseCustomSubnetMask.store(state == BST_CHECKED);
            if (g_UseCustomSubnetMask.load()) LogMessage(L"[SET] Используется свой маска подсети");
            else LogMessage(L"[SET] Используется маска по умолчанию");
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
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 695, 460, NULL, NULL, hInst, NULL);
    if (!hwnd) return 0;
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return static_cast<int>(msg.wParam);
}