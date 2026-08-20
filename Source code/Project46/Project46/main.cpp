#include "network.h"
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <thread>

static std::atomic<bool> g_ShuttingDown(false);

BOOL WINAPI ConsoleHandler(DWORD dwType) {
    if (dwType == CTRL_C_EVENT || dwType == CTRL_CLOSE_EVENT || dwType == CTRL_SHUTDOWN_EVENT) {
        if (!g_ShuttingDown.exchange(true)) {
            LogMessage(L"[SYS] Получен сигнал завершения. Остановка сети...");
            StopNetwork();
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return TRUE;
    }
    return FALSE;
}

void PrintUsage(const char* prog) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " server <port>        # start headless server\n";
    std::cout << "  " << prog << " client <ip> <port>   # start headless client\n";
    std::cout << "  (If you want the GUI, build/run the GUI target which uses WinMain.)\n";
}

int main(int argc, char** argv) {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 0;
    }

    std::string cmd = argv[1];
    if (cmd == "server") {
        if (argc < 3) { PrintUsage(argv[0]); return 1; }
        int port = std::stoi(argv[2]);
        std::cout << "[INFO] Starting server on port " << port << "...\n";
        std::thread t([port]() { StartServer(port); });
        while (!g_ShuttingDown) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (t.joinable()) t.join();
    }
    else if (cmd == "client") {
        if (argc < 4) { PrintUsage(argv[0]); return 1; }
        std::string ip = argv[2];
        int port = std::stoi(argv[3]);

        std::cout << "[INFO] Starting client to " << ip << ":" << port << "...\n";
        std::thread t([ip, port]() {
            StartClient(ip, port);
            });
        while (!g_ShuttingDown) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (t.joinable()) t.join();
    }
    else {
        PrintUsage(argv[0]);
        return 1;
    }

    std::cout << "[INFO] Exiting.\n";
    return 0;
}