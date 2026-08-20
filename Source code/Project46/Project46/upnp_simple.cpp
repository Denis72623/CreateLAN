#include "upnp_simple.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <thread>
#include <chrono>
#include <cstdio>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Iphlpapi.lib")

// Local lightweight logger
static void upnp_local_log(const char* msg) {
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
    printf("%s\n", msg);
}

// Simple HTTP GET using WinHTTP, returns response body or empty string on error
static std::string http_get(const std::string& url, int /*timeoutMs*/ = 5000) {
    std::string proto, host, path;
    unsigned short port = 80;
    if (url.rfind("http://", 0) == 0) { proto = "http"; host = url.substr(7); port = 80; }
    else if (url.rfind("https://", 0) == 0) { proto = "https"; host = url.substr(8); port = 443; }
    else return {};

    size_t pos = host.find('/');
    if (pos != std::string::npos) { path = host.substr(pos); host = host.substr(0, pos); }
    else path = "/";

    size_t col = host.find(':');
    if (col != std::string::npos) {
        port = static_cast<unsigned short>(std::stoi(host.substr(col + 1)));
        host = host.substr(0, col);
    }

    HINTERNET hSession = WinHttpOpen(L"upnp-simple/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return {};
    DWORD dwFlags = 0;
    if (proto == "https") dwFlags = WINHTTP_FLAG_SECURE;
    std::wstring wHost(host.begin(), host.end());
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return {}; }
    std::wstring wPath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return {}; }

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return {}; }
    ok = WinHttpReceiveResponse(hRequest, nullptr);
    if (!ok) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return {}; }

    std::string result;
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD dwRead = 0;
        if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead) && dwRead > 0) {
            result.append(buffer.data(), (size_t)dwRead);
        }
        else break;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

// Find the first occurrence of <tag>value</tag> (simple string-based search)
static std::string find_xml_tag_value(const std::string& xml, const std::string& tag, size_t start = 0) {
    std::string open = "<" + tag;
    auto p = xml.find(open, start);
    if (p == std::string::npos) return {};
    auto q = xml.find('>', p);
    if (q == std::string::npos) return {};
    if (xml[q - 1] == '/') return {}; // self-closing
    q++;
    auto r = xml.find("</" + tag + ">", q);
    if (r == std::string::npos) return {};
    return xml.substr(q, r - q);
}

// Send SSDP M-SEARCH bound to each IPv4 local address, return first LOCATION header value
static bool send_ssdp_msearch(std::string& outLocation, int timeoutMs) {
    outLocation.clear();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        upnp_local_log("WSAStartup failed");
        return false;
    }

    const char* msearchTemplate =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: %s\r\n"
        "\r\n";
    const char* stValues[] = {
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "ssdp:all"
    };

    // enumerate adapters
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG buflen = 0;
    GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &buflen);
    if (buflen == 0) {
        upnp_local_log("GetAdaptersAddresses returned no buffer length");
        WSACleanup();
        return false;
    }
    std::vector<uint8_t> buffer(buflen);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    if (GetAdaptersAddresses(AF_UNSPEC, flags, NULL, adapters, &buflen) != NO_ERROR) {
        upnp_local_log("GetAdaptersAddresses failed");
        WSACleanup();
        return false;
    }

    // iterate adapters and their unicast IPv4 addresses
    for (PIP_ADAPTER_ADDRESSES aa = adapters; aa; aa = aa->Next) {
        if ((aa->OperStatus != IfOperStatusUp) || (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK)) continue;
        for (PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            SOCKADDR* sa = ua->Address.lpSockaddr;
            if (!sa) continue;
            if (sa->sa_family != AF_INET) continue; // only IPv4
            sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(sa);
            char localIp[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &sin->sin_addr, localIp, sizeof(localIp));

            SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (s == INVALID_SOCKET) continue;

            BOOL reuse = TRUE;
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

            sockaddr_in bindAddr{};
            bindAddr.sin_family = AF_INET;
            inet_pton(AF_INET, localIp, &bindAddr.sin_addr);
            bindAddr.sin_port = htons(0);
            if (bind(s, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
                closesocket(s);
                continue;
            }

            sockaddr_in dest{};
            dest.sin_family = AF_INET;
            dest.sin_port = htons(1900);
            inet_pton(AF_INET, "239.255.255.250", &dest.sin_addr);

            // send M-SEARCH for multiple ST values
            for (const char* st : stValues) {
                char msearch[512];
                int len = snprintf(msearch, sizeof(msearch), msearchTemplate, st);
                for (int i = 0; i < 3; ++i) {
                    int sent = sendto(s, msearch, len, 0, (sockaddr*)&dest, sizeof(dest));
                    char logbuf[256];
                    if (sent == SOCKET_ERROR) sprintf_s(logbuf, "sendto err on %s: %d", localIp, WSAGetLastError());
                    else sprintf_s(logbuf, "sendto ok on %s bytes=%d", localIp, sent);
                    upnp_local_log(logbuf);
                    std::this_thread::sleep_for(std::chrono::milliseconds(150));
                }
            }

            // wait for replies on this socket
            int waited = 0;
            const int step = 200;
            char recvbuf[8192];
            fd_set readSet;
            while (waited < timeoutMs) {
                FD_ZERO(&readSet);
                FD_SET(s, &readSet);
                timeval tv; tv.tv_sec = step / 1000; tv.tv_usec = (step % 1000) * 1000;
                int sel = select((int)(s + 1), &readSet, NULL, NULL, &tv);
                if (sel > 0 && FD_ISSET(s, &readSet)) {
                    sockaddr_in from{};
                    int fromLen = sizeof(from);
                    int r = recvfrom(s, recvbuf, (int)sizeof(recvbuf) - 1, 0, (sockaddr*)&from, &fromLen);
                    if (r > 0) {
                        recvbuf[r] = 0;
                        std::string resp(recvbuf);
                        auto findHeader = [&](const std::string& key)->std::string {
                            size_t pos = resp.find(key);
                            if (pos == std::string::npos) return {};
                            pos += key.size();
                            while (pos < resp.size() && (resp[pos] == ' ' || resp[pos] == '\t')) ++pos;
                            size_t e = resp.find("\r\n", pos);
                            if (e == std::string::npos) e = resp.size();
                            std::string val = resp.substr(pos, e - pos);
                            while (!val.empty() && (val.back() == '\r' || val.back() == '\n' || val.back() == ' ')) val.pop_back();
                            return val;
                            };
                        std::string loc = findHeader("\r\nLOCATION:"); if (loc.empty()) loc = findHeader("\r\nLocation:");
                        if (loc.empty()) { loc = findHeader("LOCATION:"); if (loc.empty()) loc = findHeader("Location:"); }
                        char fromIp[64]; inet_ntop(AF_INET, &from.sin_addr, fromIp, sizeof(fromIp));
                        char tbuf[512]; sprintf_s(tbuf, "recvfrom on %s from=%s len=%d loc=%s", localIp, fromIp, r, loc.c_str());
                        upnp_local_log(tbuf);
                        if (!loc.empty()) {
                            outLocation = loc;
                            closesocket(s);
                            WSACleanup();
                            return true;
                        }
                    }
                }
                waited += step;
            }

            closesocket(s);
        }
    }

    WSACleanup();
    upnp_local_log("send_ssdp_msearch: timeout, no LOCATION received on any interface");
    return false;
}

// SOAP POST helper using WinHTTP
static bool soap_post(const std::string& controlURL, const std::string& serviceType, const std::string& action, const std::string& body, std::string& outResponse) {
    std::string proto, host, path;
    unsigned short port = 80;
    if (controlURL.rfind("http://", 0) == 0) { proto = "http"; host = controlURL.substr(7); port = 80; }
    else if (controlURL.rfind("https://", 0) == 0) { proto = "https"; host = controlURL.substr(8); port = 443; }
    else return false;
    size_t pos = host.find('/');
    if (pos != std::string::npos) { path = host.substr(pos); host = host.substr(0, pos); }
    else path = "/";
    size_t col = host.find(':');
    if (col != std::string::npos) { port = (unsigned short)std::stoi(host.substr(col + 1)); host = host.substr(0, col); }

    std::wstring wHost(host.begin(), host.end());
    std::wstring wPath(path.begin(), path.end());
    HINTERNET hSession = WinHttpOpen(L"upnp-soap/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    DWORD dwFlags = 0;
    if (proto == "https") dwFlags = WINHTTP_FLAG_SECURE;
    HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::string soapAction = "\"" + serviceType + "#" + action + "\"";
    std::ostringstream headers;
    headers << "Content-Type: text/xml; charset=\"utf-8\"\r\n";
    headers << "SOAPACTION: " << soapAction << "\r\n";
    std::string hdrs = headers.str();
    std::wstring whdrs(hdrs.begin(), hdrs.end());

    BOOL ok = WinHttpSendRequest(hRequest, whdrs.c_str(), (DWORD)whdrs.size(), (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    ok = WinHttpReceiveResponse(hRequest, nullptr);
    if (!ok) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::string result;
    DWORD dwSize = 0;
    do {
        dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1);
        DWORD dwRead = 0;
        if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwRead) && dwRead > 0) {
            result.append(buffer.data(), (size_t)dwRead);
        }
        else break;
    } while (dwSize > 0);

    outResponse = result;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

// Public API implementations

bool UPnP_Discover(std::string& outControlURL, std::string& outServiceType, std::string& outBaseURL, int timeoutMs) {
    outControlURL.clear(); outServiceType.clear(); outBaseURL.clear();

    std::string location;
    if (!send_ssdp_msearch(location, timeoutMs)) {
        upnp_local_log("UPnP_Discover: SSDP discovery failed");
        return false;
    }

    std::string desc = http_get(location, 4000);
    if (desc.empty()) {
        upnp_local_log("UPnP_Discover: failed to GET description");
        return false;
    }

    std::string urlBase = find_xml_tag_value(desc, "URLBase");
    if (urlBase.empty()) {
        size_t pos = location.find("://");
        if (pos == std::string::npos) return false;
        pos += 3;
        size_t slash = location.find('/', pos);
        if (slash == std::string::npos) urlBase = location;
        else urlBase = location.substr(0, slash);
    }
    outBaseURL = urlBase;

    size_t pos = 0;
    while (true) {
        size_t svc = desc.find("<service>", pos);
        if (svc == std::string::npos) break;
        size_t svcEnd = desc.find("</service>", svc);
        if (svcEnd == std::string::npos) break;
        std::string svcBlock = desc.substr(svc, svcEnd - svc + 10);
        std::string st = find_xml_tag_value(svcBlock, "serviceType");
        if (st.find("WANIPConnection") != std::string::npos || st.find("WANPPPConnection") != std::string::npos) {
            std::string control = find_xml_tag_value(svcBlock, "controlURL");
            if (!control.empty()) {
                if (control.rfind("http://", 0) == 0 || control.rfind("https://", 0) == 0) {
                    outControlURL = control;
                }
                else {
                    std::string base = outBaseURL;
                    if (!base.empty() && base.back() == '/') base.pop_back();
                    if (control.front() != '/') outControlURL = base + "/" + control;
                    else outControlURL = base + control;
                }
                outServiceType = st;
                return true;
            }
        }
        pos = svcEnd + 10;
    }

    upnp_local_log("UPnP_Discover: no suitable service found in description");
    return false;
}

std::string UPnP_GetExternalIPAddress(const std::string& controlURL, const std::string& serviceType, const std::string& /*baseURL*/) {
    std::ostringstream body;
    body << "<?xml version=\"1.0\"?>\r\n";
    body << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">";
    body << "<s:Body>";
    body << "<u:GetExternalIPAddress xmlns:u=\"" << serviceType << "\"/>";
    body << "</s:Body></s:Envelope>";
    std::string resp;
    if (!soap_post(controlURL, serviceType, "GetExternalIPAddress", body.str(), resp)) return {};
    std::string tag = "NewExternalIPAddress";
    auto p = resp.find("<" + tag + ">");
    if (p == std::string::npos) return {};
    p += tag.size() + 2;
    auto q = resp.find("</" + tag + ">", p);
    if (q == std::string::npos) return {};
    return resp.substr(p, q - p);
}

bool UPnP_AddPortMapping(const std::string& controlURL, const std::string& serviceType,
    const std::string& internalClient, uint16_t internalPort, uint16_t externalPort,
    const std::string& proto, const std::string& description, int leaseSeconds) {

    std::ostringstream body;
    body << "<?xml version=\"1.0\"?>\r\n";
    body << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">";
    body << "<s:Body>";
    body << "<u:AddPortMapping xmlns:u=\"" << serviceType << "\">";
    body << "<NewRemoteHost></NewRemoteHost>";
    body << "<NewExternalPort>" << externalPort << "</NewExternalPort>";
    body << "<NewProtocol>" << proto << "</NewProtocol>";
    body << "<NewInternalPort>" << internalPort << "</NewInternalPort>";
    body << "<NewInternalClient>" << internalClient << "</NewInternalClient>";
    body << "<NewEnabled>1</NewEnabled>";
    body << "<NewPortMappingDescription>" << description << "</NewPortMappingDescription>";
    body << "<NewLeaseDuration>" << leaseSeconds << "</NewLeaseDuration>";
    body << "</u:AddPortMapping>";
    body << "</s:Body></s:Envelope>";

    std::string resp;
    if (!soap_post(controlURL, serviceType, "AddPortMapping", body.str(), resp)) return false;
    if (resp.find("fault") != std::string::npos) return false;
    return true;
}

bool UPnP_DeletePortMapping(const std::string& controlURL, const std::string& serviceType,
    uint16_t externalPort, const std::string& proto) {

    std::ostringstream body;
    body << "<?xml version=\"1.0\"?>\r\n";
    body << "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">";
    body << "<s:Body>";
    body << "<u:DeletePortMapping xmlns:u=\"" << serviceType << "\">";
    body << "<NewRemoteHost></NewRemoteHost>";
    body << "<NewExternalPort>" << externalPort << "</NewExternalPort>";
    body << "<NewProtocol>" << proto << "</NewProtocol>";
    body << "</u:DeletePortMapping>";
    body << "</s:Body></s:Envelope>";

    std::string resp;
    if (!soap_post(controlURL, serviceType, "DeletePortMapping", body.str(), resp)) return false;
    if (resp.find("fault") != std::string::npos) return false;
    return true;
}