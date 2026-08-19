#pragma once
#include <string>

// Discover IGD and retrieve control URL + service type + base URL.
// Returns true if discovery succeeded.
bool UPnP_Discover(std::string& outControlURL, std::string& outServiceType, std::string& outBaseURL, int timeoutMs = 3000);

// Get external IP address (returns empty string on failure)
std::string UPnP_GetExternalIPAddress(const std::string& controlURL, const std::string& serviceType, const std::string& baseURL);

// Add port mapping (externalPort -> internalClient:internalPort). proto = "TCP" or "UDP". leaseSeconds: 0 for permanent if router supports.
// Returns true on success.
bool UPnP_AddPortMapping(const std::string& controlURL, const std::string& serviceType,
    const std::string& internalClient, uint16_t internalPort, uint16_t externalPort,
    const std::string& proto, const std::string& description, int leaseSeconds);

// Delete port mapping
bool UPnP_DeletePortMapping(const std::string& controlURL, const std::string& serviceType,
    uint16_t externalPort, const std::string& proto);