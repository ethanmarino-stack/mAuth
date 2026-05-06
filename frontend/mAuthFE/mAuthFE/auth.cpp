#define _CRT_SECURE_NO_WARNINGS

#include "auth.h"
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <intrin.h>
#include <winhttp.h>
#include <random>
#include <chrono>
#include <thread>
#include <fstream>

#include "auth_state.h"

#pragma comment(lib, "winhttp.lib")

// ========== CHANGE THIS TO YOUR CLOUDFLARE TUNNEL URL ==========
// Get this from running: cloudflared tunnel --url http://localhost:5000
const wchar_t* SERVER_HOST = L"";//YOUR GENERATED URL GOES HERE, EX: "abc-123-xyz.cloudflare tunnels.com";
const int SERVER_PORT = 443;//USE 443 FOR HTTPS, 80 FOR HTTP 
// ================================================================

std::atomic<bool> auth::heartbeat_failed{ false };

static FILE* g_logFile = nullptr;
void DebugLog(const std::string& msg)
{
    if (!g_logFile)
    {
        fopen_s(&g_logFile, "mAuth_debug.log", "w");
    }
    if (g_logFile)
    {
        fprintf(g_logFile, "%s\n", msg.c_str());
        fflush(g_logFile);
    }
    printf("%s\n", msg.c_str());
}

std::string send_http_request(const std::string& endpoint, const std::string& json_data, DWORD timeout_ms)
{
    DebugLog("[HTTP] Sending POST request to: " + endpoint);
    DebugLog("[HTTP] JSON: " + json_data);

    HINTERNET hSession = WinHttpOpen(L"mAuth/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpOpen failed with error: %lu", error);
        DebugLog(errorMsg);
        return "";
    }

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_HOST, SERVER_PORT, 0);
    if (!hConnect)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpConnect failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wEndpoint(endpoint.begin(), endpoint.end());

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        wEndpoint.c_str(),
        NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    if (!hRequest)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpOpenRequest failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    LPCWSTR headers = L"Content-Type: application/json\r\nUser-Agent: mAuth/1.0\r\n";

    BOOL result = WinHttpSendRequest(
        hRequest,
        headers,
        wcslen(headers),
        (LPVOID)json_data.c_str(),
        (DWORD)json_data.size(),
        (DWORD)json_data.size(),
        0);

    if (!result)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpSendRequest failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    result = WinHttpReceiveResponse(hRequest, NULL);

    if (!result)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpReceiveResponse failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::string response;
    char buffer[4096];
    DWORD bytes_read = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0)
    {
        buffer[bytes_read] = '\0';
        response.append(buffer, bytes_read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    DebugLog("[HTTP] Response received, length: " + std::to_string(response.length()));
    if (!response.empty())
    {
        DebugLog("[HTTP] Response: " + response);
    }

    return response;
}

std::string send_http_get(const std::string& endpoint, DWORD timeout_ms)
{
    DebugLog("[HTTP] Sending GET request to: " + endpoint);

    HINTERNET hSession = WinHttpOpen(L"mAuth/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpOpen failed with error: %lu", error);
        DebugLog(errorMsg);
        return "";
    }

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_HOST, SERVER_PORT, 0);
    if (!hConnect)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpConnect failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wEndpoint(endpoint.begin(), endpoint.end());

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wEndpoint.c_str(),
        NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    if (!hRequest)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpOpenRequest failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    BOOL result = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);

    if (!result)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpSendRequest failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    result = WinHttpReceiveResponse(hRequest, NULL);

    if (!result)
    {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[HTTP] WinHttpReceiveResponse failed with error: %lu", error);
        DebugLog(errorMsg);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::string response;
    char buffer[4096];
    DWORD bytes_read = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0)
    {
        buffer[bytes_read] = '\0';
        response.append(buffer, bytes_read);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    DebugLog("[HTTP] GET response length: " + std::to_string(response.length()));
    return response;
}

std::string parse_json_value(const std::string& json, const std::string& key)
{
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";

    pos++;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    if (json[pos] == '"')
    {
        pos++;
        size_t end = json.find('"', pos);
        if (end != std::string::npos)
            return json.substr(pos, end - pos);
    }
    else
    {
        size_t end = json.find_first_of(",}", pos);
        if (end != std::string::npos)
            return json.substr(pos, end - pos);
    }

    return "";
}

std::string auth::get_hwid()
{
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);

    int cpu[4];
    __cpuid(cpu, 1);

    char comp_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD comp_size = sizeof(comp_name);
    GetComputerNameA(comp_name, &comp_size);

    std::stringstream ss;
    ss << std::hex << serial;
    ss << std::hex << cpu[0];
    ss << comp_name;

    std::string hwid = ss.str();
    for (char& c : hwid) c = toupper(c);

    return hwid;
}

bool auth::check_version()
{
    DebugLog("[VERSION] Checking version...");
    std::string response = send_http_get("/get_version", 5000);

    if (response.empty())
    {
        DebugLog("[VERSION] CRITICAL: Failed to check version - exiting");
        return false;
    }

    DebugLog("[VERSION] Full response: " + response);

    std::string server_version = "";

    size_t pos = response.find("\"version\":\"");
    if (pos != std::string::npos)
    {
        pos += 11;
        size_t end = response.find("\"", pos);
        if (end != std::string::npos)
        {
            server_version = response.substr(pos, end - pos);
        }
    }

    if (server_version.empty())
    {
        pos = response.find("\"version\"");
        if (pos != std::string::npos)
        {
            pos = response.find(":", pos);
            if (pos != std::string::npos)
            {
                pos++;
                while (pos < response.length() && (response[pos] == ' ' || response[pos] == '\t')) pos++;
                if (response[pos] == '"')
                {
                    pos++;
                    size_t end = response.find("\"", pos);
                    if (end != std::string::npos)
                    {
                        server_version = response.substr(pos, end - pos);
                    }
                }
            }
        }
    }

    std::string current_version = "1.0.0";

    if (server_version.empty())
    {
        DebugLog("[VERSION] WARNING: Could not parse version, continuing anyway");
        return true;
    }

    if (server_version != current_version)
    {
        DebugLog("[VERSION] Version mismatch! Server: " + server_version + ", Current: " + current_version);
        DebugLog("[VERSION] Please download the latest version!");
        return false;
    }

    DebugLog("[VERSION] Version check passed! (v" + current_version + ")");
    return true;
}

void auth::heartbeat()
{
    int consecutive_failures = 0;

    while (auth_state::heartbeat_running)
    {
        if (!auth_state::logged_in)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        std::string hwid = get_hwid();
        std::string json = "{\"token\":\"" + auth_state::token +
            "\",\"hwid\":\"" + hwid + "\"}";

        std::string response = send_http_request("/heartbeat", json, 10000);

        if (response.empty())
        {
            consecutive_failures++;
            if (consecutive_failures >= 3)
            {
                heartbeat_failed = true;
                auth_state::logged_in = false;
                auth_state::needs_relogin = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        consecutive_failures = 0;

        if (response.find("\"ok\"") == std::string::npos)
        {
            heartbeat_failed = true;
            auth_state::logged_in = false;
            auth_state::needs_relogin = true;
            break;
        }

        for (int i = 0; i < 30 && auth_state::heartbeat_running; i++)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void auth::logout()
{
    if (auth_state::logged_in)
    {
        std::string json = "{\"token\":\"" + auth_state::token + "\"}";
        send_http_request("/logout", json, 3000);

        auth_state::logged_in = false;
        auth_state::token.clear();
        auth_state::username.clear();
        auth_state::uid.clear();
        auth_state::needs_relogin = false;
        heartbeat_failed = false;
    }
}

void auth::shutdown()
{
    auth_state::heartbeat_running = false;
    logout();
    if (g_logFile)
    {
        fclose(g_logFile);
        g_logFile = nullptr;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

bool auth::is_session_valid()
{
    if (!auth_state::logged_in) return false;
    if (heartbeat_failed) return false;
    if (auth_state::needs_relogin) return false;
    return true;
}

std::string auth::get_logged_in_user()
{
    return auth_state::username;
}

std::string auth::get_logged_in_uid()
{
    return auth_state::uid;
}

std::string auth::get_token()
{
    return auth_state::token;
}