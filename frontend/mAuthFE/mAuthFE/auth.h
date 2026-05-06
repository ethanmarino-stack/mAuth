#pragma once
#include <string>
#include <atomic>
#include <windows.h>

// Server configuration (change these for your deployment)
extern const wchar_t* SERVER_HOST;
extern const int SERVER_PORT;

namespace auth
{
    void heartbeat();
    void logout();
    void shutdown();
    bool check_version();
    bool is_session_valid();

    std::string get_hwid();
    std::string get_logged_in_user();
    std::string get_logged_in_uid();
    std::string get_token();

    extern std::atomic<bool> heartbeat_failed;
}

// HTTP helper functions
std::string send_http_request(const std::string& endpoint, const std::string& json_data, DWORD timeout_ms = 10000);
std::string parse_json_value(const std::string& json, const std::string& key);
std::string send_http_get(const std::string& endpoint, DWORD timeout_ms = 10000);