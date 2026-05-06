#pragma once
#include <string>
#include <atomic>

namespace auth_state
{
    inline std::string token;
    inline std::string username;
    inline std::string uid;
    inline bool logged_in = false;
    inline bool show_register = false;
    inline std::atomic<bool> heartbeat_running{ true };
    inline std::atomic<bool> needs_relogin{ false };
}