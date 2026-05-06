#include <cstdint>
#include <chrono>
#include <thread>
#include <string>
#include <cstdio>
#include <Windows.h>
#include <vector>
#include <sstream>

// Auth headers
#include "auth.h"
#include "auth_state.h"

// Forward declarations for HTTP functions
std::string send_http_request(const std::string& endpoint, const std::string& json_data, DWORD timeout_ms);
std::string parse_json_value(const std::string& json, const std::string& key);

bool ConsoleLogin()
{
    char username[64] = { 0 };
    char password[64] = { 0 };
    char license_key[64] = { 0 };
    bool show_register = false;

    while (!auth_state::logged_in)
    {
        system("cls");
        printf("\n");
        printf("========================================\n");
        printf("      Ethan - mAuth - Login          \n");
        printf("========================================\n");
        printf("\n");

        if (!show_register)
        {
            printf("[1] Login\n");
            printf("[2] Register\n");
            printf("[0] Exit\n");
            printf("\n");
            printf("Choice: ");

            int choice;
            scanf_s("%d", &choice);

            if (choice == 0)
            {
                return false;
            }
            else if (choice == 2)
            {
                show_register = true;
                continue;
            }
            else if (choice == 1)
            {
                printf("\nUsername: ");
                scanf_s("%s", username, (unsigned)_countof(username));
                printf("Password: ");
                scanf_s("%s", password, (unsigned)_countof(password));

                std::string hwid = auth::get_hwid();
                std::string json = "{\"username\":\"" + std::string(username) +
                    "\",\"password\":\"" + std::string(password) +
                    "\",\"hwid\":\"" + hwid + "\"}";

                std::string response = send_http_request("/login", json);

                if (response.find("\"ok\"") != std::string::npos)
                {
                    auth_state::token = parse_json_value(response, "token");
                    auth_state::username = parse_json_value(response, "username");
                    auth_state::uid = parse_json_value(response, "uid");
                    auth_state::logged_in = true;
                    printf("\n[SUCCESS] Login successful!\n");
                    Sleep(2000);
                    return true;
                }
                else if (response.find("hwid_mismatch") != std::string::npos)
                {
                    printf("\n[ERROR] HWID mismatch - Account locked to another computer!\n");
                    Sleep(2000);
                }
                else
                {
                    printf("\n[ERROR] Invalid credentials!\n");
                    Sleep(2000);
                }
            }
        }
        else
        {
            printf("[1] Register\n");
            printf("[2] Back to Login\n");
            printf("[0] Exit\n");
            printf("\n");
            printf("Choice: ");

            int choice;
            scanf_s("%d", &choice);

            if (choice == 0)
            {
                return false;
            }
            else if (choice == 2)
            {
                show_register = false;
                continue;
            }
            else if (choice == 1)
            {
                printf("\nUsername (3-20 chars): ");
                scanf_s("%s", username, (unsigned)_countof(username));
                printf("Password (min 4 chars): ");
                scanf_s("%s", password, (unsigned)_countof(password));
                printf("License Key: ");
                scanf_s("%s", license_key, (unsigned)_countof(license_key));

                std::string hwid = auth::get_hwid();
                std::string json = "{\"username\":\"" + std::string(username) +
                    "\",\"password\":\"" + std::string(password) +
                    "\",\"license_key\":\"" + std::string(license_key) +
                    "\",\"hwid\":\"" + hwid + "\"}";

                std::string response = send_http_request("/register", json);

                if (response.find("\"ok\"") != std::string::npos)
                {
                    auth_state::token = parse_json_value(response, "token");
                    auth_state::username = parse_json_value(response, "username");
                    auth_state::uid = parse_json_value(response, "uid");
                    auth_state::logged_in = true;
                    printf("\n[SUCCESS] Registration successful!\n");
                    Sleep(2000);
                    return true;
                }
                else
                {
                    std::string error = parse_json_value(response, "message");
                    if (error.empty()) error = "Registration failed";
                    printf("\n[ERROR] %s\n", error.c_str());
                    Sleep(2000);
                }
            }
        }
    }
    return true;
}

int main()
{
    // Set console codepage to UTF-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    printf("[AUTH] Checking version...\n");
    if (!auth::check_version())
    {
        printf("[AUTH] Update required. Exiting...\n");
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return 1;
    }

    printf("[AUTH] Version check passed!\n");
    printf("[AUTH] Starting login...\n");

    if (!ConsoleLogin())
    {
        printf("[AUTH] Login cancelled. Exiting...\n");
        return 0;
    }

    printf("\n========================================\n");
    printf("[AUTH] Login successful!\n");
    printf("[AUTH] Welcome, %s!\n", auth_state::username.c_str());
    printf("[AUTH] UID: %s\n", auth_state::uid.c_str());
    printf("========================================\n\n");

    // Start heartbeat thread
    std::thread heartbeat_thread([]() { auth::heartbeat(); });
    heartbeat_thread.detach();

    printf("[AUTH] Session is active. Press ENTER to exit...\n");
    printf("[AUTH] Your session will stay alive until you exit.\n");

    // Wait for Enter key
    while (auth::is_session_valid())
    {
        if (GetAsyncKeyState(VK_RETURN) & 1)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Print a dot every 5 seconds to show it's alive
        static int counter = 0;
        counter++;
        if (counter >= 50)
        {
            counter = 0;
            printf(".");
        }
    }

    printf("\n\n[AUTH] Shutting down...\n");
    auth::shutdown();

    return 0;
}