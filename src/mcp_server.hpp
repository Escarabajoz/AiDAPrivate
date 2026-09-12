#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <mutex>

class instance_registry_t;

class mcp_server_t
{
public:
    mcp_server_t();
    ~mcp_server_t();

    bool start(int port);
    void stop();
    bool is_running() const;
    int get_port() const;
    void write_mcp_client_configs() const;

    instance_registry_t* registry() const { return _registry.get(); }

private:
    void server_thread_entry(int port);
    void server_thread_finish(unsigned long seh, int port);
    void server_thread_func(int port);

    std::thread _server_thread;
    std::atomic<bool> _running{false};
    std::atomic<bool> _stop_requested{false};
    std::atomic<bool> _bind_failed{false};
    std::atomic<bool> _thread_finished{true};

    void* _active_server = nullptr;
    std::mutex _server_mutex;
    std::atomic<int> _port{0};

    std::unique_ptr<instance_registry_t> _registry;
};
