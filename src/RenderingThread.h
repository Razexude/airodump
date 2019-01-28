#include <functional>
#include <thread>
#include <atomic>

#include "util.h"
#include "AirodumpApInfo.h"

using namespace wlan;

class RenderingThread {
public:
    void threadMain(std::map<MacAddr, AirodumpApInfo>& ap_list, std::atomic_flag& lock) {
        int i = 0;
        while (true) {
            clearConsole();
            printTableHeader();
            while (lock.test_and_set());
            for (auto ap_info = ap_list.begin(); ap_info != ap_list.end(); ++ap_info) {
                std::cout << ap_info->second << std::endl;
            }
            lock.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 0.1sec.
        }
    }
};