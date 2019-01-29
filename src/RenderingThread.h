#include <functional>
#include <thread>
#include <atomic>
#include <iomanip>

#include "AirodumpApInfo.h"
#include "AirodumpStationInfo.h"

using namespace wlan;
using namespace std;
using namespace chrono;

class RenderingThread {
public:
    void threadMain(std::map<MacAddr, AirodumpApInfo>& ap_list, 
                    std::map<MacAddr, AirodumpStationInfo>& station_list, 
                    std::atomic_flag& lock,
                    char* dev) {
        char channel_hopping_cmd[40];
        std::vector<int> channel_list = {1, 7, 13, 2, 8, 14, 3, 9, 4, 10, 5, 11, 6, 12};
        int ch_idx = 0;
        system_clock::time_point start = system_clock::now();
        system_clock::time_point now;
        time_t now_tt;
        duration<double> elapsed_seconds;
        int i = 0;

        while (true) {
            clearConsole();

            now = system_clock::now();
            now_tt = system_clock::to_time_t(now);
            elapsed_seconds = now - start;
            cout << "\n CH  " << setw(2) << channel_list[ch_idx] << " ][ Elapsed: " << int(elapsed_seconds.count()) << " s ][ " << 
                    put_time(localtime(&now_tt), "%c");
            printf("\n\n BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID\n\n");

            while (lock.test_and_set());  // spin
            for (auto ap_info = ap_list.begin(); ap_info != ap_list.end(); ++ap_info) {
                std::cout << ap_info->second << std::endl;
            }
            
            printf("\n BSSID              STATION            PWR   Rate    Lost    Frames  Probe     \n\n");
            for (auto station_info = station_list.begin(); station_info != station_list.end(); ++station_info) {
                std::cout << station_info->second << std::endl;
            }
            
            if (i > 12) {
                i = 0;
                // channel hopping ; INT_NAME_MAX = 16
                snprintf(channel_hopping_cmd, 39, "iw dev %s set channel %d", dev, channel_list[ch_idx]);
                int ret = system(channel_hopping_cmd);
                if (ret == 0) {
                    ch_idx = (ch_idx + 1) % 14;
                }
                else {
                    // something wrong.
                }
            }
            
            i++;
            lock.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // 0.05sec.
        }
    }
    

    void clearConsole() {
        std::cout << "\x1B[2J\x1B[H";
    }
};