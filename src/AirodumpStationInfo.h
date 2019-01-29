#ifndef AIRODUMPSTATIONINFO_H
#define AIRODUMPSTATIONINFO_H


class AirodumpStationInfo {
public:
    MacAddr      bssid;
    MacAddr      station;
    int          pwr = -1;
    unsigned int rate = 0;
    unsigned int lost = 0;
    unsigned int frames = 0;
    std::string  probe;
    
    AirodumpStationInfo() {}
    AirodumpStationInfo(MacAddr _station): station(_station) {}

    friend std::ostream& operator<<(std::ostream& os, AirodumpStationInfo& obj) {
        std::string bssid = (obj.bssid == MacAddr::BROADCAST) ? "(not associated)" : (std::string)obj.bssid;
        return os << " " << obj.bssid << 
                    "  " << obj.station <<
                    std::setw(5) << obj.pwr << " " << 
                    std::setw(8) << obj.rate << " " << 
                    std::setw(8) << obj.lost << " " <<
                    std::setw(4) << obj.frames << " ";
                    // std::setw(3) << obj.probe << "  " <<
    }

};

#endif