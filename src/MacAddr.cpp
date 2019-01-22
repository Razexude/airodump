
#include "MacAddr.h"

#include <cstdio>

char* MacAddr::toString(char *str, size_t len) const {
    // GC가 안되니까 되게 애매하네... static에 thread를 걸면 성능이 안나올 것 같고... 
    // 그냥 외부에서 delete 해주는 수 밖에. 그럼 변수를 인자로 받는게 낫겠지? 여기서 new해서 리턴하면 leak이 발생할 가능성이 커질 것 같아.
    assert(len >= 18);
    snprintf(str, (len < 18) ? len : 18, "%02x:%02x:%02x:%02x:%02x:%02x", 
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return str;
}

void MacAddr::print() const {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}