#include <iostream>

#include "TrapDataProvider.h"

int main()
{
    auto trap_provider = make_shared<TrapDataUdpDP>();

    std::map<std::string, std::string> my_config = {
            {"port", "1162"},
            {"tap.file", "tap_tap2.txt"},
            {"mib.dir", "mibs_combined"}
    };

    trap_provider->Configure(my_config, {});
    trap_provider->Run();
    return 0;
}
