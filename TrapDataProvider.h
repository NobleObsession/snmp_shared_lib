#pragma once

#include "IDataProvider.h"
#include "packet_handler.h"

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <fstream>

using boost::asio::ip::udp;

class TrapDataUdpDP : public IDataProvider {
public:
    TrapDataUdpDP();

    ~TrapDataUdpDP() override ;

    bool Run() override;

    bool Stop() override;
    //void UpdateStatistics() override;

    bool Configure( LibraryType::Config config, LibraryType::Config config_override ) override;

private:
    void                       ReportMessage( string &Timestamp, string &IpAddress, string &Message );
    static LibraryType::Config getConfigWithDefaults( LibraryType::Config config, LibraryType::Config config_override );
    void                tapMessage(const string& timestamp, const string& ip_addr,  const string &msg );

    int    m_Port{ 0 };
    string m_BindIPAddress;

    bool                    m_Interrupted{ false };
    bool                    m_ExitOnError{ false };
    shared_ptr<udp::socket> m_Socket;

    boost::asio::io_service io_service;
    bool                    m_DoTap     = false;
    std::ofstream           m_TapOutput;
    std::string             m_MibDirPath;
};
