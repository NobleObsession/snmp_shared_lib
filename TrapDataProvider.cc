#define LOG_CATEGORY "SyslogUdpDP"
#include <memory>

#include "TrapDataProvider.h"
#include <boost/bind/bind.hpp>

extern "C" IDataProvider *
create() {
    return new TrapDataUdpDP();
}

TrapDataUdpDP::TrapDataUdpDP(){};


TrapDataUdpDP::~TrapDataUdpDP() {
    if ( m_TapOutput.is_open() ) {
        m_TapOutput.flush();
        m_TapOutput.close();
    }
}

void TrapDataUdpDP::ReportMessage( string &IpAddress, string &Message ) {
    if ( m_DoTap ) {
        tapMessage( IpAddress, Message );
    }
}

bool TrapDataUdpDP::Run() {
    try {

        // Construct a signal set registered for process termination.
        boost::asio::signal_set signals( io_service, SIGINT, SIGTERM );
        signals.async_wait( boost::bind( &boost::asio::io_service::stop, &io_service ) );
        if ( m_BindIPAddress == "0.0.0.0" ) {
            // bind to all interfaces
            m_Socket = std::make_shared<udp::socket>( io_service, udp::endpoint( boost::asio::ip::udp::v4(), m_Port ) );
            //MLOG( INFO ) << "Listening  all interfaces on port " << m_Port;
        } else {
            m_Socket = std::make_shared<udp::socket>( io_service,
                                                      udp::endpoint( boost::asio::ip::address::from_string( m_BindIPAddress ), m_Port ) );
            //MLOG( INFO ) << "Listening " << m_BindIPAddress << ":" << m_Port;
        }
    } catch ( exception &ex ) {
        //MLOG( ERROR ) << ex.what();
        return false;
    } catch ( ... ) {
       // MLOG( ERROR ) << "Unhandled exception";
        return false;
    }
    boost::system::error_code      error;
    udp::endpoint                  remote_endpoint;
    boost::array<u_char, 100 * 1024> recv_buf{};
    while ( !m_Interrupted ) {

        //        LOG(TRACE) << "Awaiting for data";
        size_t len = m_Socket->receive_from( boost::asio::buffer( recv_buf ), remote_endpoint, 0, error );
        if ( error && error != boost::asio::error::message_size ) {
           // MLOG( FATAL ) << error.category().name() << ": " << error.value();
            if ( m_ExitOnError ) {
                break;
            };
            continue;
        }

        u_char* data = recv_buf.c_array();

        string parsed_packet = HandleMibPacket(data, len, m_MibDirPath.c_str());

        string ipAddress = remote_endpoint.address().to_string();
        ReportMessage( ipAddress, parsed_packet );
    }

        //MLOG( DEBUG ) << "Socket loop interrupted...";
        if ( m_Socket.get() ) {
           // MLOG( DEBUG ) << "Shutdown socket...";
            m_Socket->shutdown( boost::asio::socket_base::shutdown_receive, error );
            m_Socket->close();
            //MLOG( DEBUG ) << "Shutdown socket done";
        }

        return true;
    }

    bool TrapDataUdpDP::Stop() {
        m_Interrupted = true;
        boost::system::error_code error;
        //MLOG( INFO ) << "Data Provider stop signal received";
        if ( m_Socket.get() ) {
            //        m_Socket->shutdown_receive();
            m_Socket->shutdown( boost::asio::socket_base::shutdown_receive, error );
        }

        return true;
    }

    bool TrapDataUdpDP::Configure( LibraryType::Config config, LibraryType::Config config_override ) {
        auto t_config = getConfigWithDefaults( config, config_override );
        bool valid    = true;
        for ( const auto &kv : t_config ) {
            const string k = kv.first;
            const string v = kv.second;
            if ( k == "port" ) {
                try {
                    m_Port = std::stoi( v );
                } catch ( const std::exception &e ) {
                    /*MLOG( ERROR ) << "Port value "
                                  << "\""
                                  << " is invalid : " << e.what();*/
                valid = false;
                continue;
                }
            }
            if ( k == "address" ) {
                m_BindIPAddress = v;
                continue;
            }
            if ( k == "exit_on_socket_error" ) {
                m_ExitOnError = v == "true";
                continue;
            }
            if ( k == "mib.dir" ) {
                m_MibDirPath = v;
                continue;
            }
            if ( k == "tap.file" ) {
                m_DoTap = true;
                m_TapOutput.open( v, ios::out | ios::app );
            if ( !m_TapOutput.is_open() ) {

                //MLOG( ERROR ) << "Could not open tap-file \"" << v << "\"";
                valid = false;
            }
            continue;
        }
    }
    if ( !m_Port ) {
        //MLOG( ERROR ) << "Listen Port is required";
        valid = false;
    }
    if ( m_BindIPAddress.empty() ) {
       // MLOG( ERROR ) << "Listen Address is required";
        valid = false;
    }
    m_DoTap = m_DoTap & valid;
    return valid;
}
LibraryType::Config TrapDataUdpDP::getConfigWithDefaults( LibraryType::Config config, LibraryType::Config config_override ) {
    LibraryType::Config config_defaults{
            { "port", "515" }, { "address", "0.0.0.0" }, { "exit_on_socket_error", "true" },
            //
    };
    //MLOG( DEBUG ) << "config override " << config_override;
    //MLOG( DEBUG ) << "config input   " << config;
    //MLOG( DEBUG ) << "config default " << config_defaults;
    LibraryType::Config t_config{};
    t_config.merge( config_override );
    t_config.merge( config );
    t_config.merge( config_defaults );
   // MLOG( INFO ) << "Data provider SyslogUdpDP config " << t_config;
    return t_config;
}

/*void TrapDataUdpDP::UpdateStatistics() {
    if ( counters_ == nullptr ) {
        return;
    }
    counters_->events_received++;
}*/

void TrapDataUdpDP::tapMessage( const string &ip_addr, const string &msg ) {
    std::cout << msg << endl;
    m_TapOutput << ip_addr << ' ' << msg << endl; }

