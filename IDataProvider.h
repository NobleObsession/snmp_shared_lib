#ifndef NGNETMS_IDATAPROVIDER
#define NGNETMS_IDATAPROVIDER

//#include "IEventCounters.h"
#include "LibraryType.h"
#include <chrono>
#include <map>
#include <ostream>
#include <string>
#include <utility>
using namespace std;
typedef chrono::time_point<chrono::system_clock, chrono::milliseconds> Timestamp;
namespace EventDataProvider {
    enum DataType {
        DATA, // Data received.
        // Data types:
        // 1. strings for text file
        // 2. PDUs for UDP
        // 3. Stream for TCP
        END_OF_DATA,     // File provider only.
        SOURCE_ATTACHED, // TCP provider only. Sends on new client connected to the TCP server
        SOURCE_DETTACHED // TCP provider only. Sends on client disconnected from the TCP server
    };
    inline ostream &operator<<( ostream &os, const EventDataProvider::DataType &t ) {
        switch ( t ) {
            case EventDataProvider::DataType::DATA:
                os << "DATA";
                break;
            default:
                os << "WTF";
            case EventDataProvider::DataType::END_OF_DATA:
                os << "END_OF_DATA";
                break;
            case EventDataProvider::DataType::SOURCE_ATTACHED:
                os << "SOURCE_ATTACHED";
                break;
            case EventDataProvider::DataType::SOURCE_DETTACHED:
                os << "SOURCE_DETTACHED";
                break;
        }
        return os;
    }

    struct Data {
    public:
        explicit Data( EventDataProvider::DataType data_type, string message = string(), string src_ip = string() )
                : data_type( data_type ), message( std::move( message ) ), source_ip( std::move( src_ip ) ) {
            // TODO fix received timestamp here! to be more precise!
            //            m_receivedTimestamp = chrono::system_clock::now();
            //        counters->events_received++;
        }


        const EventDataProvider::DataType &GetEvent() const { return data_type; }

        const string &GetData() const { return message; }

        bool GetHasSourceIP() const { return !source_ip.empty(); }

        const string &GetSourceIPAddress() const { return source_ip; }

        EventDataProvider::DataType data_type;
        const string                message;
        const string                source_ip;
    };
    class Listener {
    public:
        virtual ~Listener()                                              = default;
        virtual void OnDataProviderEvent( EventDataProvider::Data data ) = 0;
    };
} // namespace EventDataProvider

class IDataProvider {
public:
    virtual ~IDataProvider() = 0;
    /** called after lib load but befor event loop started
     *
     * @param config
     * @param config_override
     * @return
     */
    virtual bool Configure( LibraryType::Config config, LibraryType::Config config_override ) = 0; // NOLINT
    /** receive events and call  m_DataListener->OnDataProviderEvent for each
     *
     * @return
     */
    virtual bool Run() = 0;
    /** juts remainder to update statistics counters
     *
     */
    //virtual void UpdateStatistics() = 0;

    /** finalise - close files , sockets etc
     *
     * @return
     */
    virtual bool Stop() = 0;

    virtual void SetDataListener( std::shared_ptr<EventDataProvider::Listener> data_listener ) {
        m_DataListener = std::move( data_listener );
    }

    void        SetName( string n ) { name_ = std::move( n ); }
    std::string GetName() {
        /** We use events.priority field which is varchar(10)!*/
        return name_.substr( 0, 10 );
    }

protected:
    std::shared_ptr<EventDataProvider::Listener> m_DataListener;
    std::string                                  name_     = "Should_be_implemented";
};
// Pure virtual destructor in C++ MUST provide a function body for the pure virtual destructor
// Define pure virtual function outside class scope.
// Inline to avoid redefinition errors if placed in header.
inline IDataProvider::~IDataProvider() = default;
#endif // NGNETMS_IDATAPROVIDER
