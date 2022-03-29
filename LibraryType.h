#ifndef NGNETMS_LIBRRYTYPE
#define NGNETMS_LIBRRYTYPE
#include <cstdarg>
#include <map>
#include <memory>
#include <string>
#include <vector>
class Operator;
namespace LibraryType {
typedef std::map<std::string, std::string> Config;

/**Merge config
 *
 * @param config_defaults - good, lib defaults  lowest priority, overridden by all
 * @param config          - better,lib conf passed via rules file, overridden by config_override
 * @param config_override - best, lib conf passed via CLI (-L libname.key=value) overrides all
 * @return  merged config
 */
// Inline to avoid redefinition errors if placed in header.
inline Config mergeConfig( Config config_defaults, Config config, Config config_override ) {
    Config libconf_{};
    libconf_.merge( config_override );
    libconf_.merge( config );
    libconf_.merge( config_defaults );
    return libconf_;
}

// Library represents all shared libraries used by collector
class Library {
  public:
    Library( std::string Name, std::string Type, std::string fileName, Config config )
        : m_Type( std::move( Type ) ), m_Name( std::move( Name ) ), m_LibraryFileName( std::move( fileName ) ),
          m_LibraryConf( std::move( config ) ) {}

    ~Library() = default;

    const std::string &getName() const { return m_Name; }

    const std::string &getLibraryFile() const { return m_LibraryFileName; }

    const std::string &getType() const { return m_Type; }

    Config &getConfig() { return m_LibraryConf; }

    Library( const Library & ) = delete;
    const Library &operator=( const Library & ) = delete;

  private:
    std::string m_Type;
    std::string m_Name;
    std::string m_LibraryFileName;
    Config      m_LibraryConf;
};

typedef std::vector<std::pair<std::string, std::shared_ptr<Library>>> List;

} // namespace LibraryType

#endif // NGNETMS_LIBRRYTYPE
