#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>

class MachoLibrariesTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "arch", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("library_name",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("library_size",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "version", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("compatibility_version",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT)};
  }
  osquery::TableRows generate(osquery::QueryContext& context) {
    auto paths = context.constraints["path"].getAll(osquery::EQUALS);
    // Expand contstraints
    context.expandConstraints(
        "path",
        osquery::LIKE,
        paths,
        ([&](const std::string& pattern, std::set<std::string>& out) {
          std::vector<std::string> patterns;
          auto status = resolveFilePattern(
              pattern, patterns, osquery::GLOB_ALL | osquery::GLOB_NO_CANON);
          if (status.ok()) {
            for (const auto& resolved : patterns) {
              out.insert(resolved);
            }
          }
          return status;
        }));

    auto config = LIEF::MachO::ParserConfig().deep();
    boost::system::error_code ec;
    osquery::TableRows results;

    for (const auto& path_string : paths) {
      boost::filesystem::path path = path_string;
      if (!boost::filesystem::is_regular_file(path, ec)) {
        continue;
      }
      // Skip non-macho files
      if (!LIEF::MachO::is_macho(path_string)) {
        continue;
      }
      try {
        // Parse macho file and get some information
        std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
            LIEF::MachO::Parser::parse(path_string, config.deep());

        for (const auto& data : mac_binary->begin()) {
          for (const auto& library : data.libraries().begin()) {
            auto r = osquery::make_table_row();
            r["path"] = path_string;
            r["filename"] = path.filename().string();
            r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
            r["library_name"] = library.name();
            r["library_size"] = osquery::INTEGER(library.size());
            std::ostringstream ss;
            for (const auto& version : library.current_version()) {
              ss << std::to_string(version) << ".";
            }
            r["version"] = ss.str().substr(0, ss.str().size() - 1);
            ss.str("");
            for (const auto& version : library.compatibility_version()) {
              ss << std::to_string(version) << ".";
            }
            r["compatibility_version"] =
                ss.str().substr(0, ss.str().size() - 1);
            ss.str("");

            results.push_back(std::move(r));
          }
        }
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse Mach-O file: " << error.what();
      }
    }
    return results;
  }
};
REGISTER_EXTERNAL(MachoLibrariesTable, "table", "macho_libraries");
