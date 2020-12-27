#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>

class PeLibrariesTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("library_name",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("import_address_table_rva",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("import_lookup_table_rva",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("timestamp",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("forwarder_chain",
                        osquery::INTEGER_TYPE,
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
    boost::system::error_code ec;
    osquery::TableRows results;
    for (const auto& path_string : paths) {
      boost::filesystem::path path = path_string;
      if (!boost::filesystem::is_regular_file(path, ec)) {
        continue;
      }
      try {
        // Skip non-pe files
        if (!LIEF::PE::is_pe(path_string)) {
          continue;
        }
        std::unique_ptr<LIEF::PE::Binary> pe_binary =
            LIEF::PE::Parser::parse(path_string);

        // Get Library info from PE file
        for (const auto& imports : pe_binary->imports()) {
          auto r = osquery::make_table_row();
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["library_name"] = imports.name();
          std::ostringstream stream;
          stream << std::hex << imports.import_address_table_rva();
          r["import_address_table_rva"] = stream.str();
          stream.str("");
          stream << std::hex << imports.import_lookup_table_rva();
          r["import_lookup_table_rva"] = stream.str();
          r["timestamp"] = osquery::INTEGER(imports.timedatestamp());
          r["forwarder_chain"] = osquery::INTEGER(imports.forwarder_chain());
          results.push_back(std::move(r));
        }
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse PE file: " << error.what();
      }
    }
    return results;
  }
};

REGISTER_EXTERNAL(PeLibrariesTable, "table", "pe_libraries");
