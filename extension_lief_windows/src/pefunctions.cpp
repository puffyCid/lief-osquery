#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>

class PeFunctionsTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("function_type",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("function_name",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("function_address",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "ordinal", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "library", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
    };
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

        // Get imported functions from PE file
        for (const auto& imports : pe_binary->imports()) {
          for (const auto& entries : imports.entries()) {
            // std::cout << entries.name() << std::endl;
            auto r = osquery::make_table_row();
            r["path"] = path_string;
            r["filename"] = path.filename().string();
            r["function_type"] = "import";
            r["function_name"] = entries.name();
            std::ostringstream stream;
            stream << std::hex << entries.iat_value();
            r["function_address"] = stream.str();
            r["library"] = imports.name();
            if (entries.is_ordinal()) {
              r["ordinal"] = osquery::INTEGER(entries.ordinal());
            }
            results.push_back(std::move(r));
          }
        }
        auto& exports = pe_binary->get_export();

        // Get exported functiosn from PE file
        for (const auto& entries : exports.entries()) {
          auto r = osquery::make_table_row();
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["function_type"] = "export";
          r["library"] = exports.name();
          r["function_name"] = entries.name();
          std::ostringstream stream;
          stream << std::hex << entries.address();
          r["function_address"] = stream.str();
          r["ordinal"] = osquery::INTEGER(entries.ordinal());
          results.push_back(std::move(r));
        }
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse PE file: " << error.what();
      }
    }
    return results;
  }
};

REGISTER_EXTERNAL(PeFunctionsTable, "table", "pe_functions");
