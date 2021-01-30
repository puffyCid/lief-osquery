#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>
class LiefInfoTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "pie", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("entrypoint",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_exported_functions",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_libraries",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_imported_functions",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_sections",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "imphash", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "signed", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("has_resources",
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
        auto r = osquery::make_table_row();

        // Get basic PE file info
        r["path"] = path_string;
        r["filename"] = path.filename().string();
        r["signed"] = osquery::INTEGER(pe_binary->has_signatures());
        r["imphash"] = LIEF::PE::get_imphash(*pe_binary);
        r["number_of_libraries"] =
            osquery::INTEGER(pe_binary->imported_libraries().size());
        int import_number = 0;
        for (const auto& imports : pe_binary->imports()) {
          import_number += imports.entries().size();
        }
        r["number_of_imported_functions"] = osquery::INTEGER(import_number);

        std::ostringstream stream;
        stream << std::hex << pe_binary->entrypoint();
        r["entrypoint"] = stream.str();;
        r["number_of_exported_functions"] =
            osquery::INTEGER(pe_binary->exported_functions().size());
        r["pie"] = osquery::INTEGER(pe_binary->is_pie());
        r["number_of_sections"] =
            osquery::INTEGER(pe_binary->sections().size());
        r["has_resources"] = osquery::INTEGER(pe_binary->has_resources());
        results.push_back(std::move(r));
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse PE file: " << error.what();
      }
    }
    return results;
  }
};

REGISTER_EXTERNAL(LiefInfoTable, "table", "pe_info");

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);
  auto status = osquery::startExtension("lief", ".1");
  LIEF::logging::disable();
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}