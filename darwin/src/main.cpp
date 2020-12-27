#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>
#include <sstream>

class MachoInfoTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "arch", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("entrypoint",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("build_version_min",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("build_version_sdk",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "is_pie", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "has_nx", osquery::INTEGER_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("is_encrypted",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_libraries",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_imported_functions",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
	std::make_tuple("number_of_exported_functions",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("number_of_sections",
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

    auto config = LIEF::MachO::ParserConfig().deep();
    boost::system::error_code ec;
    osquery::TableRows results;

    for (const auto& path_string : paths) {
      boost::filesystem::path path = path_string;
      if (!boost::filesystem::is_regular_file(path, ec)) {
        continue;
      }
      try {
        // Skip non-macho files
        if (!LIEF::MachO::is_macho(path_string)) {
          continue;
        }

        std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
            LIEF::MachO::Parser::parse(path_string, config.deep());

        for (const auto& data : mac_binary->begin()) {
          auto r = osquery::make_table_row();
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
          if (data.has_encryption_info()) {
            r["is_encrypted"] = osquery::INTEGER(1);
          } else {
            r["is_encrypted"] = osquery::INTEGER(0);
          }
          if (data.has_entrypoint()) {
	    std::ostringstream stream;
	    stream << std::hex << data.entrypoint();
            r["entrypoint"] = stream.str();
          }

          if (data.has_build_version()) {
            std::ostringstream ss;

            for (const auto& min : data.build_version().minos()) {
              ss << std::to_string(min) << ".";
            }
            r["build_version_min"] = ss.str().substr(0, ss.str().size() - 1);
            ss.str("");
            for (const auto& build : data.build_version().sdk()) {
              ss << std::to_string(build) << ".";
            }
            r["build_version_sdk"] = ss.str().substr(0, ss.str().size() - 1);
          }

          r["number_of_imported_functions"] = osquery::INTEGER(data.imported_functions().size());
	  r["number_of_exported_functions"] = osquery::INTEGER(data.exported_functions().size());
          r["number_of_libraries"] = osquery::INTEGER(data.libraries().size());
          r["number_of_sections"] = osquery::INTEGER(data.sections().size());
          r["is_pie"] = osquery::INTEGER(data.is_pie());
          r["has_nx"] = osquery::INTEGER(data.has_nx());
          results.push_back(std::move(r));
        }
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse Mach-O file: " << error.what();
      }
    }

    return results;
  }
};
REGISTER_EXTERNAL(MachoInfoTable, "table", "macho_info");

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
