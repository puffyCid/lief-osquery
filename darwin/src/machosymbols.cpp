#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>


class MachoSymbolsTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "arch", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "symbol_name", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("is_external",
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
        std::unique_ptr<LIEF::MachO::FatBinary> mac_binary =
            LIEF::MachO::Parser::parse(path_string, config.deep());

        for (const auto& data : mac_binary->begin()) {
          for (const auto& symbol : data.symbols().begin()) {
            auto r = osquery::make_table_row();
            r["path"] = path_string;
            r["filename"] = path.filename().string();
            r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
            r["symbol_name"] = symbol.name();
            r["is_external"] = std::to_string(symbol.is_external());
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
REGISTER_EXTERNAL(MachoSymbolsTable, "table", "macho_symbols");
