#include <LIEF/LIEF.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>

class MachoSectionsTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "arch", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("section_name",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("section_address",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("section_flags",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("section_size",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple(
            "entropy", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
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
          for (const auto& section : data.sections().begin()) {
            auto r = osquery::make_table_row();

            r["path"] = path_string;
            r["filename"] = path.filename().string();
            r["arch"] = LIEF::MachO::to_string(data.header().cpu_type());
            r["section_name"] = section.name();
	    std::ostringstream stream;
	    stream << std::hex << section.address();
            r["section_address"] = stream.str();
	    stream.str("");
	    stream << std::hex << section.flags();
            r["section_flags"] = stream.str();
            r["section_size"] = osquery::INTEGER(section.Section::size());

            // LIEF returns 0 as -0.0000, strip negative sign from 0 value
            if (std::to_string(section.entropy()).find("-") !=
                std::string::npos) {
              r["entropy"] = std::to_string(section.entropy()).erase(0, 1);

            } else {
              r["entropy"] = std::to_string(section.entropy());
            }
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
REGISTER_EXTERNAL(MachoSectionsTable, "table", "macho_sections");
