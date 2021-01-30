#include <LIEF/PE.hpp>
#include <LIEF/logging.hpp>
#include <boost/filesystem.hpp>
#include <osquery/core/system.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sdk/sdk.h>
#include <osquery/sql/dynamic_table_row.h>

#include <sstream>
class PeSigTable : public osquery::TablePlugin {
 private:
  osquery::TableColumns columns() const {
    return {
        std::make_tuple(
            "path", osquery::TEXT_TYPE, osquery::ColumnOptions::REQUIRED),
        std::make_tuple(
            "filename", osquery::TEXT_TYPE, osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_valid_from",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_valid_to",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_issuer",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_subject",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_version",
                        osquery::INTEGER_TYPE,
                        osquery::ColumnOptions::DEFAULT),
        std::make_tuple("certificate_serial_number",
                        osquery::TEXT_TYPE,
                        osquery::ColumnOptions::DEFAULT),
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
        if (!pe_binary->has_signatures()) {
          continue;
        }

        auto sig = pe_binary->signatures();

        // Get Signature info from PE file
        for (const auto& certs : sig->certificates()) {
          auto r = osquery::make_table_row();
          r["path"] = path_string;
          r["filename"] = path.filename().string();
          r["certificate_issuer"] = certs.issuer();
          r["certificate_subject"] = certs.subject();
          std::string valid_from = "";
          for (int dates = 0; dates < certs.valid_from().size(); dates++) {
            if (dates > 2) {
              valid_from += std::to_string(certs.valid_from()[dates]) + ":";
              continue;
            }
            if (dates == 2) {
              valid_from += std::to_string(certs.valid_from()[dates]) + " ";
              continue;
            }
            valid_from += std::to_string(certs.valid_from()[dates]) + "-";
          }
          valid_from.pop_back();
          r["certificate_valid_from"] = valid_from;
          std::string valid_to = "";
          for (int dates = 0; dates < certs.valid_to().size(); dates++) {
            if (dates > 2) {
              valid_to += std::to_string(certs.valid_to()[dates]) + ":";
              continue;
            }
            if (dates == 2) {
              valid_to += std::to_string(certs.valid_to()[dates]) + " ";
              continue;
            }
            valid_to += std::to_string(certs.valid_to()[dates]) + "-";
          }
          valid_to.pop_back();
          r["certificate_valid_to"] = valid_to;
          r["certificate_version"] = osquery::INTEGER(certs.version());
          std::string serial = "";
          for (const auto& serial_num : certs.serial_number()) {
            std::ostringstream stream;
            stream << std::hex << (int)serial_num;
            serial += stream.str() + ":";
          }
          serial.pop_back();
          r["certificate_serial_number"] = serial;
          results.push_back(std::move(r));
        }
      } catch (std::exception& error) {
        LOG(WARNING) << "Failed to parse PE file: " << error.what();
      }
    }
    return results;
  }
};

REGISTER_EXTERNAL(PeSigTable, "table", "pe_sig");
