from __future__ import annotations

import itertools
import json
from typing import TYPE_CHECKING, Any

from checkov.common.models.enums import CheckResult
from checkov.common.output.cyclonedx_consts import SCA_CHECKTYPES
from checkov.common.util.http_utils import valid_url
from checkov.version import version

if TYPE_CHECKING:
    from checkov.common.output.record import Record
    from checkov.common.output.report import Report

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "none": "none",
}


SEVERITY_TO_SCORE = {
    "critical": "10.0",
    "high": "8.9",
    "medium": "6.9",
    "low": "3.9",
    "none": "0.0",
}

TEST_ID_SEVERITY = {
    'CKV_GCP_37': 'low', 'CKV2_GCP_3': 'low', 'CKV2_GCP_6': 'low', 'CKV_GCP_97': 'low',
    'CKV_GCP_79': 'low', 'CKV_GCP_85': 'low', 'CKV_GCP_93': 'low', 'CKV_GCP_91': 'low',
    'CKV_GCP_92': 'low', 'CKV_GCP_96': 'low', 'CKV_GCP_83': 'low', 'CKV_GCP_80': 'low',
    'CKV_GCP_90': 'low', 'CKV_GCP_84': 'low', 'CKV_GCP_74': 'low', 'CKV_GCP_81': 'low',
    'CKV_GCP_82': 'low', 'CKV_GCP_87': 'low', 'CKV_GCP_86': 'low', 'CKV_GCP_105': 'low',
    'CKV_GCP_78': 'low', 'CKV_GCP_104': 'low', 'CKV2_GCP_7': 'low', 'CKV_GCP_13': 'low',
    'CKV_GCP_24': 'low', 'CKV_GCP_18': 'low', 'CKV_GCP_21': 'low', 'KV_GCP_22': 'low',
    'CKV_GCP_23': 'low', 'CKV_GCP_65': 'low', 'CKV_GCP_69': 'low', 'CKV_GCP_88': 'low',
    'CKV_GCP_76': 'low', 'CKV_GCP_106': 'low', 'CKV_GCP_77': 'low', 'CKV_GCP_75': 'low',
    'CKV_GCP_63': 'low', 'CKV_GCP_50': 'low', 'CKV_GCP_51': 'low', 'CKV_GCP_52': 'low',
    'CKV_GCP_53': 'low', 'CKV_GCP_54': 'low', 'CKV_GCP_55': 'low', 'CKV_GCP_56': 'low',
    'CKV_GCP_57': 'low', 'CKV_GCP_60': 'low', 'CKV_GCP_39': 'medium', 'CKV_GCP_43': 'medium',
    'CKV_GCP_95': 'medium', 'CKV_GCP_30': 'medium', 'CKV_GCP_31': 'medium', 'CKV_GCP_49': 'medium',
    'CKV_GCP_1': 'medium', 'CKV_GCP_7': 'medium', 'CKV_GCP_8': 'medium', 'CKV_GCP_9': 'medium',
    'CKV_GCP_10': 'medium', 'CKV_GCP_25': 'medium', 'CKV_GCP_12': 'medium', 'CKV_GCP_19': 'medium',
    'CKV_GCP_20': 'medium', 'CKV2_GCP_1': 'medium', 'CKV_GCP_68': 'medium', 'CKV_GCP_61': 'medium',
    'CKV_GCP_64': 'medium', 'CKV_GCP_66': 'medium', 'CKV_GCP_67': 'medium', 'CKV_GCP_71': 'medium',
    'CKV_GCP_72': 'medium', 'CKV_GCP_70': 'medium', 'CKV_GCP_26': 'medium', 'CKV2_GCP_4': 'medium',
    'CKV2_GCP_5': 'medium', 'CKV_GCP_4': 'medium', 'CKV_GCP_16': 'medium', 'CKV_GCP_17': 'medium',
    'CKV_GCP_27': 'medium', 'CKV_GCP_34': 'medium', 'CKV_GCP_35': 'medium', 'CKV_GCP_36': 'medium',
    'CKV2_GCP_2': 'medium', 'CKV_GCP_73': 'medium', 'CKV2_GCP_10': 'medium', 'CKV2_GCP_11': 'medium',
    'CKV_GCP_40': 'medium', 'CKV_GCP_102': 'medium', 'CKV_GCP_99': 'medium', 'CKV_GCP_29': 'medium',
    'CKV_GCP_62': 'medium', 'CKV_GCP_58': 'medium', 'CKV_GCP_59': 'medium', 'CKV_GCP_6': 'high',
    'CKV_GCP_14': 'high', 'CKV_GCP_41': 'high', 'CKV2_GCP_8': 'high', 'CKV_GCP_11': 'high',
    'CKV_GCP_32': 'high', 'CKV_GCP_33': 'high', 'CKV_GCP_88': 'high', 'CKV2_GCP_12': 'high',
    'CKV_GCP_28': 'high', 'CKV_GCP_100': 'high', 'CKV_GCP_94': 'high', 'CKV_GCP_89': 'high',
    'CKV_GCP_98': 'high', 'CKV2_GCP_6': 'high', 'CKV_GCP_101': 'high', 'CKV2_GCP_9': 'high',
    'CKV_GCP_103': 'high', 'CKV_GCP_5': 'high', 'CKV_GCP_38': 'critical', 'CKV_GCP_15': 'critical',
    'CKV_GCP_42': 'critical', 'CKV_GCP_44': 'critical', 'CKV_GCP_45': 'critical', 'CKV_GCP_46': 'critical',
    'CKV_GCP_47': 'critical', 'CKV_GCP_48': 'critical', 'CKV_GCP_2': 'critical', 'CKV_GCP_3': 'critical'
}

TESTID_UNDOC_SEVERITY = {
    'CKV_GCP_107': 'low', 'CKV_GCP_108': 'low', 'CKV_GCP_109': 'low', 'CKV_GCP_110': 'low',
    'CKV_GCP_111': 'low', 'CKV_GCP_112': 'low', 'CKV_GCP_113': 'low', 'CKV_GCP_114': 'low',
    'CKV_GCP_115': 'low', 'CKV_GCP_117': 'low', 'CKV2_GCP_13': 'low', 'CKV2_GCP_14': 'low',
    'CKV2_GCP_15': 'low', 'CKV2_GCP_16': 'low', 'CKV2_GCP_17': 'low', 'CKV2_GCP_18': 'low',
    'CKV2_GCP_19': 'low', 'CKV2_GCP_20': 'low'
}

TEST_ID_SEVERITY.update(TESTID_UNDOC_SEVERITY)

 
class Sarif:
    def __init__(self, reports: list[Report], tool: str | None) -> None:
        self.reports = reports
        self.rule_index_map: "dict[str, int]" = {}
        self.tool = tool if tool else "Bridgecrew"

        self.json = self.create_json()

    def create_json(self) -> dict[str, Any]:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": self._create_runs(),
        }

    def _create_runs(self) -> list[dict[str, Any]]:
        information_uri = "https://docs.bridgecrew.io" if self.tool.lower() == "bridgecrew" else "https://checkov.io"
        rules = self._create_rules()  # needs to be invoked before _create_results()
        results = self._create_results()

        return [
            {
                "tool": {
                    "driver": {
                        "name": self.tool,
                        "version": version,
                        "informationUri": information_uri,
                        "rules": rules,
                        "organization": "bridgecrew",
                    }
                },
                "results": results,
            }
        ]

    def _create_rules(self) -> list[dict[str, Any]]:
        rule_idx = 0
        rules: "list[dict[str, Any]]" = []

        for report in self.reports:
            if report.check_type in SCA_CHECKTYPES:
                for record in itertools.chain(report.failed_checks, report.skipped_checks):
                    rule = None
                    if record.check_id.startswith("BC_LIC"):
                        rule = self._create_license_rule(check_type=report.check_type, record=record)
                    elif record.check_id.startswith(("BC_VUL", "CKV_CVE")):
                        rule = self._create_cve_rule(check_type=report.check_type, record=record)

                    if rule and rule["id"] not in self.rule_index_map:
                        self.rule_index_map[rule["id"]] = rule_idx
                        rules.append(rule)
                        rule_idx += 1
            else:
                for record in itertools.chain(report.failed_checks, report.skipped_checks):
                    if record.check_id not in self.rule_index_map:
                        rule = self._create_iac_rule(check_type=report.check_type, record=record)
                        self.rule_index_map[rule["id"]] = rule_idx
                        rules.append(rule)
                        rule_idx += 1

        return rules

    def _create_iac_rule(self, check_type: str, record: Record) -> dict[str, Any]:
        rule = {
            "id": self._create_rule_id(check_type=check_type, record=record),
            "name": record.short_description or record.check_name,
            "shortDescription": {
                "text": record.short_description or record.check_name,
            },
            "fullDescription": {
                "text": record.description or record.check_name,
            },
            "help": {
                "text": f"{record.check_name}\nResource: {record.resource}",
            },
            "defaultConfiguration": {"level": "error"},
        }

        # Adding 'properties' dictionary only if 'record.severity' exists
        if record.severity:
            rule["properties"] = {
                "security-severity": SEVERITY_TO_SCORE.get(record.severity.name.lower(), "0.0"),
            }

        help_uri = record.guideline
        if valid_url(help_uri):
            rule["helpUri"] = help_uri

        return rule

    def _create_cve_rule(self, check_type: str, record: Record) -> dict[str, Any] | None:
        details = record.vulnerability_details
        if not details:
            # this shouldn't happen
            return None

        rule = {
            "id": self._create_rule_id(check_type=check_type, record=record),
            "name": record.short_description or record.check_name,
            "shortDescription": {
                "text": record.short_description or record.check_name,
            },
            "fullDescription": {
                "text": record.description or record.check_name,
            },
            "help": {
                "text": f"{record.check_name}\nResource: {record.resource}\nStatus: {details.get('status')}",
            },
            "defaultConfiguration": {"level": "error"},
        }

        # Add properties dictionary with security-severity
        cvss = details.get("cvss")
        if cvss:
            # use CVSS, if exists
            rule["properties"] = {
                "security-severity": str(cvss),
            }
        elif record.severity:
            # otherwise severity, if exists
            rule["properties"] = {
                "security-severity": SEVERITY_TO_SCORE.get(record.severity.name.lower(), "0.0"),
            }

        help_uri = details.get("link")
        if valid_url(help_uri):
            rule["helpUri"] = help_uri

        return rule

    def _create_license_rule(self, check_type: str, record: Record) -> dict[str, Any] | None:
        details = record.vulnerability_details
        if not details:
            # this shouldn't happen
            return None

        rule = {
            "id": self._create_rule_id(check_type=check_type, record=record),
            "name": record.short_description or record.check_name,
            "shortDescription": {
                "text": record.short_description or record.check_name,
            },
            "fullDescription": {
                "text": f"Package {details['package_name']}@{details['package_version']} has license {details['license']}",
            },
            "help": {
                "text": f"{record.check_name}\nResource: {record.resource}",
            },
            "defaultConfiguration": {"level": "error"},
        }

        # Adding 'properties' dictionary only if 'record.severity' exists
        if record.severity:
            rule["properties"] = {
                "security-severity": SEVERITY_TO_SCORE.get(record.severity.name.lower(), "0.0"),
            }

        help_uri = record.guideline
        if valid_url(help_uri):
            rule["helpUri"] = help_uri

        return rule

    def _create_results(self) -> list[dict[str, Any]]:
        results: "list[dict[str, Any]]" = []

        for report in self.reports:
            for record in itertools.chain(report.failed_checks, report.skipped_checks):
                level = "warning"
                if record.severity:
                    level = SEVERITY_TO_SARIF_LEVEL.get(record.severity.name.lower(), "none")
                elif record.check_result.get("result") == CheckResult.FAILED:
                    if record.check_id in TEST_ID_SEVERITY:
                        level = SEVERITY_TO_SARIF_LEVEL.get(TEST_ID_SEVERITY[record.check_id], "none")
                    else:
                        level = "error"

                rule_id = self._create_rule_id(check_type=report.check_type, record=record)
                if not rule_id or rule_id not in self.rule_index_map:
                    # can happen if data is missing
                    continue

                result = {
                    "ruleId": rule_id,
                    "ruleIndex": self.rule_index_map[rule_id],
                    "level": level,
                    "attachments": [{"description": detail} for detail in record.details],
                    "message": {
                        "text": record.short_description or record.check_name,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": record.repo_file_path.lstrip("/")},
                                "region": {
                                    "startLine": int(record.file_line_range[0]) or 1,
                                    "endLine": int(record.file_line_range[1]) or 1,
                                    "snippet": {"text": "".join(line for _, line in record.code_block)},
                                },
                            }
                        }
                    ],
                }

                if record.check_result.get("result") == CheckResult.SKIPPED:
                    # sca_package suppression can only be enabled via flag
                    # other runners only report in source suppression
                    kind = "external" if record.vulnerability_details else "inSource"
                    justification = record.check_result.get("suppress_comment")
                    if justification is None:
                        justification = "No comment provided"

                    result["suppressions"] = [
                        {
                            "kind": kind,
                            "justification": justification,
                        }
                    ]

                results.append(result)

        return results

    def _create_rule_id(self, check_type: str, record: Record) -> str | None:
        if check_type in SCA_CHECKTYPES:
            details = record.vulnerability_details
            if not details:
                # this shouldn't happen
                return None

            if record.check_id.startswith("BC_LIC"):
                return f"{details['license']}_{details['package_name']}@{details['package_version']}".replace(" ", "_")
            elif record.check_id.startswith(("BC_VUL", "CKV_CVE")):
                return f"{details['id']}_{details['package_name']}@{details['package_version']}".replace(" ", "_")
        else:
            return record.check_id

        return None

    def write_sarif_output(self) -> None:
        try:
            with open("results.sarif", "w") as f:
                f.write(json.dumps(self.json))
                print("\nWrote output in SARIF format to the file 'results.sarif'")
        except EnvironmentError as e:
            print("\nAn error occurred while writing SARIF results to file: results.sarif")
            print(f"More details: \n {e}")
