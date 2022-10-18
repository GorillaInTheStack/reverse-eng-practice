"""
    author: Husamu-Aldeen Alkhafaji
    version: 0.0.1
    date: 15/10/2022
"""
import glob
import json
import logging
import re

logging.basicConfig(format='INFO: %(message)s', level=logging.DEBUG)


class DetectRun(object):
    __activity_log = {}  # The log file
    __path_pattern = r"^C:\\Users\\.*\\AppData\\Roaming\\.*"  # The pattern the malware uses to store itself
    __reg_pattern = r"%APPDATA%\\.*\\.*"  # The pattern the malware uses to store itself in registry
    __type_pattern = r"^PE32 .*"  # The type of the malware
    __compromise_indicators = {"attributes": "SYSTEM", "sec_attribute": "HIDDEN", "path": __path_pattern,
                               "type": __type_pattern}  # Compromise indicators foound in the log files
    __log_keys = ["system_activity", "filesystem", "basic_info_change", "rename_old_name", "rename_new_name",
                  "indexable_change", "registry", "created_keys"]  # keys from the log files
    is_executed = False  # is malware executed in the respective log
    indicator_counter = 0  # number of indicators found
    sus_file = {}  # suspicious file details
    sus_folder = ""  # suspicious file folder
    rename_old = ""  # old name of malware
    rename_new = ""  # new name of malware

    def __init__(self, json_path):
        try:

            # Try to open log file
            with open(json_path, "r") as f:
                self.activity_log = json.load(f)

            if self.__analyze():
                self.is_executed = not self.is_executed

        except (OSError, json.JSONDecodeError, AttributeError) as e:
            logging.exception("An error occurred while parsing the json file", e)
            exit(1)

    def __analyze(self):
        """
        checks all indicators found
        :return: boolean
        """
        return self.__check_change() or self.__check_rename() or self.__check_registry()

    def __check_change(self):
        """
        checks if a suspicious file exists in the indexable_change field of the log
        :return: boolean
        """
        indexable_dict = self.activity_log[self.__log_keys[0]][self.__log_keys[1]][self.__log_keys[5]]

        for entry in indexable_dict:
            observed_path = re.match(self.__path_pattern, entry["path"])
            self.indicator_counter += 1
            has_system = self.__compromise_indicators["attributes"] in entry["attributes"]
            self.indicator_counter += 1
            has_type = re.match(self.__type_pattern, entry["type"])
            self.indicator_counter += 1

            if observed_path and has_system and has_type:
                self.sus_file = entry
                return True

        return False

    def __check_rename(self):
        """
        checks if the suspicious file tried to rename itself
        :return: boolean
        """
        found = False
        if self.sus_file:
            rename_old = self.activity_log[self.__log_keys[0]][self.__log_keys[1]][self.__log_keys[3]]
            rename_new = self.activity_log[self.__log_keys[0]][self.__log_keys[1]][self.__log_keys[4]]

            for entry in rename_old:
                if entry["file_reference_number"] == self.sus_file["file_reference_number"]:
                    self.rename_old = entry["path"]
                    found = not found
                    self.indicator_counter += 1
                    break

            for entry in rename_new:
                if entry["file_reference_number"] == self.sus_file["file_reference_number"]:
                    self.rename_new = entry["path"]
                    self.sus_folder = self.rename_new.split("\\")[-2]
                    break
            return found
        return False

    def __check_registry(self):
        """
        checks if the suspicious file tried to install itself to HKCU registry
        :return: boolean
        """
        if self.sus_file:
            reg_keys = self.activity_log[self.__log_keys[0]][self.__log_keys[6]][self.__log_keys[7]]
            print(reg_keys)
            for v in reg_keys.values():
                try:
                    has_reg_data = re.match(self.__reg_pattern, v["values"][self.sus_folder]["data"])
                    has_reg_type = re.match(r"REG_EXPAND_SZ", v["values"][self.sus_folder]["type"])

                    if has_reg_data and has_reg_type:
                        self.indicator_counter += 1
                        return True

                except KeyError:
                    continue
        return False

    def check_result(self):
        """
        retuns if the malware was run in the log file given.
        :return: boolean
        """
        return self.is_executed

    def check_compromise_indicators(self):
        """
        returns the number of compromise indicators found
        :return: int
        """
        return self.indicator_counter

    def get_sus_file(self):
        """
        returns a dictionary with information of the suspect file
        :return: dict
        """
        return self.sus_file

    def get_sus_file_old_name(self):
        """
        returns the old name of the suspect file before it renamed itself
        :return: str
        """
        return self.rename_old


if __name__ == "__main__":

    for file in glob.glob("*.json"):
        test = DetectRun(file)
        print(f"Is malware executed in log {file} ? : {test.check_result()}")
