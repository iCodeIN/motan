#!/usr/bin/env python3

import logging
import os
import plistlib
import re
import zipfile
from typing import Optional, Union, Iterable, List

import networkx as nx
from androguard.core.analysis.analysis import (
    Analysis as AndroguardAnalysis,
    MethodAnalysis,
)
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import Instruction, ClassDefItem
from androguard.core.bytecodes.dvm_types import Operand

logger = logging.getLogger(__name__)


def get_non_empty_lines_from_file(file_name: str) -> List[str]:
    try:
        with open(file_name, "r", encoding="utf-8") as file:
            # Return a list with the non blank lines contained in the file.
            return list(filter(None, (line.rstrip() for line in file)))
    except Exception as e:
        logger.error(f"Error when reading file '{file_name}': {e}")
        raise


# Adapted from https://github.com/pkumza/LiteRadar
def get_libs_to_ignore() -> List[str]:
    return get_non_empty_lines_from_file(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "resources",
            "android_libs_to_ignore.txt",
        )
    )


def check_valid_apk_file(input_file: str):
    if not APK(input_file).is_valid_APK():
        raise ValueError("This file is not a valid apk file")


def check_valid_ipa_file(input_file: str):
    try:
        with zipfile.ZipFile(input_file, "r") as ipa_zip:
            info_plist_file_regex = re.compile(
                r"Payload/.+\.app/info\.plist", re.IGNORECASE
            )

            # Every valid ipa application has an info.plist file.
            info_plist_path = list(
                filter(info_plist_file_regex.match, ipa_zip.namelist())
            )[0]

            with ipa_zip.open(info_plist_path, "r") as info_plist_file:
                plistlib.load(info_plist_file)

    except Exception:
        raise ValueError("This file is not a valid ipa file")


def is_class_implementing_interfaces(clazz: ClassDefItem, interfaces: Iterable[str]):
    """
    Check if a class is implementing a specific list of interfaces.
    """
    return all(interface in clazz.get_interfaces() for interface in interfaces)


def get_paths_to_target_method(
    target_method: Union[MethodAnalysis, Iterable[MethodAnalysis]]
) -> List[List[MethodAnalysis]]:
    def recursive_graph(graph: nx.MultiDiGraph(), method: MethodAnalysis):
        # If not already present, add the current method as a node to the graph,
        # otherwise return, since this node was already processed.
        if method not in graph.nodes:
            graph.add_node(method)
        else:
            return

        # Add to the graph all the callers of the current method and repeat the same
        # operation for each caller.
        for _, caller, offset in method.get_xref_from():
            recursive_graph(graph, caller)
            graph.add_edge(caller, method, key=offset)

    def get_paths(method: MethodAnalysis) -> List[List[MethodAnalysis]]:
        if not method:
            # There are no paths if the target method is not set.
            return []

        graph = nx.MultiDiGraph()
        recursive_graph(graph, method)

        # Find all paths that have method destination.
        paths = []
        for node in graph.nodes:
            paths.extend(nx.all_simple_paths(graph, node, method))

        # Keep only the longest paths (remove all the sub-paths that are part of longer
        # paths).
        longest_paths = []
        for path in sorted(paths, key=len, reverse=True):
            # Lists are casted to strings before comparison in order to easily use the
            # in operator to check if a list is a sub-list of another list.
            if not any(str(path)[1:-1] in str(elem)[1:-1] for elem in longest_paths):
                longest_paths.append(path)

        return longest_paths

    if isinstance(target_method, Iterable):
        # We have to check a list of target methods.
        to_return = []
        for m in target_method:
            to_return.extend(get_paths(m))
        return to_return

    if isinstance(target_method, MethodAnalysis):
        return get_paths(target_method)

    return []


class RegisterAnalyzer(object):
    class Stack:
        def __init__(self):
            self._elements = []

        def __len__(self):
            return len(self._elements)

        def push(self, elem):
            self._elements.append(elem)

        def get(self):
            return self._elements[-1]

    class ClassContainer(object):
        def __init__(self, class_name: str, class_index: int):
            self._class_name = class_name
            self._class_index = class_index

        def get_class_name(self):
            return self._class_name

        def get_class_index(self):
            return self._class_index

    class VariableContainer(object):
        def __init__(self, full_name: str):
            self._full_name = full_name

        def get_full_name(self):
            return self._full_name

    class Result(object):
        def __init__(self, result: list):
            self._result = result

        def get_result(self):
            return self._result

        def is_string(self, result_index: int):
            try:
                return isinstance(self._result[result_index], str)
            except TypeError:
                return False
            except KeyError:
                return False

        def is_class_container(self, result_index: int):
            try:
                return isinstance(
                    self._result[result_index], RegisterAnalyzer.ClassContainer
                )
            except TypeError:
                return False
            except NameError:
                return False
            except KeyError:
                return False

    def __init__(
        self,
        instructions_to_execute: Iterable[Instruction],
        max_num_of_instructions: int = -1,
        apk_analysis: Optional[APK] = None,
        dex_analysis: Optional[AndroguardAnalysis] = None,
        auto: bool = True,
    ):
        """
        This class virtually executes the list of instructions passed as parameters.

        When a list of instructions is passed to this class (e.g., the list of
        instructions from a method, by using method.get_instructions()), the
        instructions are virtually executed (until a maximum of max_num_of_instructions)
        and the values of the registers are saved (when possible). This way, when a
        method invocation is found, it's possible too see the values of the registers
        passed as params to that method invocation (if those values are constant).

        :param instructions_to_execute: The list of instructions to be virtually
                                        executed.
        :param max_num_of_instructions: The maximum number of instructions to be
                                        virtually executed (the instructions beyond this
                                        number will be ignored). Use -1 to virtually
                                        execute all the instructions.
        :param apk_analysis: Androguard APK.
        :param dex_analysis: Androguard Analysis.
        :param auto: If True, virtually execute the instructions immediately, otherwise
                     the instructions will be executed only when explicitly calling
                     load_instructions method.
        """
        self._register_values = {}
        self._execution_stack = RegisterAnalyzer.Stack()
        self._apk_analysis = apk_analysis
        self._dex_analysis = dex_analysis

        if auto:
            self.load_instructions(instructions_to_execute, max_num_of_instructions)

    def _add(self, op_code: int, operands: List[tuple]):
        if operands:
            # [const], [const/xx], [const-string]
            if 0x12 <= op_code <= 0x1C:
                destination_register = operands[0]
                value_for_register = operands[1]
                if destination_register[0] == Operand.REGISTER:
                    destination_register_num = destination_register[1]

                    # The actual value is the last one in value_for_register.
                    immediate_value = value_for_register[-1]
                    self._register_values[destination_register_num] = self.strip_string(
                        immediate_value
                    )

            # [move], [move/from]
            elif 0x01 <= op_code <= 0x02:
                # The content of one register is moved to another register.
                destination_register = operands[0]
                source_register = operands[1]
                if (
                    destination_register[0] == Operand.REGISTER
                    and source_register[0] == Operand.REGISTER
                ):
                    # Get the value from the other register (if available).
                    self._register_values[
                        destination_register[1]
                    ] = self._register_values.get(source_register[1])

            # [move-result], [move-result-wide], [move-result-object], [move-exception]
            elif 0x0A <= op_code <= 0x0D:
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                # In some cases, however, the value can be retrieved.
                last_instr = self._execution_stack.get()

                if (
                    last_instr[0] == 0x6E
                    and last_instr[1][-1][2]
                    == "Landroid/content/res/Resources;->getString(I)Ljava/lang/String;"
                ):
                    # Check if the last instruction was accessing a string from
                    # resources. 0x6E is an invoke-virtual instruction.
                    string_id = self._register_values.get(last_instr[1][1][1], None)
                    try:
                        res = self._apk_analysis.get_android_resources()
                        # The string corresponding to the id was retrieved from the
                        # resources, save its value into the corresponding register.
                        self._register_values[
                            register_number
                        ] = res.get_resolved_res_configs(string_id)[0][1]
                    except IndexError:
                        pass

                elif last_instr[0] == 0x6E and (
                    last_instr[1][-1][2] == "Ljava/lang/String;->getBytes()[B"
                    or last_instr[1][-1][2] == "Ljava/lang/String;->toCharArray()[C"
                ):
                    # Check if the last instruction is converting a string into bytes or
                    # into a char array. If so, keep the value of string saved in the
                    # corresponding register. 0x6E is an invoke-virtual instruction.
                    self._register_values[register_number] = self._register_values.get(
                        last_instr[1][0][1], None
                    )

                else:
                    # The value comes from an operation whose value is known only at
                    # runtime.
                    self._register_values[register_number] = None

            # [aget], [aget-xx]
            elif 0x44 <= op_code <= 0x4A:
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                self._register_values[register_number] = None

            # [iget], [iget-xx], [sget], [sget-xx]
            elif (0x52 <= op_code <= 0x58) or (0x60 <= op_code <= 0x66):
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime,
                # however we can save the field name (which sometimes is a known
                # constant value). The field name is the last value.
                full_field_name = operands[-1][2]
                self._register_values[
                    register_number
                ] = RegisterAnalyzer.VariableContainer(full_field_name)

            # [new-instance]
            elif op_code == 0x22:
                register_number = operands[0][1]
                new_instance_class_idx = operands[1][1]
                new_instance_class_name = operands[1][2]
                self._register_values[
                    register_number
                ] = RegisterAnalyzer.ClassContainer(
                    new_instance_class_name, new_instance_class_idx
                )

        # Push op code and operands. Format: <const/4 v5, 1> is saved as
        # <[18, [(0, 5), (1, 1)]]>.
        self._execution_stack.push([op_code, operands])

    def load_instructions(
        self,
        instructions_to_execute: Iterable[Instruction],
        max_num_of_instructions: int = -1,
    ):
        if max_num_of_instructions == -1:
            # Load all instructions.
            for instruction in instructions_to_execute:
                self._add(instruction.get_op_value(), instruction.get_operands())
        else:
            # Load instructions until max_num_of_instructions.
            current_index = 0
            for instruction in instructions_to_execute:
                self._add(instruction.get_op_value(), instruction.get_operands())
                current_index += instruction.get_length()
                if current_index > max_num_of_instructions:
                    break

    @staticmethod
    def strip_string(value):
        if isinstance(value, str):
            # Strip the left and right ' signs.
            return value.strip("'")
        return value

    def get_register_value(self, register_num: int):
        try:
            if register_num in self._register_values:
                return self._register_values[register_num]
            else:
                return None
        except KeyError:
            return None

    def get_register_values(self):
        return self._register_values

    def initialize_register_value(self, register_num: int, register_val):
        if register_num not in self._register_values:
            self._register_values[register_num] = register_val
        else:
            raise ValueError("Register already initialized")

    def get_last_instruction_return_value(self):
        """
        If the last instruction in the stack is a return instruction, get the return
        value (if available).

        :return: The return value (if available, None otherwise).
        """
        try:
            last_instruction = self._execution_stack.get()
            # 0F is a return instruction (e.g., return v5).
            if last_instruction[0] == 0x0F:
                return self._register_values[last_instruction[1][0][1]]
            else:
                return None
        except IndexError:
            return None

    def get_last_instruction_register_to_value_mapping(self):
        if not self._register_values or not self._execution_stack:
            return None

        mapping = []
        try:
            last_instruction_operands = self._execution_stack.get()[1]
            for operand in last_instruction_operands:
                if operand[0] == Operand.REGISTER:
                    # operand[1] is the register number.
                    mapping.append(self.get_register_value(operand[1]))
                else:
                    mapping.append(None)

            return mapping
        except IndexError:
            return None
