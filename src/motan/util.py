#!/usr/bin/env python3

import logging
import os
import plistlib
import re
import zipfile
from typing import Iterable, List

from androguard.core.bytecodes import dvm
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import Instruction
from tqdm import tqdm

logger = logging.getLogger(__name__)


# When iterating over list L, use
# "for element in show_list_progress(L, interactive=True)"
# to show a progress bar. When setting "interactive=False", no progress bar will be
# shown. While using this method, no other code should write to standard output.
def show_list_progress(
    the_list: Iterable,
    interactive: bool = False,
    unit: str = "unit",
    description: str = None,
):
    if not interactive:
        return the_list
    else:
        return tqdm(
            the_list,
            dynamic_ncols=True,
            unit=unit,
            desc=description,
            bar_format="{l_bar}{bar}|[{elapsed}<{remaining}, {rate_fmt}]",
        )


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
    ):
        """
        This class virtually executes the list of instructions passed as parameter.

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
        """
        self._register_values = {}
        self._execution_stack = RegisterAnalyzer.Stack()

        self.load_instructions(instructions_to_execute, max_num_of_instructions)

    def _add(self, op_code: int, operands: List[tuple]):
        if operands:
            # Push op code and operands. Format: <const/4 v5, 1> is saved as
            # <[18, [(0, 5), (1, 1)]]>.
            self._execution_stack.push([op_code, operands])

            # [const], [const/xx], [const-string]
            if 0x12 <= op_code <= 0x1C:
                destination_register = operands[0]
                value_for_register = operands[1]
                if destination_register[0] == dvm.OPERAND_REGISTER:
                    destination_register_num = destination_register[1]

                    # value_for_register will be stored in register with number
                    # destination_register_num.

                    if value_for_register[0] & dvm.OPERAND_KIND:
                        # value_for_register has 3 elements, the last being the actual
                        # value.
                        immediate_value = value_for_register[2]
                        self._register_values[
                            destination_register_num
                        ] = self.strip_string(immediate_value)
                    elif value_for_register[0] == dvm.OPERAND_LITERAL:
                        # value_for_register has 2 elements, the last being the actual
                        # value.
                        immediate_value = value_for_register[1]
                        self._register_values[
                            destination_register_num
                        ] = self.strip_string(immediate_value)

            # [move], [move/from]
            elif 0x01 <= op_code <= 0x02:
                # The content of one register is moved to another register.
                destination_register = operands[0]
                source_register = operands[1]
                if (
                    destination_register[0] == dvm.OPERAND_REGISTER
                    and source_register[0] == dvm.OPERAND_REGISTER
                ):
                    # Get the value from the other register (if available).
                    self._register_values[
                        destination_register[1]
                    ] = self._register_values.get(source_register[1])

            # [move-result], [move-result-wide], [move-result-object], [move-exception]
            elif 0x0A <= op_code <= 0x0D:
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                self._register_values[register_number] = None

            # [aget], [aget-xx], [iget], [iget-xx], [sget], [sget-xx]
            elif (
                (0x44 <= op_code <= 0x4A)
                or (0x52 <= op_code <= 0x58)
                or (0x60 <= op_code <= 0x66)
            ):
                register_number = operands[0][1]
                # This is not a constant value, so the value it's known only at runtime.
                self._register_values[register_number] = None

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
                if operand[0] == dvm.OPERAND_REGISTER:
                    # operand[1] is the register number.
                    mapping.append(self.get_register_value(operand[1]))
                else:
                    mapping.append(None)

            return mapping
        except IndexError:
            return None
