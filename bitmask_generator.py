#!/bin/env python3

from sly import Lexer, Parser
import sys

def proper_hex (v):
	return hex(v).upper().replace("0X", "0x")

class Log:
	ERRORS = 0
	WARNINGS = 0

	def print_error (*args, **kwargs):
		print("// ", file=sys.stderr, end='')
		print(*args, file=sys.stderr, **kwargs)
		Log.ERRORS += 1

	def print_warning (*args, **kwargs):
		print("// ", file=sys.stderr, end='')
		print(*args, file=sys.stderr, **kwargs)
		Log.WARNINGS += 1

	def print(*args, **kwargs):
		print("// ", end='')
		print(*args, **kwargs)

	def print_debug (*args, **kwargs):
		print("// ", end='')
		print(*args, **kwargs)

	def print_summary ():
		Log.print(
			"Completed with "
			+ str(Log.ERRORS)
			+ " error(s) and "
			+ str(Log.WARNINGS)
			+ " warning(s)."
		)

class TokenLocation:
	def __init__ (this, token):
		this.filename = BitmaskGeneratorParser.CURRENT_FILE
		this.line = token.lineno
		this.column = token.index - BitmaskGeneratorParser.COLUMN_STARTS_AT

		if (this.column < 0):
			this.column = 0

	def get_filename (this) -> str:
		return this.filename

	def get_line (this) -> int:
		return this.line

	def get_column (this) -> int:
		return this.column

	def to_string (this) -> str:
		return (
			this.get_filename()
			+ ":"
			+ str(this.get_line())
			+ ","
			+ str(this.get_column())
		)

class Device:
	LIST = list()

	def __init__ (
		this,
		name: str,
		registers: list(),
		address: int = None,
		instances: int = 1,
		offset: int = 0
	):
		this.name = name
		this.registers = registers
		this.address = address
		this.instances = instances
		this.offset = offset
		Device.LIST.insert(0, this)

	def generate_code (this):
		result = ""

		result += "/" + (78 * "*") + "/\n"
		result += "/** " + this.name.upper() + " " + ((74 - len(this.name)) * '*') + "/\n"
		result += "/" + (78 * "*") + "/\n"

		if (this.address is not None):
			if this.instances == 1:
				result += "#define " + this.name.upper() + "_ADDR " + proper_hex(this.address) + "U\n"
			else:
				for i in range(0, this.instances):
					result += (
						"#define "
						+ this.name.upper()
						+ "_"
						+ str(i)
						+ "_ADDR "
						+ proper_hex(this.address + (this.offset * i))
						+ "U\n"
					)
				result += "\n"
				result += "#define " + this.name.upper() + "_X_ADDR(x) \\\n"
				result += (
					"\t("
					+ this.name.upper()
					+ "_0_ADDR + (("
					+ this.name.upper()
					+ "_1_ADDR - "
					+ this.name.upper()
					+ "_0_ADDR) * (x))"
				)

		for i in this.registers:
			result += "\n"
			result += "/** " + i.long_name.upper() + " " + ((74 - len(i.long_name)) * '*') + "/\n"
			result += i.generate_code(this)

		result += "/" + (78 * "*") + "/\n"

		return result

class Register:
	def __init__ (
		this,
		long_name: str,
		fields: list((str, int)),
		offset: int = None,
		short_name: str = None
	):
		this.long_name = long_name
		this.fields = fields
		this.offset = offset
		this.short_name = long_name if short_name is None else short_name

	def generate_code (this, parent: Device = None):
		result = ""
		x_name = (parent.name + "_X_" + this.long_name).upper()
		long_name = (parent.name + "_" + this.long_name).upper()
		short_name = (parent.name + "_" + this.short_name).upper()

		if this.offset is not None:
			result += (
				"#define "
				+ long_name
				+ "_ADDR_OFFSET "
				+ proper_hex(this.offset)
				+ "U"
			)
			result += "\n"

		if (parent is not None) and (this.offset is not None):
			if parent.instances == 1:
				result += "#define " + long_name.upper() + "_ADDR \\\n"
				result += "\t(" + parent.name + "_ADDR + " + long_name + "_ADDR_OFFSET)\n"
				result += "#define " + long_name.upper() + "_ADDR \\\n"
				result += "\t__TO_PTR(" + long_name.upper() + "_ADDR)\n"
				result += "\n"
			else:
				result += "#define " + x_name + "_ADDR(x) \\\n"
				result += "\t(" + parent.name + "_X_ADDR(x) + " + long_name + "_ADDR_OFFSET)\n"
				result += "#define " + x_name_ + "_ADDR(x) \\\n"
				result += "\t__TO_PTR(" + x_name + "_ADDR(x))\n"
				result += "\n"

		if len(this.fields) == 0:
			return result

		result += "struct " + long_name.lower() + "\n"
		result += "{\n"
		result += "\tunion\n"
		result += "\t{\n"

		result += "\t\tstruct\n"
		result += "\t\t{\n"
		remains = 32
		for (n, s) in this.fields:
			result += "\t\t\tuint32_t " + n + ":" + str(s) + ";\n"
			remains -= s

		if (remains > 0):
			result += "\t\t\tuint32_t _reserved:" + str(remains) + ";\n"
		result += "\t\t}\n"
		result += "\t\tuint32_t reg_value;\n"
		result += "\t}\n"
		result += "}\n"
		result += "\n"
		result += "#define " + short_name + "_GET(NAME, reg) \\\n"
		result += (
			"\t(((reg) >> " + short_name + "_##NAME##_OFFSET) & ("
			+ short_name + "_##NAME##_MASK))\n"
		)

		result += "\n"
		result += "#define " + short_name + "_SET(NAME, val, reg) \\\n"
		result += "\t( \\\n"
		result += "\t\t((reg) & ~(" + short_name + "_##NAME##_MASK)) \\\n"
		result += "\t\t| \\\n"
		result += "\t\t( \\\n"
		result += "\t\t\t((val) & (" + short_name + "_##NAME##_MASK)) \\\n"
		result += "\t\t\t<< (" + short_name + "_##NAME##_OFFSET) \\\n"
		result += "\t\t) \\\n"
		result += "\t)\n"
		result += "\n"

		result += "#define " + short_name + "_SET_IN_PLACE(NAME, val, reg) \\\n"
		result += "\t(reg) = \\\n"
		result += "\t\t( \\\n"
		result += "\t\t\t((reg) & ~(" + short_name + "_##NAME##_MASK)) \\\n"
		result += "\t\t\t| \\\n"
		result += "\t\t\t( \\\n"
		result += "\t\t\t\t((val) & (" + short_name + "_##NAME##_MASK)) \\\n"
		result += "\t\t\t\t<< (" + short_name + "_##NAME##_OFFSET) \\\n"
		result += "\t\t\t) \\\n"
		result += "\t\t)\n"
		result += "\n"

		result += "#if (__USE_OF_BITFIELDS_UNION_IS_SAFE == 1)\n"
		result += "\t#define " + short_name + "_TO_UINT32_T(s) ((s).reg_value)\n"
		result += "#else\n"
		result += "\t#define " + short_name + "_TO_UINT32_T(s) \\\n"
		result += "\t\t( \\\n"

		current_level = 0
		for (n, s) in this.fields:
			indent = "\t\t\t" + ( current_level * "\t")
			result += indent + short_name + "_SET \\\n"
			result += indent + "( \\\n"
			result += indent + "\t" + n.upper() + ", \\\n"
			result += indent + "\t" + "(s)." + n + ", \\\n"
			current_level += 1

		result += "\t\t\t" + ( current_level * "\t") + "0 \\\n"
		current_level -= 1

		while (current_level >= 0):
			result += "\t\t\t" + ( current_level * "\t") + ") \\\n"
			current_level -= 1

		result += "\t\t)\n"
		result += "#endif\n"
		result += "\n"

		current_offset = 0
		for (n, s) in this.fields:
			end = current_offset + s
			mask = "0b" + (s * "1") + ("0" * current_offset)
			if s == 1:
				result += "// Bit " + str(current_offset) + ": " + n.upper() + "\n"
			else:
				result += (
					"// Bits "
					+ str(current_offset)
					+ "-"
					+ str(end - 1)
					+ ": "
					+ n.upper()
					+ "\n"
				)
			result += (
				"#define "
				+ short_name
				+ "_" + n.upper()
				+ "_OFFSET "
				+ str(current_offset)
				+ "U\n"
			)
			result += (
				"#define "
				+ short_name
				+ "_" + n.upper()
				+ "_MASK "
				+ proper_hex(int(mask, 2))
				+ "U\n"
			)
			result += "\n"

			current_offset = end

		return result

class BitmaskGeneratorLexer (Lexer):
	tokens = {
		NUMBER,
		ID,

		DEVICE_KW,
		REGISTER_KW,
		MEMBER_KW,

		EOP,
	}

	@_(r'[1-9][0-9]*')
	@_(r'0x[a-fA-F0-9]+')
	@_(r'0X[a-fA-F0-9]+')
	def NUMBER (this, t):
		if t.value.startswith("0"):
			t.value = int(t.value, 16)
		else:
			t.value = int(t.value)
		return t

	ID = r'([a-zA-Z_][a-zA-Z_0-9]*)'

	DEVICE_KW = r'(?i:\(DEVICE)'
	REGISTER_KW = r'(?i:\(REGISTER)'
	MEMBER_KW = r'(?i:\(MEMBER)'

	EOP = r'\)'

	ignore_comments = r';;.*'

	@_('\r?\n')
	def ignore_newline (this, t):
		this.lineno += 1
		BitmaskGeneratorParser.COLUMN_STARTS_AT = this.index

	ignore = ' \t'

	def error (this, t):
		Log.print_error(
			"Syntax error. Unexpected \"" + str(t.value) + "\".",
			BitmaskGeneratorParser.get_cursor(t)
		)
		raise Exception

class BitmaskGeneratorParser (Parser):
	COLUMN_STARTS_AT = 0
	CURRENT_FILE = None
	LAST_TOKEN = None

	tokens = BitmaskGeneratorLexer.tokens

	def get_cursor (t, use_column = True) -> str:
		column = t.index - BitmaskGeneratorParser.COLUMN_STARTS_AT
		result = BitmaskGeneratorParser.CURRENT_FILE
		result += ":" + str(t.lineno)

		if (use_column):
			result += "," + str(column)

		result += "\n"

		with open(BitmaskGeneratorParser.CURRENT_FILE, 'r') as file:
			line_content = file.readlines()[t.lineno - 1][:-1]

		result += line_content.replace("\t", " ")
		result += "\n"

		if (use_column):
			result += ' ' * column + "^"
		else:
			result += len(line_content) * "^"

		result += "\n"

		return result

	def print_warning (msg, t):
		Log.print_warning("[W] " + msg + "\n" + BitmaskGeneratorParser.get_cursor(t, False))

	def print_error (msg, t):
		Log.print_error("[E] " + msg + "\n" + BitmaskGeneratorParser.get_cursor(t, False))

	#### FILE ###################################################################
	@_(r'')
	def file (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return t

	@_(r'file_entry file')
	def file (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return t

	@_(r'DEVICE_KW ID register_definitions EOP')
	def file_entry (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Device(t.ID, t.register_definitions)

	@_(r'DEVICE_KW NUMBER ID register_definitions EOP')
	def file_entry (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Device(t.ID, t.register_definitions, t.NUMBER)

	#### REGISTER DEFINITIONS ###################################################
	@_(r'')
	def register_definitions (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return list()

	@_(r'register_definition register_definitions')
	def register_definitions (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		t.register_definitions.insert(0, t.register_definition)

		return t.register_definitions

	#### REGISTER DEFINITION ####################################################
	@_(r'REGISTER_KW NUMBER ID ID member_definitions EOP')
	def register_definition (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Register(t.ID0, t.member_definitions, t.NUMBER, t.ID1)

	@_(r'REGISTER_KW ID ID member_definitions EOP')
	def register_definition (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Register(t.ID0, t.member_definitions, short_name = t.ID1)

	@_(r'REGISTER_KW NUMBER ID member_definitions EOP')
	def register_definition (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Register(t.ID, t.member_definitions, offset = t.NUMBER)

	@_(r'REGISTER_KW ID member_definitions EOP')
	def register_definition (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return Register(t.ID, t.members)

	#### REGISTER DEFINITIONS ###################################################
	@_(r'')
	def member_definitions (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return list()

	@_(r'member_definition member_definitions')
	def member_definitions (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		t.member_definitions.insert(0, t.member_definition)

		return t.member_definitions

	#### MEMBER DEFINITION ######################################################
	@_(r'MEMBER_KW ID NUMBER EOP')
	def member_definition (this, t):
		BitmaskGeneratorParser.LAST_TOKEN = t

		return (t.ID, t.NUMBER)

	def error (self, t):
		Log.print_error(
			"Syntax error. Unexpected \"" + str(t.value) + "\".",
			BitmaskGeneratorParser.get_cursor(t)
		)
		raise Exception

	def parse_files (file_list):
		for f in file_list:
			with open(f, 'r') as file:
				Log.print_debug("Parsing " + f + "...")

				lexer = BitmaskGeneratorLexer()
				parser = BitmaskGeneratorParser()
				BitmaskGeneratorParser.CURRENT_FILE = f

				try:
					parser.parse(lexer.tokenize(file.read()))
				except Exception as e:
					BitmaskGeneratorParser.print_error(str(e), BitmaskGeneratorParser.LAST_TOKEN)
					file.close()
					raise e

				file.close()

BitmaskGeneratorParser.parse_files(sys.argv[1:])

print("#include <stdint.h>\n")
print("#define __TO_PTR(x) ((volatile uint32_t *)(x))")
for d in Device.LIST:
	print(d.generate_code())
Log.print_summary()
