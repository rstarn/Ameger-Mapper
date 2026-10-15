#pragma once

/*
 * Shared console styling for every diagnostic the tool prints.
 *
 * Both Mapper.exe and SymbolTool.exe include this header, so the two programs
 * draw their output from one definition of the colours, the indent and the tag
 * rules rather than each carrying its own copy.
 *
 * The rules, applied once here instead of at every call site:
 *   - every line is indented two spaces by Log()
 *   - a leading "[x]" tag is coloured by its class: [+] green, [i] and
 *     [INFO] yellow, [-] red, [!], [<] and [*] cyan
 *   - a value wrapped in Val() prints green, so addresses, offsets, counts,
 *     statuses and names stand out from the prose around them
 *   - AMEGER_NO_COLOR=1 resolves every sequence to an empty string, so the
 *     output degrades to plain text with the same wording and no escape bytes
 *
 * The prompt and the usage text are flush left on purpose; they use LogRaw(),
 * which keeps the tag colouring but not the indent.
 */

#include <Windows.h>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <type_traits>

namespace Console
{
	/*
	 * Read an on/off environment variable.
	 *
	 * Accepts the spellings a user would actually type - 1, true, yes, on and
	 * their negatives - rather than the single leading character the old test
	 * compared against. AMEGER_NO_COLOR=10 and =true both used to enable colour,
	 * so the variable was very nearly the opposite of what it says.
	 */
	inline bool EnvironmentFlag(const wchar_t* name) {
		wchar_t value[16] = { 0 };
		const DWORD length = GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
		//0 is "not set", at or above the buffer size is truncation: neither is a
		//value this can judge, and neither should be read as one.
		if (length == 0 || length >= std::size(value))
			return false;

		std::wstring text(value, length);
		for (wchar_t& c : text) {
			if (c >= L'A' && c <= L'Z')
				c = static_cast<wchar_t>(c - L'A' + L'a');
		}

		if (text == L"1" || text == L"true" || text == L"yes" || text == L"on")
			return true;
		if (text == L"0" || text == L"false" || text == L"no" || text == L"off")
			return false;

		//Something else entirely: not a request for the behaviour.
		return false;
	}

	//True when AMEGER_NO_COLOR asks for plain output. Read once, at first
	//use, so every colour below and EnableAnsiColors() agree on the answer.
	inline bool ColorsDisabled() {
		static const bool disabled = EnvironmentFlag(L"AMEGER_NO_COLOR");
		return disabled;
	}

	//True when AMEGER_VERBOSE asks for the per-entry diagnostics that would
	//otherwise flood the log (e.g. every restored page-table entry).
	inline bool Verbose() {
		static const bool verbose = EnvironmentFlag(L"AMEGER_VERBOSE");
		return verbose;
	}

	//The sequence itself, or an empty string when colour is disabled.
	inline const wchar_t* ColorOrPlain(const wchar_t* code) {
		return ColorsDisabled() ? L"" : code;
	}

	inline const wchar_t* const kReset = ColorOrPlain(L"\x1b[0m");
	inline const wchar_t* const kGreen = ColorOrPlain(L"\x1b[92m");
	inline const wchar_t* const kRed = ColorOrPlain(L"\x1b[91m");
	inline const wchar_t* const kYellow = ColorOrPlain(L"\x1b[93m");
	inline const wchar_t* const kCyan = ColorOrPlain(L"\x1b[96m");

	/*
	 * Turn on ANSI escape processing so the sequences above are drawn rather
	 * than printed literally.
	 *
	 * Idempotent and safe to call from several translation units: the mode is
	 * set once, the first time it is needed. It is a no-op under
	 * AMEGER_NO_COLOR=1 and when stdout is not a console (a redirected file
	 * keeps the bytes out of it entirely, so a log still reads as plain text).
	 */
	inline void EnableAnsiColors() {
		if (ColorsDisabled())
			return;

		static const bool enabled = [] {
			const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
			if (console == INVALID_HANDLE_VALUE || console == nullptr)
				return true;

			DWORD mode = 0;
			if (!GetConsoleMode(console, &mode))
				return true;

			SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
			return true;
		}();
		(void)enabled;
	}

	//Widen an ASCII identifier. Every string the tool widens this way is a
	//narrow module, symbol or driver name, so a per byte copy is correct and
	//needs no locale.
	inline std::wstring ToWide(const char* text) {
		const std::string narrow(text ? text : "");
		return std::wstring(narrow.begin(), narrow.end());
	}

	//A value to print in green. Built by Val()/Hex(); streamed through the
	//operator below so the green span wraps exactly the value and nothing else.
	struct GreenText {
		std::wstring text;
	};

	inline std::wostream& operator<<(std::wostream& stream, const GreenText& value) {
		return stream << kGreen << value.text << kReset;
	}

	//An integer as 0x-prefixed hexadecimal.
	template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
	inline std::wstring Hex(T value) {
		std::wostringstream stream;
		stream << L"0x" << std::hex << value;
		return stream.str();
	}

	//Wrap a value so it prints green. A pointer prints as 0x-prefixed hex; an
	//integer prints in decimal, so Hex() is used where hex is wanted.
	inline GreenText Val(const std::wstring& text) { return GreenText{ text }; }
	inline GreenText Val(const wchar_t* text) { return GreenText{ text ? text : L"" }; }
	inline GreenText Val(wchar_t* text) { return GreenText{ text ? text : L"" }; }
	inline GreenText Val(const char* text) { return GreenText{ ToWide(text) }; }
	inline GreenText Val(const void* pointer) {
		//Formatted the same way as Hex() (lowercase, 0x-prefixed) rather than
		//with operator<<(void*), which on MSVC prints the C %p form: uppercase
		//and without the 0x that every other address in the output carries.
		std::wostringstream stream;
		stream << L"0x" << std::hex << reinterpret_cast<uintptr_t>(pointer);
		return GreenText{ stream.str() };
	}
	template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
	inline GreenText Val(T value) { return GreenText{ std::to_wstring(value) }; }

	//Colour of a one character tag, or null when the tag is not one of ours.
	inline const wchar_t* TagColor(wchar_t tag) {
		switch (tag) {
		case L'+': return kGreen;
		case L'i': return kYellow;
		case L'!': return kCyan;
		case L'-': return kRed;
		case L'<': return kCyan;
		case L'*': return kCyan;
		default: return nullptr;
		}
	}

	//Write text, colouring a leading "[x]" tag when it is one of ours. "[!!]"
	//(the crash handler) and the six character "[INFO]" are treated as tags as
	//well. Text that carries no recognised tag is written unchanged.
	inline void WriteTagged(const std::wstring& text) {
		size_t tag_length = 0;
		const wchar_t* color = nullptr;

		if (text.size() >= 4 && text.compare(0, 4, L"[!!]") == 0) {
			tag_length = 4;
			color = kRed;
		}
		else if (text.size() >= 6 && text.compare(0, 6, L"[INFO]") == 0) {
			tag_length = 6;
			color = kYellow;
		}
		else if (text.size() >= 3 && text[0] == L'[' && text[2] == L']') {
			tag_length = 3;
			color = TagColor(text[1]);
		}

		if (!color) {
			std::wcout << text;
			return;
		}

		std::wcout << color << text.substr(0, tag_length) << kReset << text.substr(tag_length);
	}

	/*
	 * One log line. The Log macro builds a temporary Line and streams the
	 * caller's content into it, so the indent and the tag colour are applied in
	 * exactly one place. A Line with indent = false is the flush left variant
	 * used by the interactive prompt and the usage text.
	 */
	class Line {
	public:
		explicit Line(bool indent = true) : indent_(indent) {}

		Line& operator<<(const wchar_t* text) {
			Begin();
			WriteTagged(text ? text : L"");
			return *this;
		}

		Line& operator<<(const char* text) {
			Begin();
			WriteTagged(ToWide(text));
			return *this;
		}

		//A prebuilt line (e.g. one buffered so it can be printed after a value
		//it depends on). Without this overload the generic template below would
		//stream it raw and the leading tag would lose its colour.
		Line& operator<<(const std::wstring& text) {
			Begin();
			WriteTagged(text);
			return *this;
		}

		//std::endl and friends; resolved explicitly because a function
		//template cannot be deduced by the generic overload below.
		Line& operator<<(std::wostream& (*manipulator)(std::wostream&)) {
			Begin();
			std::wcout << manipulator;
			return *this;
		}

		//std::hex, std::dec and friends.
		Line& operator<<(std::ios_base& (*manipulator)(std::ios_base&)) {
			Begin();
			std::wcout << manipulator;
			return *this;
		}

		template <typename T>
		Line& operator<<(const T& value) {
			Begin();
			std::wcout << value;
			return *this;
		}

	private:
		void Begin() {
			if (!started_) {
				if (indent_)
					std::wcout << L"  ";
				started_ = true;
			}
		}

		bool indent_ = true;
		bool started_ = false;
	};
}

//Indented, tag-coloured diagnostic line.
//
// Variadic rather than a single parameter: the single parameter form breaks on
//any top level comma in the argument, so a call that streamed two values as
//`a, b` - a pair, a ternary, a constructor call - did not compile, and the fix
//was to add parentheses at that call site rather than here. __VA_ARGS__ is the
//one spelling that treats the whole expression list as the stream argument.
#define Log(...) Console::Line() << __VA_ARGS__

//Flush left variant, for the interactive prompt and the usage text.
#define LogRaw(...) Console::Line(false) << __VA_ARGS__

//A bare blank line, used to separate output sections. Never indented.
#define LogBlank() (std::wcout << std::endl)

//Val()/Hex() are used unqualified at the call sites to keep them readable.
using Console::Val;
using Console::Hex;
