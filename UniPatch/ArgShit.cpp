#include "ArgShit.h"
#include <sstream>
#include <codecvt>
#include <locale>

std::wstring to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
    return strconverter.from_bytes(str);
}

std::string to_string(const std::wstring& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
    return strconverter.to_bytes(str);
}

std::string leadingZero(uint64_t num) {
    std::stringstream stream;
    stream << (num < 16 ? "0" : "") << std::hex << (0xFF & num);
    return stream.str();
}

ArgShit::ArgShit() : i(0), s(L"") {}

ArgShit::ArgShit(char* _argv[], int _argc, const char* find) : i(0), s(L"") {
    this->argv = _argv;
    this->argc = _argc;
    this->parseArg(find);
}

ArgShit::ArgShit(char* _argv[], int _argc) : i(0), s(L"") {
    this->argv = _argv;
    this->argc = _argc;
}

void ArgShit::parseArg(const char* find) {
    i = 0;
    s = L"";
    if (argc > 3) {
        for (int o = 2; o < argc - 1; ++o) {
            if (strcmp(argv[o], find) == 0 && strlen(argv[o + 1]) > 0) {
                std::stringstream conv(argv[o + 1]);
                conv >> i;
                s = to_wstring(conv.str());
                break; // No need to continue after finding the argument
            }
        }
    }
}

char* ArgShit::getArg(int ind) {
    if (ind < argc)
        return argv[ind];
    else
        return nullptr; // Return nullptr for out-of-bounds access
}

bool ArgShit::contains(const char* test) const{
    if (argc > 2) {
        for (int _i = 2; _i < argc; ++_i) {
            if (strcmp(argv[_i], test) == 0)
                return true;
        }
    }
    return false;
}

int ArgShit::getInt() {
    return i;
}

std::wstring ArgShit::getString() {
    return s;
}
