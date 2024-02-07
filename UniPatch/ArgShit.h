#pragma once
#include <string>
#include <sstream>
#include <codecvt>

std::wstring to_wstring(const std::string& str);
std::string to_string(const std::wstring& str);
std::string leadingZero(uint64_t num);

class ArgShit {
private:
    char** argv;
    int argc;
    int i;
    std::wstring s;

public:
    ArgShit();

    ArgShit(char* _argv[], int _argc);

    ArgShit(char* _argv[], int _argc, const char* find);

    void parseArg(const char* find);

    char* getArg(int ind);

    bool contains(const char* test) const;

    int getInt();

    std::wstring getString();
};
