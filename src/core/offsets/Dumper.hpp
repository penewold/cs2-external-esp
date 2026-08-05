#pragma once
#include "core/memory/IMemory.hpp"
#include "Offsets.hpp"

inline const size_t MAX_BLOCK_SIZE = 409600;

class Dumper {
public:
    ~Dumper()                           = default;
    Dumper(const Dumper&)            = delete;
    Dumper(Dumper&&)                 = delete;
    Dumper& operator=(const Dumper&) = delete;
    Dumper& operator=(Dumper&&)      = delete;

   static bool Init();
private:
    Dumper() {};

    static Dumper& GetInstance()
    {
        static Dumper i{};
        return i;
    }

    bool InitImpl();
private:
    std::vector<WORD> StrSigToArray(const std::string& sig);
    uintptr_t Scan(const std::string sig, ProcessModule module);
    void GetNextArray(std::vector<short>& next, const std::vector<WORD>& signature);
    std::vector<uintptr_t> ScanMemory(const std::string& sig, uintptr_t start, uintptr_t end, int number = 1);
    void ScanBlock(byte* buffer, const std::vector<short>& next, const std::vector<WORD>& signature, uintptr_t start, size_t size, std::vector<uintptr_t>& result);
};