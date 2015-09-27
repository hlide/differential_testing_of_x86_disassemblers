#include "dec_cpu.hpp"

int main(int argc, char const *argv[])
{
    dec::Cpu oracle;

    auto decode = [&](unsigned char * source, size_t const length)
    {
        auto result = oracle.DecodeInstruction(source, length);

        for (auto i = 0u; i < length; ++i)
        {
            printf("%02X", source[i]);
        }
        printf(" -> %s\n", ("INVALID\0" "VALID\0\0\0" "LONGER\0\0") + 8*result);
    };

    unsigned char source0[] = { 0xB0 };
    unsigned char source1[] = { 0xB8 };
    unsigned char source2[] = { 0xB0, 0x00 };
    unsigned char source3[] = { 0xB8, 0x00 };
    unsigned char source4[] = { 0xB8, 0x00, 0x00 };
    unsigned char source5[] = { 0xB8, 0x00, 0x00, 0x00 };
    unsigned char source6[] = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
    //unsigned char source7[] = { 0xCC };

    decode(source0, sizeof(source0));
    decode(source1, sizeof(source1));
    decode(source2, sizeof(source2));
    decode(source3, sizeof(source3));
    decode(source4, sizeof(source4));
    decode(source5, sizeof(source5));
    decode(source6, sizeof(source6));
    //decode(source7, sizeof(source7));

    return 0;
}
