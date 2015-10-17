#include "dec_cpu.hpp"

int main(int argc, char const *argv[])
{
    dec::Cpu oracle;

    FILE* out = fopen("isa.txt", "w");

    auto decode = [&](unsigned char * source, size_t const length)
    {
        auto result = oracle.DecodeInstruction(source, length);

        for (auto i = 0u; i < length; ++i)
        {
            printf("%02X", source[i]);
        }
        printf(" -> %s\n", ("INVALID\0" "VALID\0\0\0" "LONGER\0\0" "SMALLER\0") + 8 * result);
    };

    auto encodeOpcodes = [&]()
    {
        auto dumpBytes = [&](unsigned char * const begin, unsigned char * const end)
        {
            for (unsigned char * p = begin; p < end; ++p)
            {
                printf("%02X ", *p);
                fprintf(out, "%02X ", *p);
            }
            printf("\n");
            fprintf(out, "\n");
        };

        auto encode1BOpcode = [&](unsigned char * const begin, unsigned char * const end)
        {
            auto encode2BOpcode = [&](unsigned char * const begin, unsigned char * const end)
            {
                auto encode3BOpcode = [&](unsigned char * const begin, unsigned char * const end)
                {
                    for (size_t byte = 0x00; byte <= 0xFF; ++byte)
                    {
                        unsigned char * p = end;
                        *p++ = byte;
                        oracle.DecodeInstructionState(begin, size_t(p - begin));
                        switch (oracle.m_instruction_state)
                        {
                        case dec::Cpu::valid:
                            dumpBytes(begin, p);
                            break;
                        case dec::Cpu::longer:
                            break;
                        default:
                            break;
                        }
                    }
                };

                for (size_t byte = 0x00; byte <= 0xFF; ++byte)
                {
                    unsigned char * p = end;
                    *p++ = byte;
                    oracle.DecodeInstructionState(begin, size_t(p - begin));
                    switch (oracle.m_instruction_state)
                    {
                    case dec::Cpu::valid:
                        dumpBytes(begin, p);
                        break;
                    case dec::Cpu::longer:
                        encode3BOpcode(begin, p);
                        break;
                    default:
                        break;
                    }
                }
            };

            for (size_t byte = 0x00; byte <= 0xFF; ++byte)
            {
                unsigned char * p = end;
                *p++ = byte;
                if (oracle.DecodeInstructionPrefixBytes(begin, size_t(p - begin)))
                {
                    oracle.DecodeInstructionState(begin, size_t(p - begin));
                    switch (oracle.m_instruction_state)
                    {
                    case dec::Cpu::valid:
                        dumpBytes(begin, p);
                        break;
                    case dec::Cpu::longer:
                        encode2BOpcode(begin, p);
                        break;
                    default:
                        break;
                    }
                }
            }
        };

        for (size_t mask = 0x00; mask <= 0x03; ++mask)
        {
            unsigned char buffer[32], * end = buffer;
            oracle.m_operand_size = 4;
            oracle.m_address_size = sizeof(intptr_t);
            if (mask & 0x02) *end++ = 0x67;
            if (mask & 0x01) *end++ = 0x66;
            encode1BOpcode(buffer, end);
        }
    };

#if 0
    unsigned char source0[] = { 0xB0 };
    unsigned char source1[] = { 0xB8 };
    unsigned char source2[] = { 0xB0, 0x00 }; // mov al,0
    unsigned char source3[] = { 0xB8, 0x00 };
    unsigned char source4[] = { 0xB8, 0x00, 0x00 };
    unsigned char source5[] = { 0xB8, 0x00, 0x00, 0x00 };
    unsigned char source6[] = { 0xB8, 0x00, 0x00, 0x00, 0x00 }; // mov eax, 0
    unsigned char source7[] = { 0x0F, 0x0B };
    unsigned char source8[] = { 0xB0, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00 };

    decode(source0, sizeof(source0));
    decode(source1, sizeof(source1));
    decode(source2, sizeof(source2));
    decode(source3, sizeof(source3));
    decode(source4, sizeof(source4));
    decode(source5, sizeof(source5));
    decode(source6, sizeof(source6));
    decode(source7, sizeof(source7));
    decode(source8, sizeof(source8));
#endif

    encodeOpcodes();

    fclose(out);

    return 0;
}
