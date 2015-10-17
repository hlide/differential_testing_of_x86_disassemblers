#pragma once

#include <windows.h>
#include <excpt.h>

#include <cstdio>
#include <exception>

namespace dec
{
    class Cpu
    {
    public:
        enum InstructionState
        {
            invalid,
            valid,
            longer,
            smaller
        };

        Cpu()
        {
            m_buffer = reinterpret_cast< unsigned char * >(::VirtualAlloc(nullptr, 2 * 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (m_buffer)
            {
                DWORD dummy;
                ::VirtualProtect(m_buffer + 0x1000, 4096, PAGE_NOACCESS, &dummy);
            }
            else
            {
                fprintf(stderr, "ERROR: cannot allocate two virtual pages\n");
                abort();
            }
        }

        ~Cpu()
        {
            if (m_buffer)
            {
                ::VirtualFree(m_buffer, 0, MEM_RELEASE);
            }
        }

#ifdef _WIN64
        static int Filter(Cpu * that, unsigned int code, PEXCEPTION_POINTERS ep)
        {
            printf("EXC: @%016X\n", ep->ContextRecord->Rip);
            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                that->m_instruction_state = longer;
                return EXCEPTION_EXECUTE_HANDLER;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                that->m_instruction_state = invalid;
                return EXCEPTION_EXECUTE_HANDLER;
                //case EXCEPTION_BREAKPOINT:
            case EXCEPTION_PRIV_INSTRUCTION:
            case EXCEPTION_SINGLE_STEP:
                that->m_length = ep->ContextRecord->Eip -
                    that->m_instruction_state = valid;
                return EXCEPTION_EXECUTE_HANDLER;
            default:
                fprintf(stderr, "ERROR: code: 0x%016XULL\n", code);
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }

        InstructionState DecodeInstruction(unsigned char const * source, size_t const length)
        {
            __try
            {
                m_length = 0;
                m_instruction_state = invalid;
                m_target = m_buffer + 0x1000 - length;
                {
                    printf("copying %u bytes into [%016X-%016X[\n", length, DWORD64(target), DWORD64(target + length));
                    memcpy(target, source, length);
                    // NOT WORKING FOR AMD64...
                    m_context.ContextFlags = CONTEXT_ALL;
                    if (0 == ::GetThreadContext(::GetCurrentThread(), &m_context))
                    {
                        auto last_error = ::GetLastError();
                        fprintf(stderr, "ERROR: GetThreadContext fails with LastError=%u", last_error);
                    }
                    m_context.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                    m_context.Rip = DWORD64(target);
                    if (0 == ::SetThreadContext(::GetCurrentThread(), &m_context))
                    {
                        auto last_error = ::GetLastError();
                        fprintf(stderr, "ERROR: SetThreadContext fails with LastError=%u", last_error);
                    }
                    printf("unreachable code unless this trick is not working!\n");
                    abort();
                }
            }
            __except (Filter(this, ::_exception_code(), reinterpret_cast<PEXCEPTION_POINTERS>(::_exception_info())))
            {
                if (m_instruction_state == valid)
                {
                    m_length = length;
                }
            }

            return m_instruction_state;
        }
#else
        static int Filter(Cpu * that, unsigned int code, PEXCEPTION_POINTERS ep)
        {
            ULONG_PTR addr = 0;
            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                addr = ep->ExceptionRecord->ExceptionInformation[1];
                that->m_instruction_state = (addr == ULONG_PTR(that->m_buffer + 0x1000)) ? longer : valid;
                return EXCEPTION_EXECUTE_HANDLER;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
            case EXCEPTION_BREAKPOINT:
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            case EXCEPTION_FLT_DENORMAL_OPERAND:
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            case EXCEPTION_FLT_INEXACT_RESULT:
            case EXCEPTION_FLT_INVALID_OPERATION:
            case EXCEPTION_FLT_OVERFLOW:
            case EXCEPTION_FLT_STACK_CHECK:
            case EXCEPTION_FLT_UNDERFLOW:
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
            case EXCEPTION_STACK_OVERFLOW:
            case EXCEPTION_INVALID_DISPOSITION:
            case EXCEPTION_PRIV_INSTRUCTION:
            case EXCEPTION_IN_PAGE_ERROR:
                that->m_instruction_state = valid;
                return EXCEPTION_EXECUTE_HANDLER;
            case EXCEPTION_SINGLE_STEP:
                addr = ULONG_PTR(ep->ExceptionRecord->ExceptionAddress);
                that->m_instruction_state = (addr == ULONG_PTR(that->m_buffer + 0x1000 - 5)) ? valid : (addr < ULONG_PTR(that->m_buffer + 0x1000 - 5)) ? smaller : longer;
                return EXCEPTION_EXECUTE_HANDLER;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                that->m_instruction_state = (*((unsigned short *)ep->ExceptionRecord->ExceptionAddress) == 0x0B0F) ? valid : invalid;
                return EXCEPTION_EXECUTE_HANDLER;
            default:
                fprintf(stderr, "ERROR: code: 0x%08X\n", code);
                that->m_instruction_state = invalid;
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        
        void DecodeInstructionState(unsigned char const * source, size_t const length)
        {
            m_instruction_state = invalid;
            m_target = m_buffer + 0x1000 - length - 5;
            //auto eip_addr = m_target;
            auto eip_addr = m_target - 1 - 5 - 1;
            auto esp_addr = m_target + length + 1;
            memcpy(eip_addr + 0, "\x9C", 1);                        // PUSHFD
            memcpy(eip_addr + 1, "\x80\x4C\x24\x01\x01", 5);        // OR BYTE PTR [ESP+1], 1 ; bit EFLAGS.TF <- 1
            memcpy(eip_addr + 6, "\x9D", 1);                        // POPFD
            memcpy(m_target, source, length);
            m_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // minimal flags to get it working
            ::GetThreadContext(::GetCurrentThread(), &m_context);
            m_esp = m_context.Esp;
            *((DWORD *)esp_addr) = m_esp;
            m_context.Eip = DWORD(eip_addr);
            m_context.Eax = 0;
            m_context.Ebx = 0;
            m_context.Ecx = 0;
            m_context.Edx = 0;
            m_context.Esi = 0;
            m_context.Edi = 0;
            m_context.Ebp = 0;
            __try
            {
                ::SetThreadContext(::GetCurrentThread(), &m_context);
            }
            __except (Filter(this, ::_exception_code(), reinterpret_cast<PEXCEPTION_POINTERS>(::_exception_info())))
            {
            }
        }
#endif

        bool DecodeInstructionPrefixBytes(unsigned char const * source, size_t const length)
        {
            m_prefix_bytes = 0;
            for (size_t i = 0; i < length; ++i)
            {
                auto prefix = source[i];
                switch (prefix)
                {
                case 0x8F: // XOP
                case 0xC4: // VEX
                    ++i;   // Three-byte prefix : need to skip two bytes more
                case 0xC5: // VEX
                    ++i;   // Two-byte prefix : need to skip one byte more
                case 0xF0: // LOCK
                case 0xF2: // REP,REPE, MMX/SSE prefix, XACQUIRE 
                case 0xF3: // REPNE, MMX/SSE prefix, XRELEASE
                case 0x26: // DS:
                case 0x2E: // CS:
                case 0x36: // SS:
                case 0x3E: // DS:
                case 0x64: // FS:
                case 0x65: // GS:
                    break;
                case 0x66: // Operand Size, MMX/SSE prefix
                    m_operand_size = 4;
                    break;
                case 0x67: // Address Size
                    m_address_size = 4;
                    break;
                case 0x40:
                case 0x41:
                case 0x42:
                case 0x43:
                case 0x48:
                case 0x49:
                case 0x4A:
                case 0x4B:
                case 0x44:
                case 0x45:
                case 0x46:
                case 0x47:
                case 0x4C:
                case 0x4D:
                case 0x4E:
                case 0x4F:
                    if (sizeof(intptr_t) == 8) // prefix only in long mode
                    {
                        if (prefix & 4) m_operand_size = 8;
                        break;
                    }
                default:
                    m_prefix_bytes = i;
                    return true;
                }
            }

            return false;
        }

        bool DecodeInstructionImmediateWord(unsigned char const * source, size_t position, size_t const length)
        {
            unsigned char buffer[32];
            memcpy(buffer, source, min(length, 16));
            for (;;)
            {
                if (2 == m_operand_size)
                {
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0x01;
                    DecodeInstructionState(buffer, position + 1);
                    /**/ if (smaller == m_instruction_state)
                    {
                        m_immediate_bytes = 1;
                        return true;
                    }
                    else if (valid   != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0x02;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0xFF;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_immediate_bytes = 2;
                    return true;
                }
                else
                {
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0x00;
                    buffer[position + 2] = 0x00;
                    buffer[position + 3] = 0x01;
                    DecodeInstructionState(buffer, position + 1);
                    /**/ if (smaller == m_instruction_state)
                    {
                        m_immediate_bytes = 1;
                        return true;
                    }
                    else if (valid   != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0x00;
                    buffer[position + 2] = 0x00;
                    buffer[position + 3] = 0x02;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x00;
                    buffer[position + 1] = 0x00;
                    buffer[position + 2] = 0x00;
                    buffer[position + 3] = 0xFF;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_immediate_bytes = 4;
                    return true;
                }
            }
            return false;
        }

        size_t GetModRMSIBDispLength_00(unsigned char const * source) const
        {
            auto SIB = *source;
            auto Base = SIB & 7;
            auto Index = (SIB >> 3) & 7;
            return (5 == Base && 4 == Index) ? 6 : 2;
        }

        size_t GetModRMDispLength(unsigned char const * source) const
        {
            auto ModRM = *source;
            auto Mod = ModRM >> 6;
            auto RM = ModRM & 7;
            if (2 == m_address_size)
            {
                switch (Mod)
                {
                case 00:
                    return (6 == RM) ? 3 : 1;
                case 01:
                    return 2;
                case 02:
                    return 3;
                default:
                    return 1;
                }
            }
            else
            {
                switch (Mod)
                {
                case 00:
                    return (4 == RM) ? GetModRMSIBDispLength_00(source + 1) : (5 == RM) ? 5 : 1;
                case 01:
                    return (4 == RM) ? 3 : 2;
                case 02:
                    return (4 == RM) ? 6 : 5;
                default:
                    return 1;
                }
            }
        }

        bool DecodeInstructionAddressingFormBytes(unsigned char const * source, size_t position, size_t const length)
        {
            unsigned char buffer[32];
            memcpy(buffer, source, min(length, 16));
            for (;;)
            {
                if (2 == m_address_size)
                {
                    buffer[position + 0] = 0x07; // [BX] - MOD:00 RM:111(BX)
                    DecodeInstructionState(buffer, position + 1);
                    if (invalid == m_instruction_state)
                    {
                        break;
                    }
                    else if (longer == m_instruction_state)
                    {
                        m_immediate_bytes = 0;
                        return DecodeInstructionImmediateWord(buffer, position, length);
                    }
                    buffer[position + 0] = 0x47; // [BX + 0x00] - MOD:01 RM:111(BX)
                    buffer[position + 1] = 0x00;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x87; // [BX + 0x0000] - MOD:10 RM:111(BX)
                    buffer[position + 1] = 0x00;
                    buffer[position + 2] = 0x00;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_addressing_form_bytes = GetModRMDispLength(source + position);
                    return true;
                }
                else
                {
                    buffer[position + 0] = 0x00; // [EAX] - MOD:00 RM:000(EAX) SIB:0
                    DecodeInstructionState(buffer, position + 1);
                    if (invalid == m_instruction_state)
                    {
                        break;
                    }
                    else if (longer == m_instruction_state)
                    {
                        m_immediate_bytes = 0;
                        return DecodeInstructionImmediateWord(buffer, position, length);
                    }
                    buffer[position + 0] = 0x40; // [EAX + 0x00] - MOD:01 RM:000(EAX) SIB:0
                    buffer[position + 1] = 0x00;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x44; // [EAX + 0x00] - MOD:01 RM:100(SIB) SIB.B:000(EAX) SIB.I:100([base + disp8])
                    buffer[position + 1] = 0x20;
                    buffer[position + 2] = 0x00;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x84; // [EAX + 0x00000000] - MOD:00 RM:100(SIB) SIB.B:000(EAX) SIB.I:100([base + disp32])
                    buffer[position + 1] = 0x20;
                    buffer[position + 2] = 0x00;
                    buffer[position + 3] = 0x00;
                    buffer[position + 4] = 0x00;
                    buffer[position + 5] = 0x00;
                    DecodeInstructionState(buffer, position + 6);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_addressing_form_bytes = GetModRMDispLength(source + position);
                    return true;
                }
            }
            return false;
        }

        void DecodeInstructionOpcodeBytes(unsigned char const * source, size_t const length)
        {
            size_t const n = min(m_prefix_bytes + 4, length); // opcode is 1/2/3-byte long
            for (size_t i = m_prefix_bytes + 1; i < n; ++i)
            {
                m_opcode_bytes = 0;
                m_immediate_bytes = false;
                m_addressing_form_bytes = false;
                switch (length - i)
                {
                case 0:
                    m_opcode_bytes = i - m_prefix_bytes;
                    return;
                case 1: // a 1-byte address form / an 8-bit immediate 
                    m_opcode_bytes = i - m_prefix_bytes;
                    DecodeInstructionAddressingFormBytes(source, i, length);
                    return;
                case 2: // a 2-byte address form / a 1-byte address + 1-byte immediate / a 2-byte immediate
                    m_opcode_bytes = i - m_prefix_bytes;
                    DecodeInstructionAddressingFormBytes(source, i, length);
                    return;
                case 3: // a 3-byte address from / 2-byte address form + a 1-byte immediate / 1-byte address form + 2-byte immediate 
                    m_opcode_bytes = i - m_prefix_bytes;
                    DecodeInstructionAddressingFormBytes(source, i, length);
                    return;
                case 4:  // a 3-byte address from + a 1-byte immediate / a 4-byte immediate
                    m_opcode_bytes = i - m_prefix_bytes;
                    if (!DecodeInstructionAddressingFormBytes(source, i, length))
                    {
                        m_immediate_bytes = true;
                    }
                    return;
                case 5:  // a 5-byte address form / a 1-byte address form + a 4-byte immediate
                    m_opcode_bytes = i - m_prefix_bytes;
                    DecodeInstructionAddressingFormBytes(source, i, length);
                    return;
                case 6:  // a 6-byte address form / a 1-byte address form + a 4-byte immediate
                    m_opcode_bytes = i - m_prefix_bytes;
                    DecodeInstructionAddressingFormBytes(source, i, length);
                    return;
                }
            }
        }

        bool DecodeInstructionAddressingFormImmediate(unsigned char const * source, size_t position, size_t const length, int immediate)
        {
            unsigned char buffer[32];
            memcpy(buffer, source, min(length, 32));
            for (;;)
            {
                if (2 == m_address_size)
                {
                    buffer[position + 0] = 0x07; // [BX] - MOD:00 RM:111(BX)
                    DecodeInstructionState(buffer, position + 1);
                    if (invalid == m_instruction_state)
                    {
                        break;
                    }
                    else if (longer == m_instruction_state)
                    {
                        m_immediate_bytes = 0;
                        return DecodeInstructionImmediateWord(buffer, position, length);
                    }
                    buffer[position + 0] = 0x47; // [BX + 0x00] - MOD:01 RM:111(BX)
                    buffer[position + 1] = 0x00;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x87; // [BX + 0x0000] - MOD:10 RM:111(BX)
                    buffer[position + 1] = 0x00;
                    buffer[position + 2] = 0x00;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_addressing_form_bytes = GetModRMDispLength(source + position);
                    return true;
                }
                else
                {
                    buffer[position + 0] = 0x00; // [EAX] - MOD:00 RM:000(EAX) SIB:0
                    DecodeInstructionState(buffer, position + 1);
                    if (invalid == m_instruction_state)
                    {
                        break;
                    }
                    else if (longer == m_instruction_state)
                    {
                        m_immediate_bytes = 0;
                        return DecodeInstructionImmediateWord(buffer, position, length);
                    }
                    buffer[position + 0] = 0x40; // [EAX + 0x00] - MOD:01 RM:000(EAX) SIB:0
                    buffer[position + 1] = 0x00;
                    DecodeInstructionState(buffer, position + 2);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x44; // [EAX + 0x00] - MOD:01 RM:100(SIB) SIB.B:000(EAX) SIB.I:100([base + disp8])
                    buffer[position + 1] = 0x20;
                    buffer[position + 2] = 0x00;
                    DecodeInstructionState(buffer, position + 3);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    buffer[position + 0] = 0x84; // [EAX + 0x00000000] - MOD:00 RM:100(SIB) SIB.B:000(EAX) SIB.I:100([base + disp32])
                    buffer[position + 1] = 0x20;
                    buffer[position + 2] = 0x00;
                    buffer[position + 3] = 0x00;
                    buffer[position + 4] = 0x00;
                    buffer[position + 5] = 0x00;
                    DecodeInstructionState(buffer, position + 6);
                    if (valid != m_instruction_state)
                    {
                        break;
                    }
                    m_addressing_form_bytes = GetModRMDispLength(source + position);
                    return true;
                }
            }
            return false;
        }

        void DecodeInstructionLength(unsigned char const * source, size_t const length)
        {
            m_instruction_state = invalid;
            m_length = 0;
            m_operand_size = 4;
            m_address_size = sizeof(intptr_t);
            if (DecodeInstructionPrefixBytes(source, length))
            {
                for (size_t i = m_prefix_bytes + 1; i <= length; ++i)
                {
                    DecodeInstructionState(source, i);
                    switch (m_instruction_state)
                    {
                    case invalid:
                        break;
                    case valid:
                        m_length = i;
                        if (i == length)
                        {
                            //DecodeInstructionOpcodeBytes(source, length);
                        }
                        else
                        {
                            m_instruction_state = smaller;
                            i = length;
                        }
                        break;
                    case longer:
                    default: // unreachable
                        continue;
                    }
                }
            }
        }


        InstructionState DecodeInstruction(unsigned char const * source, size_t const length)
        {
            DecodeInstructionLength(source, length);
            return m_instruction_state;
        }

        bool const Valid() const { return valid == m_instruction_state;  }
        bool const Invalid() const { return invalid == m_instruction_state; }

        size_t const Length() const { return m_length; }

        size_t const PrefixBytes() const { return m_prefix_bytes;  }
        size_t const OpcodeBytes() const { return m_opcode_bytes; }
        size_t const AddressingFormBytes() const { return m_addressing_form_bytes; }
        size_t const ImmediateWordBytes() const { return m_immediate_bytes; }

        unsigned char * m_buffer;
        unsigned char * m_target;
        size_t m_length;
        size_t m_prefix_bytes;
        size_t m_operand_size;
        size_t m_address_size;
        size_t m_opcode_bytes;
        size_t m_addressing_form_bytes;
        size_t m_immediate_bytes;
        InstructionState m_instruction_state;
        CONTEXT m_context;
        DWORD m_esp;
        HANDLE m_thread;
    };
}
