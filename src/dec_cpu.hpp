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
            longer
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
                throw std::exception("Cannot allocate two virtual pages");
            }
        }

        ~Cpu()
        {
            if (m_buffer)
            {
                ::VirtualFree(m_buffer, 0, MEM_RELEASE);
            }
        }

        static int Filter(Cpu * that, unsigned int code, PEXCEPTION_POINTERS ep)
        {
#ifdef _WIN64
            printf("EXC: @%016X\n", ep->ContextRecord->Rip);
#else
            printf("EXC: @%08X\n", ep->ContextRecord->Eip);
#endif
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
                that->m_instruction_state = valid;
                return EXCEPTION_EXECUTE_HANDLER;
            default:
#ifdef _WIN64
                fprintf(stderr, "ERROR: code: 0x%016XULL\n", code);
#else
                fprintf(stderr, "ERROR: code: 0x%08X\n", code);
#endif
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        
        InstructionState DecodeInstruction(unsigned char const * source, size_t const length)
        {
            __try
            {
                m_length = 0;
                m_instruction_state = invalid;
                auto target = m_buffer + 0x1000 - length;
                {
#ifdef _WIN64
                    printf("copying %u bytes into [%016X-%016X[\n", length, DWORD64(target), DWORD64(target + length));
#else
                    printf("copying %u bytes into [%08X-%08X[\n", length, target, target + length);
#endif
                    memcpy(target, source, length);
#ifdef _WIN64
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
#else
                    m_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // minimal flags to get it working
                    if (0 == ::GetThreadContext(::GetCurrentThread(), &m_context))
                    {
                        auto last_error = ::GetLastError();
                        fprintf(stderr, "ERROR: GetThreadContext fails with LastError=%u", last_error);
                    }
                    m_context.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                    m_context.Eip = DWORD(target);
                    if (0 == ::SetThreadContext(::GetCurrentThread(), &m_context))
                    {
                        auto last_error = ::GetLastError();
                        fprintf(stderr, "ERROR: SetThreadContext fails with LastError=%u", last_error);
                    }
#endif
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

        unsigned char * m_buffer;
        size_t m_length;
        InstructionState m_instruction_state;
        CONTEXT m_context;
    };
}
