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
            switch (code)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                that->m_instruction_state = (ep->ExceptionRecord->ExceptionInformation[1] == ULONG_PTR(that->m_buffer + 0x1000)) ? longer : valid;
                return EXCEPTION_EXECUTE_HANDLER;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
            case EXCEPTION_BREAKPOINT:
            case EXCEPTION_SINGLE_STEP:
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
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                that->m_instruction_state = (*((unsigned short *)ep->ExceptionRecord->ExceptionAddress) == 0x0B0F) ? valid : invalid;
                return EXCEPTION_EXECUTE_HANDLER;
            default:
                fprintf(stderr, "ERROR: code: 0x%08X\n", code);
                that->m_instruction_state = invalid;
                return EXCEPTION_CONTINUE_SEARCH;
            }
        }
        
        InstructionState DecodeInstruction(unsigned char const * source, size_t const length)
        {
            m_instruction_state = invalid;
            for (size_t i = 1; i <= length; ++i)
            {
                __try
                {
                    m_length = 0;
                    m_target = m_buffer + 0x1000 - i;
                    {
                        memcpy(m_target, source, i);
                        m_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // minimal flags to get it working
                        ::GetThreadContext(::GetCurrentThread(), &m_context);
                        m_context.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                        m_context.Eip = DWORD(m_target);
                        ::SetThreadContext(::GetCurrentThread(), &m_context);
                    }
                }
                __except (Filter(this, ::_exception_code(), reinterpret_cast<PEXCEPTION_POINTERS>(::_exception_info())))
                {
                    switch (m_instruction_state)
                    {
                    case invalid:
                        break;
                    case valid:
                        m_length = i;
                        break;
                    case longer:
                        continue;
                    }
                }
            }

            return m_instruction_state;
        }
#endif
        unsigned char * m_buffer;
        unsigned char * m_target;
        size_t m_length;
        InstructionState m_instruction_state;
        CONTEXT m_context;
    };
}
