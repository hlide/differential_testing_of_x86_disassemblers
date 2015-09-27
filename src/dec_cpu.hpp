#pragma once

#include <windows.h>
#include <excpt.h>

#include <cstdio>
#include <exception>

#include "dec_base.hpp"

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
                throw std::exception("dec::Cpu: Cannot allocate two virtual pages");
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
                printf("code: 0x%08X\n", code);
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
                    printf("copying %u bytes into [%08X-%08X[\n", length, target, target + length);
                    memcpy(target, source, length);
                    CONTEXT context;
                    {
                        context.ContextFlags = CONTEXT_FULL;
                        ::GetThreadContext(::GetCurrentThread(), &context);
                        context.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
                        context.Eip = DWORD_PTR(target);
                        ::SetThreadContext(::GetCurrentThread(), &context);
                        printf("trick not working!\n");
                        abort();
                    }
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
    };
}
