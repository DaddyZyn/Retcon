#pragma once

#include <cstdint>
#include <tuple>
#include <array>
#include <vector>
#include <type_traits>
#include <cstring>
#include <windows.h>
#include <retcon/types.hpp>
#include <retcon/unwind.hpp>
#include <retcon/gadget.hpp>
#include <retcon/stack.hpp>

extern "C" uint64_t RetconDispatch(retcon::context* ctx);

namespace retcon {

bool initialize();
uint64_t get_active_gadget();
const std::vector<gadget_info>& get_gadget_pool();

namespace detail {

template <typename T>
uint64_t pack_arg(T&& val) {
    using CleanT = std::decay_t<T>;
    if constexpr (std::is_pointer_v<CleanT> || std::is_null_pointer_v<CleanT>) {
        return reinterpret_cast<uint64_t>(val);
    } else if constexpr (std::is_integral_v<CleanT> || std::is_enum_v<CleanT>) {
        return static_cast<uint64_t>(val);
    } else if constexpr (std::is_floating_point_v<CleanT>) {
        if constexpr (sizeof(CleanT) == sizeof(float)) {
            uint32_t bits = 0;
            std::memcpy(&bits, &val, sizeof(float));
            return static_cast<uint64_t>(bits);
        } else {
            uint64_t bits = 0;
            std::memcpy(&bits, &val, sizeof(double));
            return bits;
        }
    } else if constexpr (sizeof(CleanT) <= sizeof(uint64_t)) {
        uint64_t buf = 0;
        std::memcpy(&buf, &val, sizeof(CleanT));
        return buf;
    } else {
        return *reinterpret_cast<const uint64_t*>(&val);
    }
}

template <typename T>
uint64_t pack_xmm(T&& val) {
    using CleanT = std::decay_t<T>;
    if constexpr (std::is_same_v<CleanT, float>) {
        uint32_t bits = 0;
        std::memcpy(&bits, &val, sizeof(float));
        return static_cast<uint64_t>(bits);
    } else if constexpr (std::is_same_v<CleanT, double>) {
        uint64_t bits = 0;
        std::memcpy(&bits, &val, sizeof(double));
        return bits;
    } else {
        return 0;
    }
}

} // namespace detail

template <typename RetType = void, typename... Args>
RetType invoke(void* target, Args&&... args) {
    const auto& gadget = gadget_locator::get_default_gadget();
    if (!gadget.address) {
        // fallback to direct call if no gadget found
        using FnType = RetType(*)(Args...);
        if constexpr (std::is_void_v<RetType>) {
            reinterpret_cast<FnType>(target)(std::forward<Args>(args)...);
            return;
        } else {
            return reinterpret_cast<FnType>(target)(std::forward<Args>(args)...);
        }
    }

    context ctx;
    ctx.target_fn = reinterpret_cast<uint64_t>(target);
    ctx.gadget_addr = gadget.address;

    auto args_tuple = std::forward_as_tuple(args...);
    constexpr size_t arg_count = sizeof...(Args);

    // ms x64 abi: first 4 args in rcx, rdx, r8, r9 (or xmm0-xmm3)
    if constexpr (arg_count > 0) {
        ctx.arg_rcx  = detail::pack_arg(std::get<0>(args_tuple));
        ctx.arg_xmm0 = detail::pack_xmm(std::get<0>(args_tuple));
    }
    if constexpr (arg_count > 1) {
        ctx.arg_rdx  = detail::pack_arg(std::get<1>(args_tuple));
        ctx.arg_xmm1 = detail::pack_xmm(std::get<1>(args_tuple));
    }
    if constexpr (arg_count > 2) {
        ctx.arg_r8   = detail::pack_arg(std::get<2>(args_tuple));
        ctx.arg_xmm2 = detail::pack_xmm(std::get<2>(args_tuple));
    }
    if constexpr (arg_count > 3) {
        ctx.arg_r9   = detail::pack_arg(std::get<3>(args_tuple));
        ctx.arg_xmm3 = detail::pack_xmm(std::get<3>(args_tuple));
    }

    // args 5+ go to stack right above target's 32-byte shadow space
    constexpr size_t stack_arg_count = (arg_count > 4 ? arg_count - 4 : 1);
    std::array<uint64_t, stack_arg_count> stack_args_arr{};
    if constexpr (arg_count > 4) {
        [&]<size_t... Is>(std::index_sequence<Is...>) {
            ((stack_args_arr[Is] = detail::pack_arg(std::get<Is + 4>(args_tuple))), ...);
        }(std::make_index_sequence<arg_count - 4>{});
    }

    uint32_t stack_args_size = (arg_count > 4) ? static_cast<uint32_t>((arg_count - 4) * sizeof(uint64_t)) : 0;
    const uint8_t* stack_args_ptr = (arg_count > 4) ? reinterpret_cast<const uint8_t*>(stack_args_arr.data()) : nullptr;

    ctx.stack_args_size = stack_args_size;
    ctx.stack_args_ptr = reinterpret_cast<uint64_t>(stack_args_ptr);

    // zero-heap: buffer lives on caller stack
    stack_synthesizer::synthetic_layout layout;
    if (!stack_synthesizer::synthesize(
        gadget,
        reinterpret_cast<uint64_t>(&ctx),
        stack_args_ptr,
        stack_args_size,
        layout)) {
        using FnType = RetType(*)(Args...);
        if constexpr (std::is_void_v<RetType>) {
            reinterpret_cast<FnType>(target)(std::forward<Args>(args)...);
            return;
        } else {
            return reinterpret_cast<FnType>(target)(std::forward<Args>(args)...);
        }
    }

    ctx.synthetic_stack = reinterpret_cast<uint64_t>(layout.buffer.data());
    ctx.synthetic_size = layout.total_size;

    RetconDispatch(&ctx);

    if constexpr (std::is_void_v<RetType>) {
        return;
    } else if constexpr (std::is_same_v<RetType, float>) {
        // lower 32-bit of xmm0 saved raw to gadget_addr by RetconCleanup
        union {
            uint32_t u;
            float f;
        } conv;
        conv.u = static_cast<uint32_t>(ctx.gadget_addr & 0xFFFFFFFFULL);
        return conv.f;
    } else if constexpr (std::is_same_v<RetType, double>) {
        union {
            uint64_t u;
            double d;
        } conv;
        conv.u = ctx.gadget_addr;
        return conv.d;
    } else if constexpr (std::is_pointer_v<RetType>) {
        return reinterpret_cast<RetType>(ctx.target_fn);
    } else {
        return static_cast<RetType>(ctx.target_fn);
    }
}

} // namespace retcon
