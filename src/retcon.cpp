#include <retcon/retcon.hpp>
#include <retcon/gadget.hpp>

namespace retcon {

bool initialize() {
    const auto& pool = gadget_locator::get_gadget_pool();
    return !pool.empty() && pool.front().address != 0;
}

uint64_t get_active_gadget() {
    return gadget_locator::get_default_gadget().address;
}

const std::vector<gadget_info>& get_gadget_pool() {
    return gadget_locator::get_gadget_pool();
}

} // namespace retcon
