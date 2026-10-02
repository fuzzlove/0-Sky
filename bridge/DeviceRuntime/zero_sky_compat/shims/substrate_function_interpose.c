/*
 * 0-Sky adapter for legacy tweaks which import only MSHookFunction.
 *
 * This uses dyld's typed interpose API and does not patch executable pages.
 * It deliberately does not implement message hooks or pretend to be a full
 * Substrate replacement. Packages importing any other Substrate API must be
 * routed to a different adapter or blocked for review.
 */
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdatomic.h>

struct osky_interpose_tuple {
    const void *replacement;
    const void *replacee;
};

extern void dyld_dynamic_interpose(const struct mach_header *header,
                                   const struct osky_interpose_tuple tuples[],
                                   size_t count);

static _Atomic unsigned long osky_hook_count;

__attribute__((visibility("default")))
unsigned long OSkySubstrateFunctionHookCount(void)
{
    return atomic_load_explicit(&osky_hook_count, memory_order_relaxed);
}

__attribute__((visibility("default")))
void MSHookFunction(void *symbol, void *replacement, void **original)
{
    if (original != NULL) {
        *original = symbol;
    }
    if (symbol == NULL || replacement == NULL) {
        return;
    }
    atomic_fetch_add_explicit(&osky_hook_count, 1, memory_order_relaxed);

    const struct osky_interpose_tuple tuple = {
        .replacement = replacement,
        .replacee = symbol,
    };
    const uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        if (header != NULL) {
            dyld_dynamic_interpose(header, &tuple, 1);
        }
    }
}
