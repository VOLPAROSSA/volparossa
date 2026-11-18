// SPDX-License-Identifier: GPL-3.0-only
// A deliberately scoped test driver, not a replacement for the unchanged
// all-type upstream test. Reuse its actual functions and tolerances verbatim.
// The original upstream main remains compiled under a different name.
#define main vp_upstream_all_types_main
#include VP_UPSTREAM_TEST_FILE
#undef main

int main() {
    ggml_cpu_init();
    int failed = test_vec_dot_f32(true);
    const auto * traits = ggml_get_type_traits(GGML_TYPE_BF16);
    const auto * cpu = ggml_get_type_traits_cpu(GGML_TYPE_BF16);
    assert(traits->to_float && traits->from_float_ref && cpu->from_float && cpu->vec_dot);
    constexpr size_t count = 32 * 128;
    std::vector<float> first(count);
    std::vector<float> second(count);
    generate_data(0.0, count, first.data());
    generate_data(1.0, count, second.data());
    const float errors[] = {
        total_quantization_error(traits, cpu, count, first.data()),
        reference_quantization_error(traits, cpu, count, first.data()),
        dot_product_error(cpu, GGML_TYPE_BF16, count, first.data(), second.data(), nullptr, nullptr, 1),
    };
    const float limits[] = {MAX_QUANTIZATION_TOTAL_ERROR, MAX_QUANTIZATION_REFERENCE_ERROR, MAX_DOT_PRODUCT_ERROR};
    for (int index = 0; index < 3; ++index) {
        const bool bad = !(errors[index] < limits[index]);
        failed += bad;
        printf("BF16 original upstream check %d: %s (error=%f limit=%f)\n",
               index, RESULT_STR[bad], errors[index], limits[index]);
    }
    printf("Owned BF16/F32 scope: %d failures; no model; upstream all-type result is separate\n", failed);
    return failed > 0;
}
