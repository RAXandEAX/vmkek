#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef R04_DFSAN
#include <sanitizer/dfsan_interface.h>
#elif defined(R04_KLEE)
#include <assert.h>
#include <klee/klee.h>
#endif

#if defined(__clang__)
#define FIXTURE __attribute__((noinline))
#else
#define FIXTURE __attribute__((noipa))
#endif

typedef struct {
    uint64_t a, b, state, effects[4];
    uint32_t n, effect_count, status;
    uint8_t left, bytes[16], right;
} Context;

typedef uint64_t (*Function)(Context *);

FIXTURE uint64_t affine_xor(Context *c) { return (c->a * 7 + 3) ^ c->b; }
FIXTURE uint64_t add_rotate(Context *c) {
    uint64_t x = c->a + c->b;
    return (x << 9) | (x >> 55);
}
FIXTURE uint64_t clamp(Context *c) { return c->a > c->b ? c->b : c->a; }
FIXTURE uint64_t parity_band(Context *c) {
    if (c->a < c->b) return c->a & 1;
    return c->a ^ c->b;
}
FIXTURE uint64_t bounded_sum(Context *c) {
    uint64_t sum = 0;
    for (uint32_t i = 0; i < c->n; i++) sum += c->bytes[i];
    return sum;
}
FIXTURE uint64_t rolling_checksum(Context *c) {
    uint64_t sum = c->a;
    for (uint32_t i = 0; i < c->n; i++) sum = sum * 33 + c->bytes[i];
    return sum;
}
FIXTURE uint64_t lookup4(Context *c) {
    static const uint64_t table[] = {7, 3, 11, 4};
    return table[c->a & 3];
}
FIXTURE uint64_t lookup16(Context *c) {
    static const uint8_t table[] = {5, 3, 0, 1, 7, 9, 2, 6, 8, 4, 15, 14, 13, 10, 11, 12};
    return table[c->a & 15] ^ c->b;
}
FIXTURE uint64_t xor_copy(Context *c) {
    for (uint32_t i = 0; i < c->n; i++) c->bytes[i] ^= (uint8_t)c->a;
    return c->n;
}
FIXTURE uint64_t masked_add(Context *c) {
    for (uint32_t i = 0; i < c->n; i++) c->bytes[i] = (uint8_t)(c->bytes[i] + c->b);
    return c->n;
}
FIXTURE uint64_t bounded_u16le(Context *c) {
    if (c->n < 2) { c->status = 1; return 0; }
    return (uint64_t)c->bytes[0] | ((uint64_t)c->bytes[1] << 8);
}
FIXTURE uint64_t hex_digit(Context *c) {
    if (c->n != 0) {
        uint8_t v = c->bytes[0];
        if (v >= '0' && v <= '9') return v - '0';
        if (v >= 'a' && v <= 'f') return v - 'a' + 10;
    }
    c->status = 1;
    return 0;
}
FIXTURE uint64_t counter(Context *c) { c->state += c->a; return c->state; }
FIXTURE uint64_t rolling_state(Context *c) {
    c->state = (c->state * 17 + c->a) ^ c->b;
    return c->state;
}
static FIXTURE uint64_t helper_a(uint64_t x) { return x + 7; }
static FIXTURE uint64_t helper_b(uint64_t x) { return x ^ 12; }
FIXTURE uint64_t two_helpers(Context *c) {
    uint64_t first = helper_a(c->a);
    c->effects[0] = first;
    c->effects[1] = helper_b(first);
    c->effect_count = 2;
    return c->effects[1];
}
FIXTURE uint64_t conditional_helper(Context *c) {
    uint64_t value = c->a < c->b ? helper_a(c->a) : helper_b(c->b);
    c->effects[0] = value;
    c->effect_count = 1;
    return value;
}

#ifdef R04_HOLDOUT
FIXTURE uint64_t lane_sum(Context *c) {
    return (c->a & 0xffff) + (c->b >> 48) + R04_P0;
}
FIXTURE uint64_t threshold_pair(Context *c) {
    const uint64_t threshold = R04_P1;
    if (c->a < threshold) return c->b;
    return c->b < c->a ? c->a - c->b : c->b - c->a;
}
FIXTURE uint64_t count_transitions(Context *c) {
    uint64_t count = 0;
    for (uint32_t i = 1; i < c->n; i++) count += (c->bytes[i] ^ c->bytes[i - 1]) > R04_P2;
    return count;
}
FIXTURE uint64_t table_classify(Context *c) {
    static const uint8_t table[] = {2, 0, 6, 3, 5, 1, 7, 4};
    return table[(c->a ^ R04_P3) & 7];
}
FIXTURE uint64_t in_place_swap(Context *c) {
    for (uint32_t i = 0; i < c->n / 2; i++) {
        uint8_t temp = c->bytes[i];
        c->bytes[i] = c->bytes[c->n - i - 1] ^ R04_P4;
        c->bytes[c->n - i - 1] = temp ^ R04_P4;
    }
    return c->n;
}
FIXTURE uint64_t bounded_tlv(Context *c) {
    if (c->n < 2 || c->bytes[1] > c->n - 2) { c->status = 1; return 0; }
    return (uint64_t)(c->bytes[0] ^ R04_P5) << 8 | c->bytes[1];
}
FIXTURE uint64_t finite_state_machine(Context *c) {
    c->state = ((c->state & 3) + (c->a & 1) + (R04_P6 & 3)) & 3;
    return c->state;
}
FIXTURE uint64_t callback_sequence(Context *c) {
    uint64_t first = helper_a(c->a + R04_P7);
    c->effects[0] = first;
    c->effects[1] = helper_b(first ^ c->b);
    c->effect_count = 2;
    return c->effects[1];
}
#endif

static const struct { const char *name; Function function; } functions[] = {
#define ROW(name) {#name, name}
#ifdef R04_ONLY
#define SELECTED(name) ROW(name)
    SELECTED(R04_ONLY),
#undef SELECTED
#else
    ROW(affine_xor), ROW(add_rotate), ROW(clamp), ROW(parity_band),
    ROW(bounded_sum), ROW(rolling_checksum), ROW(lookup4), ROW(lookup16),
    ROW(xor_copy), ROW(masked_add), ROW(bounded_u16le), ROW(hex_digit),
    ROW(counter), ROW(rolling_state), ROW(two_helpers), ROW(conditional_helper),
#ifdef R04_HOLDOUT
    ROW(lane_sum), ROW(threshold_pair), ROW(count_transitions), ROW(table_classify),
    ROW(in_place_swap), ROW(bounded_tlv), ROW(finite_state_machine), ROW(callback_sequence),
#endif
#endif
#undef ROW
};

#ifdef R04_DFSAN
int main(void) {
    Context c = {.a = 3, .b = 9};
    dfsan_set_label(1, &c.a, sizeof(c.a));
    dfsan_set_label(2, &c.b, sizeof(c.b));
    uint64_t value = functions[0].function(&c);
    unsigned label = dfsan_get_label(value);
    printf("{\"value\":%" PRIu64 ",\"label\":%u}\n", value, label);
    return value == ((3 * 7 + 3) ^ 9) && label == 3 ? 0 : 2;
}
#elif defined(R04_KLEE)
int main(void) {
    Context c = {0};
    klee_make_symbolic(&c.a, sizeof(c.a), "a");
    klee_make_symbolic(&c.b, sizeof(c.b), "b");
    assert(functions[0].function(&c) == ((c.a * 7 + 3) ^ c.b));
    return 0;
}
#elif defined(R04_SLICE)
int main(void) {
    Context c = {.a = 3, .b = 9};
    return (int)(functions[0].function(&c) & 255);
}
#else
static int read_context(Context *c) {
    if (scanf("%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu32,
              &c->a, &c->b, &c->state, &c->n) != 4 || c->n > 16) return 0;
    for (unsigned i = 0; i < sizeof(c->bytes); i++) {
        unsigned value;
        if (scanf("%u", &value) != 1 || value > 255) return 0;
        c->bytes[i] = (uint8_t)value;
    }
    return 1;
}

static void print_observation(const Context *c, uint64_t value) {
    printf("{\"status\":%" PRIu32 ",\"value\":%" PRIu64 ",\"state\":%" PRIu64
           ",\"buffer\":\"", c->status, value, c->state);
    for (unsigned i = 0; i < sizeof(c->bytes); i++) printf("%02x", (unsigned)c->bytes[i]);
    printf("\",\"canaries\":[%u,%u],\"effect_count\":%" PRIu32 ",\"effects\":[",
           (unsigned)c->left, (unsigned)c->right, c->effect_count);
    for (uint32_t i = 0; i < c->effect_count && i < 4; i++) {
        printf("%s%" PRIu64, i ? "," : "", c->effects[i]);
    }
    puts("]}");
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    for (unsigned i = 0; i < sizeof(functions) / sizeof(functions[0]); i++) {
        if (strcmp(argv[1], functions[i].name) == 0) {
            Context c = {.left = 0xa5, .right = 0x5a};
            if (!read_context(&c)) return 2;
            uint64_t value = functions[i].function(&c);
            print_observation(&c, value);
            return 0;
        }
    }
    return 2;
}
#endif
