/* Reference sample. vmkek protects the PE built from the same contract. */
typedef unsigned long long u64;

u64 mix(u64 value) { return (value * 7u + 3u) ^ 0x5au; }

u64 compute(u64 n) {
    u64 sum = 0;
    for (u64 i = 1; i <= n; i++) sum += mix(i);
    return sum;
}

int start(void) {
    /* The protected image prints vmkek-ok:<compute(10)>. */
    return (int)compute(10);
}
