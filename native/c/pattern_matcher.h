/*
 * NOSP C Core - Pattern Matcher Header
 * High-performance Aho-Corasick implementation for signature scanning
 */

#ifndef NOSP_PATTERN_MATCHER_H
#define NOSP_PATTERN_MATCHER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque types
typedef struct ACMatcher ACMatcher;
typedef struct ACResult ACResult;

typedef struct {
    int pattern_id;
    int position;
} ACMatch;

// Initialize pattern matcher
ACMatcher* ac_init(void);

// Add pattern (returns pattern ID or -1 on error)
int ac_add_pattern(ACMatcher *matcher, const char *pattern);

// Build failure function (must be called after adding all patterns)
void ac_build_failure(ACMatcher *matcher);

// Search for patterns in text
ACResult* ac_search(ACMatcher *matcher, const char *text, int text_len);

// Get result count
static inline int ac_result_count(ACResult *result) {
    return result ? ((struct { ACMatch *matches; int count; int capacity; } *)result)->count : 0;
}

// Get match at index
static inline ACMatch ac_get_match(ACResult *result, int index) {
    ACMatch *matches = ((struct { ACMatch *matches; int count; int capacity; } *)result)->matches;
    return matches[index];
}

// Free resources
void ac_free(ACMatcher *matcher);
void ac_free_result(ACResult *result);

#ifdef __cplusplus
}
#endif

#endif // NOSP_PATTERN_MATCHER_H
