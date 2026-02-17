

#ifndef NOSP_PATTERN_MATCHER_H
#define NOSP_PATTERN_MATCHER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif



typedef struct ACMatcher ACMatcher;
typedef struct ACResult ACResult;

typedef struct {
    int pattern_id;
    int position;
} ACMatch;



ACMatcher* ac_init(void);



int ac_add_pattern(ACMatcher *matcher, const char *pattern);



void ac_build_failure(ACMatcher *matcher);



ACResult* ac_search(ACMatcher *matcher, const char *text, int text_len);



static inline int ac_result_count(ACResult *result) {
    return result ? ((struct { ACMatch *matches; int count; int capacity; } *)result)->count : 0;
}



static inline ACMatch ac_get_match(ACResult *result, int index) {
    ACMatch *matches = ((struct { ACMatch *matches; int count; int capacity; } *)result)->matches;
    return matches[index];
}



void ac_free(ACMatcher *matcher);
void ac_free_result(ACResult *result);

#ifdef __cplusplus
}
#endif

#endif 

