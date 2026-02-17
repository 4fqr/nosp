

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_PATTERNS 10000
#define MAX_PATTERN_LENGTH 256
#define ALPHABET_SIZE 256
#define MAX_STATES 100000



typedef struct ACNode {
    struct ACNode *children[ALPHABET_SIZE];
    struct ACNode *failure;
    int *outputs;  

    int output_count;
    int state_id;
} ACNode;



typedef struct {
    ACNode *root;
    int state_count;
    char **patterns;
    int pattern_count;
    int *pattern_lengths;
} ACMatcher;



typedef struct {
    ACNode **data;
    int front;
    int rear;
    int capacity;
} Queue;



Queue* create_queue(int capacity) {
    Queue *q = (Queue*)malloc(sizeof(Queue));
    q->data = (ACNode**)malloc(capacity * sizeof(ACNode*));
    q->front = 0;
    q->rear = 0;
    q->capacity = capacity;
    return q;
}

void enqueue(Queue *q, ACNode *node) {
    q->data[q->rear++] = node;
}

ACNode* dequeue(Queue *q) {
    return q->data[q->front++];
}

bool is_queue_empty(Queue *q) {
    return q->front == q->rear;
}

void free_queue(Queue *q) {
    free(q->data);
    free(q);
}



ACNode* create_node(int state_id) {
    ACNode *node = (ACNode*)calloc(1, sizeof(ACNode));
    node->state_id = state_id;
    node->outputs = NULL;
    node->output_count = 0;
    node->failure = NULL;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        node->children[i] = NULL;
    }
    return node;
}



ACMatcher* ac_init() {
    ACMatcher *matcher = (ACMatcher*)malloc(sizeof(ACMatcher));
    matcher->root = create_node(0);
    matcher->state_count = 1;
    matcher->patterns = (char**)malloc(MAX_PATTERNS * sizeof(char*));
    matcher->pattern_count = 0;
    matcher->pattern_lengths = (int*)malloc(MAX_PATTERNS * sizeof(int));
    return matcher;
}



int ac_add_pattern(ACMatcher *matcher, const char *pattern) {
    if (matcher->pattern_count >= MAX_PATTERNS) {
        return -1;
    }
    
    int pattern_id = matcher->pattern_count;
    int len = strlen(pattern);
    
    

    matcher->patterns[pattern_id] = (char*)malloc((len + 1) * sizeof(char));
    strcpy(matcher->patterns[pattern_id], pattern);
    matcher->pattern_lengths[pattern_id] = len;
    matcher->pattern_count++;
    
    

    ACNode *current = matcher->root;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)pattern[i];
        
        if (current->children[c] == NULL) {
            current->children[c] = create_node(matcher->state_count++);
        }
        current = current->children[c];
    }
    
    

    current->outputs = (int*)realloc(current->outputs, (current->output_count + 1) * sizeof(int));
    current->outputs[current->output_count++] = pattern_id;
    
    return pattern_id;
}



void ac_build_failure(ACMatcher *matcher) {
    Queue *queue = create_queue(MAX_STATES);
    
    

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (matcher->root->children[i] != NULL) {
            matcher->root->children[i]->failure = matcher->root;
            enqueue(queue, matcher->root->children[i]);
        }
    }
    
    

    while (!is_queue_empty(queue)) {
        ACNode *current = dequeue(queue);
        
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            ACNode *child = current->children[i];
            if (child == NULL) continue;
            
            enqueue(queue, child);
            
            

            ACNode *failure = current->failure;
            while (failure != NULL && failure->children[i] == NULL) {
                failure = failure->failure;
            }
            
            if (failure == NULL) {
                child->failure = matcher->root;
            } else {
                child->failure = failure->children[i];
                
                

                if (child->failure->output_count > 0) {
                    int old_count = child->output_count;
                    child->output_count += child->failure->output_count;
                    child->outputs = (int*)realloc(child->outputs, child->output_count * sizeof(int));
                    memcpy(child->outputs + old_count, child->failure->outputs, 
                           child->failure->output_count * sizeof(int));
                }
            }
        }
    }
    
    free_queue(queue);
}



typedef struct {
    int pattern_id;
    int position;
} ACMatch;

typedef struct {
    ACMatch *matches;
    int count;
    int capacity;
} ACResult;

ACResult* ac_search(ACMatcher *matcher, const char *text, int text_len) {
    ACResult *result = (ACResult*)malloc(sizeof(ACResult));
    result->capacity = 1000;
    result->matches = (ACMatch*)malloc(result->capacity * sizeof(ACMatch));
    result->count = 0;
    
    ACNode *current = matcher->root;
    
    for (int i = 0; i < text_len; i++) {
        unsigned char c = (unsigned char)text[i];
        
        

        while (current != matcher->root && current->children[c] == NULL) {
            current = current->failure;
        }
        
        if (current->children[c] != NULL) {
            current = current->children[c];
        }
        
        

        if (current->output_count > 0) {
            for (int j = 0; j < current->output_count; j++) {
                

                if (result->count >= result->capacity) {
                    result->capacity *= 2;
                    result->matches = (ACMatch*)realloc(result->matches, 
                                                        result->capacity * sizeof(ACMatch));
                }
                
                result->matches[result->count].pattern_id = current->outputs[j];
                result->matches[result->count].position = i - matcher->pattern_lengths[current->outputs[j]] + 1;
                result->count++;
            }
        }
    }
    
    return result;
}



void ac_free_node(ACNode *node) {
    if (node == NULL) return;
    
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        ac_free_node(node->children[i]);
    }
    
    if (node->outputs != NULL) {
        free(node->outputs);
    }
    free(node);
}

void ac_free(ACMatcher *matcher) {
    ac_free_node(matcher->root);
    
    for (int i = 0; i < matcher->pattern_count; i++) {
        free(matcher->patterns[i]);
    }
    
    free(matcher->patterns);
    free(matcher->pattern_lengths);
    free(matcher);
}

void ac_free_result(ACResult *result) {
    free(result->matches);
    free(result);
}



#ifdef AC_TEST_MAIN
#include <time.h>

double get_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main() {
    printf("=== NOSP Aho-Corasick Pattern Matcher ===\n\n");
    
    

    ACMatcher *matcher = ac_init();
    
    

    const char *malware_patterns[] = {
        "mimikatz", "sekurlsa", "lsadump", "kerberos",
        "procdump", "psexec", "wmic", "powershell -enc",
        "net user /add", "schtasks /create", "reg add",
        "cmd /c", "certutil", "bitsadmin", "mshta",
        "rundll32", "regsvr32", "sc create", "invoke-expression",
        "downloadstring", "bypass", "iex", "hidden"
    };
    
    int pattern_count = sizeof(malware_patterns) / sizeof(malware_patterns[0]);
    
    printf("Adding %d malware patterns...\n", pattern_count);
    for (int i = 0; i < pattern_count; i++) {
        ac_add_pattern(matcher, malware_patterns[i]);
    }
    
    printf("Building failure function...\n");
    ac_build_failure(matcher);
    printf("Pattern matcher ready with %d states\n\n", matcher->state_count);
    
    

    const char *test_text = 
        "C:\\Windows\\System32\\cmd.exe /c powershell -enc SGVsbG8gV29ybGQ= "
        "C:\\Temp\\mimikatz.exe sekurlsa::logonpasswords "
        "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    
    printf("Searching in text (%zu bytes)...\n", strlen(test_text));
    
    double start = get_time();
    ACResult *result = ac_search(matcher, test_text, strlen(test_text));
    double end = get_time();
    
    printf("\n--- Results ---\n");
    printf("Found %d matches in %.6f ms (%.0f ns per search)\n", 
           result->count, (end - start) * 1000, (end - start) * 1e9);
    
    for (int i = 0; i < result->count; i++) {
        printf("  Pattern '%s' at position %d\n", 
               matcher->patterns[result->matches[i].pattern_id],
               result->matches[i].position);
    }
    
    

    printf("\n--- Performance Benchmark ---\n");
    const int large_size = 1024 * 1024;  

    char *large_text = (char*)malloc(large_size);
    memset(large_text, 'A', large_size);
    memcpy(large_text + large_size / 2, "mimikatz sekurlsa", 17);
    
    start = get_time();
    ACResult *bench_result = ac_search(matcher, large_text, large_size);
    end = get_time();
    
    printf("Scanned 1 MB in %.6f ms\n", (end - start) * 1000);
    printf("Throughput: %.2f MB/s\n", 1.0 / (end - start));
    printf("Found %d matches\n", bench_result->count);
    
    

    ac_free_result(result);
    ac_free_result(bench_result);
    free(large_text);
    ac_free(matcher);
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
#endif
