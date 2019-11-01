#ifndef THREADS_FIXED_H
#define THREADS_FIXED_H

// f = 2^(14) as mentioned in
// http://web.stanford.edu/class/cs140/projects/pintos/pintos_7.html#SEC133
#define F 16384

#define FIXED_TO_INT(x) (x) / F
#define FIXED_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
#define INT_TO_FIXED(n) (n) * (F)
#define FIXED_ADD(x ,y) (x) + (y)
#define FIXED_SUB(x ,y) (x) - (y)
#define FIXED_ADD_INT(x , n) (x) + (n) * (F)
#define FIXED_SUB_INT(x , n) (x) - (n) * (F)
#define FIXED_MULT(x , y) ((int64_t)(x)) * (y) / (F)
#define FIXED_DIV(x , y) ((int64_t)(x)) * (F) / (y)
#define FIXED_MULT_INT(x , n) (x) * (n)
#define FIXED_DIV_INT(x , n) (x) / (n)

#endif