#ifndef WS_LEAN_DEFLATE_H
#define WS_LEAN_DEFLATE_H

#include <lean/lean.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

LEAN_EXPORT lean_obj_res ws_deflate_create(uint8_t compress,
                                            uint8_t window_bits);
LEAN_EXPORT lean_obj_res ws_deflate_process(b_lean_obj_arg context,
                                             b_lean_obj_arg input,
                                             uint64_t max_output,
                                             uint8_t reset_before);
LEAN_EXPORT lean_obj_res ws_deflate_close(b_lean_obj_arg context);

#ifdef __cplusplus
}
#endif

#endif
