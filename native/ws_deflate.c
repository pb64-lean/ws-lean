#include "ws_deflate.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

enum ws_deflate_error {
  WS_DEFLATE_INVALID_WINDOW = 0,
  WS_DEFLATE_OUT_OF_MEMORY = 1,
  WS_DEFLATE_CORRUPT_DATA = 2,
  WS_DEFLATE_OUTPUT_LIMIT = 3,
  WS_DEFLATE_CLOSED = 4,
  WS_DEFLATE_BACKEND = 5,
};

typedef int ws_status;

#define WS_STATUS_OK 0

static ws_status ws_status_error(enum ws_deflate_error error) {
  return (int)error + 1;
}

typedef struct ws_deflate_context {
  z_stream stream;
  bool compress;
  bool initialized;
} ws_deflate_context;

typedef struct ws_output {
  uint8_t *data;
  size_t length;
  size_t capacity;
  size_t hard_limit;
} ws_output;

static _Atomic(lean_external_class *) ws_context_class = NULL;
static atomic_flag ws_context_class_lock = ATOMIC_FLAG_INIT;

static lean_obj_res ws_except_error(enum ws_deflate_error code) {
  lean_object *result = lean_alloc_ctor(0, 1, 0);
  lean_ctor_set(result, 0, lean_box((size_t)code));
  return result;
}

static lean_obj_res ws_except_ok(lean_obj_arg value) {
  lean_object *result = lean_alloc_ctor(1, 1, 0);
  lean_ctor_set(result, 0, value);
  return result;
}

static lean_obj_res ws_io_except_error(enum ws_deflate_error code) {
  return lean_io_result_mk_ok(ws_except_error(code));
}

static lean_obj_res ws_io_except_ok(lean_obj_arg value) {
  return lean_io_result_mk_ok(ws_except_ok(value));
}

static void ws_context_release(ws_deflate_context *context) {
  if (context == NULL || !context->initialized) {
    return;
  }
  if (context->compress) {
    (void)deflateEnd(&context->stream);
  } else {
    (void)inflateEnd(&context->stream);
  }
  memset(&context->stream, 0, sizeof(context->stream));
  context->initialized = false;
}

static void ws_context_finalize(void *data) {
  ws_deflate_context *context = (ws_deflate_context *)data;
  if (context != NULL) {
    ws_context_release(context);
    free(context);
  }
}

static void ws_context_foreach(void *data, b_lean_obj_arg visit) {
  (void)data;
  (void)visit;
}

static lean_external_class *ws_get_context_class(void) {
  lean_external_class *klass =
      atomic_load_explicit(&ws_context_class, memory_order_acquire);
  if (klass != NULL) {
    return klass;
  }

  while (atomic_flag_test_and_set_explicit(&ws_context_class_lock,
                                            memory_order_acquire)) {
  }
  klass = atomic_load_explicit(&ws_context_class, memory_order_relaxed);
  if (klass == NULL) {
    klass = lean_register_external_class(ws_context_finalize,
                                         ws_context_foreach);
    atomic_store_explicit(&ws_context_class, klass, memory_order_release);
  }
  atomic_flag_clear_explicit(&ws_context_class_lock, memory_order_release);
  return klass;
}

static ws_deflate_context *ws_unwrap_context(b_lean_obj_arg object) {
  lean_object *owned = (lean_object *)object;
  if (!lean_is_external(owned) ||
      lean_get_external_class(owned) != ws_get_context_class()) {
    return NULL;
  }
  return (ws_deflate_context *)lean_get_external_data(owned);
}

static bool ws_output_init(ws_output *output, size_t hard_limit) {
  output->data = NULL;
  output->length = 0;
  output->capacity = 0;
  output->hard_limit = hard_limit;
  return true;
}

static void ws_output_release(ws_output *output) {
  free(output->data);
  output->data = NULL;
  output->length = 0;
  output->capacity = 0;
}

/* Ensure at least one writable byte whenever the configured limit permits it. */
static ws_status ws_output_reserve(ws_output *output) {
  if (output->length < output->capacity) {
    return WS_STATUS_OK;
  }
  if (output->capacity == output->hard_limit) {
    return ws_status_error(WS_DEFLATE_OUTPUT_LIMIT);
  }

  size_t next = output->capacity == 0 ? 256 : output->capacity;
  if (next > SIZE_MAX / 2) {
    next = output->hard_limit;
  } else {
    next *= 2;
    if (next > output->hard_limit) {
      next = output->hard_limit;
    }
  }
  if (next <= output->capacity) {
    return ws_status_error(WS_DEFLATE_OUTPUT_LIMIT);
  }

  void *resized = realloc(output->data, next);
  if (resized == NULL) {
    return ws_status_error(WS_DEFLATE_OUT_OF_MEMORY);
  }
  output->data = (uint8_t *)resized;
  output->capacity = next;
  return WS_STATUS_OK;
}

static ws_status ws_prepare_output(ws_output *output, z_stream *stream) {
  if (output->length == output->capacity) {
    ws_status reserve = ws_output_reserve(output);
    if (output->length == output->capacity) {
      return reserve;
    }
  }
  size_t available = output->capacity - output->length;
  if (available > UINT_MAX) {
    available = UINT_MAX;
  }
  stream->next_out = output->data + output->length;
  stream->avail_out = (uInt)available;
  return WS_STATUS_OK;
}

static void ws_commit_output(ws_output *output, const z_stream *stream,
                             uInt offered) {
  output->length += (size_t)(offered - stream->avail_out);
}

/* RFC 7692 permits a BFINAL=1 block followed by another byte-aligned block,
   including across a message boundary when context takeover is active. zlib
   reports stream end at BFINAL, so restart its raw parser while carrying the
   exact LZ77 dictionary forward. */
static ws_status ws_inflate_restart(z_stream *stream) {
  uint8_t dictionary[32768];
  uInt dictionary_length = (uInt)sizeof(dictionary);
  if (inflateGetDictionary(stream, dictionary, &dictionary_length) != Z_OK) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }
  if (inflateReset(stream) != Z_OK) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }
  if (dictionary_length != 0 &&
      inflateSetDictionary(stream, dictionary, dictionary_length) != Z_OK) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }
  return WS_STATUS_OK;
}

static ws_status ws_deflate_message(ws_deflate_context *context,
                                    const uint8_t *input,
                                    size_t input_length,
                                    uint64_t max_output,
                                    bool reset_before,
                                    ws_output *output) {
  z_stream *stream = &context->stream;
  if (reset_before && deflateReset(stream) != Z_OK) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }

  size_t public_limit = max_output > SIZE_MAX ? SIZE_MAX : (size_t)max_output;
  if (public_limit > SIZE_MAX - 4) {
    output->hard_limit = SIZE_MAX;
  } else {
    output->hard_limit = public_limit + 4;
  }

  size_t remaining = input_length;
  const uint8_t *cursor = input;
  while (remaining != 0) {
    uInt chunk = remaining > UINT_MAX ? UINT_MAX : (uInt)remaining;
    stream->next_in = (Bytef *)cursor;
    stream->avail_in = chunk;
    while (stream->avail_in != 0) {
      ws_status prepared = ws_prepare_output(output, stream);
      if (stream->avail_out == 0) {
        return prepared;
      }
      uInt offered = stream->avail_out;
      int result = deflate(stream, Z_NO_FLUSH);
      ws_commit_output(output, stream, offered);
      if (result != Z_OK) {
        return ws_status_error(WS_DEFLATE_BACKEND);
      }
    }
    cursor += chunk;
    remaining -= chunk;
  }

  stream->next_in = Z_NULL;
  stream->avail_in = 0;
  for (;;) {
    ws_status prepared = ws_prepare_output(output, stream);
    if (stream->avail_out == 0) {
      return prepared;
    }
    uInt offered = stream->avail_out;
    int result = deflate(stream, Z_SYNC_FLUSH);
    ws_commit_output(output, stream, offered);
    if (result != Z_OK) {
      return ws_status_error(WS_DEFLATE_BACKEND);
    }
    if (stream->avail_out != 0) {
      break;
    }
  }

  static const uint8_t marker[4] = {0x00, 0x00, 0xff, 0xff};
  if (output->length < sizeof(marker) ||
      memcmp(output->data + output->length - sizeof(marker), marker,
             sizeof(marker)) != 0) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }
  output->length -= sizeof(marker);
  if ((uint64_t)output->length > max_output) {
    return ws_status_error(WS_DEFLATE_OUTPUT_LIMIT);
  }
  return WS_STATUS_OK;
}

static ws_status ws_inflate_chunk(z_stream *stream, const uint8_t *input,
                                  size_t input_length, int flush,
                                  ws_output *output, uint64_t max_output) {
  size_t remaining = input_length;
  const uint8_t *cursor = input;
  do {
    uInt chunk = remaining > UINT_MAX ? UINT_MAX : (uInt)remaining;
    stream->next_in = (Bytef *)cursor;
    stream->avail_in = chunk;
    do {
      ws_status prepared = ws_prepare_output(output, stream);
      if (stream->avail_out == 0) {
        return prepared;
      }
      uInt offered = stream->avail_out;
      uInt input_before = stream->avail_in;
      int result = inflate(stream, flush);
      ws_commit_output(output, stream, offered);
      if ((uint64_t)output->length > max_output) {
        return ws_status_error(WS_DEFLATE_OUTPUT_LIMIT);
      }
      if (result == Z_STREAM_END) {
        /* RFC 7692 also permits a BFINAL=1 stream followed by the required
           non-final empty block. Start a fresh raw stream at the unconsumed
           suffix; a final stream cannot carry takeover state forward. */
        if (stream->avail_in == input_before) {
          return ws_status_error(WS_DEFLATE_CORRUPT_DATA);
        }
        Bytef *remaining_input = stream->next_in;
        uInt remaining_input_size = stream->avail_in;
        ws_status restarted = ws_inflate_restart(stream);
        if (restarted != WS_STATUS_OK) {
          return restarted;
        }
        stream->next_in = remaining_input;
        stream->avail_in = remaining_input_size;
        result = Z_OK;
      }
      if (result == Z_NEED_DICT || result == Z_DATA_ERROR) {
        return ws_status_error(WS_DEFLATE_CORRUPT_DATA);
      }
      if (result == Z_MEM_ERROR) {
        return ws_status_error(WS_DEFLATE_OUT_OF_MEMORY);
      }
      if (result != Z_OK && result != Z_BUF_ERROR) {
        return ws_status_error(WS_DEFLATE_BACKEND);
      }
      if (result == Z_BUF_ERROR && stream->avail_in != 0 &&
          stream->avail_out != 0) {
        return ws_status_error(WS_DEFLATE_CORRUPT_DATA);
      }
      if (stream->avail_in == 0 &&
          (stream->avail_out != 0 || result == Z_BUF_ERROR)) {
        break;
      }
    } while (true);
    cursor += chunk;
    remaining -= chunk;
  } while (remaining != 0);
  return WS_STATUS_OK;
}

static ws_status ws_inflate_message(ws_deflate_context *context,
                                    const uint8_t *input,
                                    size_t input_length,
                                    uint64_t max_output,
                                    bool reset_before,
                                    ws_output *output) {
  z_stream *stream = &context->stream;
  if (reset_before && inflateReset(stream) != Z_OK) {
    return ws_status_error(WS_DEFLATE_BACKEND);
  }

  size_t public_limit = max_output > SIZE_MAX ? SIZE_MAX : (size_t)max_output;
  output->hard_limit = public_limit == SIZE_MAX ? SIZE_MAX : public_limit + 1;

  ws_status result =
      ws_inflate_chunk(stream, input, input_length, Z_NO_FLUSH, output,
                       max_output);
  if (result != WS_STATUS_OK) {
    return result;
  }

  static const uint8_t marker[4] = {0x00, 0x00, 0xff, 0xff};
  result = ws_inflate_chunk(stream, marker, sizeof(marker), Z_SYNC_FLUSH,
                            output, max_output);
  if (result != WS_STATUS_OK) {
    return result;
  }
  return WS_STATUS_OK;
}

LEAN_EXPORT lean_obj_res ws_deflate_create(uint8_t compress,
                                            uint8_t window_bits) {
  if (window_bits < 8 || window_bits > 15) {
    return ws_io_except_error(WS_DEFLATE_INVALID_WINDOW);
  }

  ws_deflate_context *context =
      (ws_deflate_context *)calloc(1, sizeof(ws_deflate_context));
  if (context == NULL) {
    return ws_io_except_error(WS_DEFLATE_OUT_OF_MEMORY);
  }
  context->compress = compress != 0;

  int result;
  if (context->compress) {
    result = deflateInit2(&context->stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          -(int)window_bits, 8, Z_DEFAULT_STRATEGY);
  } else {
    result = inflateInit2(&context->stream, -(int)window_bits);
  }
  if (result != Z_OK) {
    free(context);
    if (result == Z_MEM_ERROR) {
      return ws_io_except_error(WS_DEFLATE_OUT_OF_MEMORY);
    }
    if (result == Z_STREAM_ERROR) {
      return ws_io_except_error(WS_DEFLATE_INVALID_WINDOW);
    }
    return ws_io_except_error(WS_DEFLATE_BACKEND);
  }

  context->initialized = true;
  lean_object *external =
      lean_alloc_external(ws_get_context_class(), (void *)context);
  return ws_io_except_ok(external);
}

LEAN_EXPORT lean_obj_res ws_deflate_process(b_lean_obj_arg context_object,
                                             b_lean_obj_arg input,
                                             uint64_t max_output,
                                             uint8_t reset_before) {
  ws_deflate_context *context = ws_unwrap_context(context_object);
  if (context == NULL || !context->initialized) {
    return ws_io_except_error(WS_DEFLATE_CLOSED);
  }

  const uint8_t *source = lean_sarray_cptr(input);
  size_t source_length = lean_sarray_size(input);
  ws_output output;
  ws_output_init(&output, 0);

  ws_status result;
  if (context->compress) {
    /* Compression is transactional.  A caller may decline an expanded result
       and send the original message; committing dictionary state for bytes
       that never reached the peer would corrupt the next takeover message. */
    ws_deflate_context candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.compress = true;
    int copied = deflateCopy(&candidate.stream, &context->stream);
    if (copied != Z_OK) {
      ws_output_release(&output);
      return ws_io_except_error(copied == Z_MEM_ERROR
                                    ? WS_DEFLATE_OUT_OF_MEMORY
                                    : WS_DEFLATE_BACKEND);
    }
    candidate.initialized = true;
    result = ws_deflate_message(&candidate, source, source_length, max_output,
                                reset_before != 0, &output);
    if (result == WS_STATUS_OK) {
      int ended = deflateEnd(&context->stream);
      memset(&context->stream, 0, sizeof(context->stream));
      int committed = deflateCopy(&context->stream, &candidate.stream);
      ws_context_release(&candidate);
      /* A persistent raw stream is intentionally never finalized with
         Z_FINISH. zlib reports Z_DATA_ERROR while still releasing that prior
         BUSY_STATE, so it is a successful ownership transition here. */
      if ((ended != Z_OK && ended != Z_DATA_ERROR) || committed != Z_OK) {
        if (committed == Z_OK) {
          (void)deflateEnd(&context->stream);
          memset(&context->stream, 0, sizeof(context->stream));
        }
        context->initialized = false;
        result = ws_status_error(WS_DEFLATE_BACKEND);
      }
    } else {
      ws_context_release(&candidate);
    }
  } else {
    result = ws_inflate_message(context, source, source_length, max_output,
                                reset_before != 0, &output);
  }
  if (result != WS_STATUS_OK) {
    ws_output_release(&output);
    return ws_io_except_error((enum ws_deflate_error)(result - 1));
  }

  lean_object *bytes = lean_alloc_sarray(1, output.length, output.length);
  if (output.length != 0) {
    memcpy(lean_sarray_cptr(bytes), output.data, output.length);
  }
  ws_output_release(&output);
  return ws_io_except_ok(bytes);
}

LEAN_EXPORT lean_obj_res ws_deflate_close(b_lean_obj_arg context_object) {
  ws_deflate_context *context = ws_unwrap_context(context_object);
  if (context != NULL) {
    ws_context_release(context);
  }
  return lean_io_result_mk_ok(lean_box(0));
}
