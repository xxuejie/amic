#ifndef AMIC_H_
#define AMIC_H_

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This library only works on little endian machine!"
#endif

#include <stdbool.h>
#include <stdint.h>

#ifdef AMIC_NAMESPACE
#define N(t) AMIC_NAMESPACE##t
#else
#define N(t) t
#endif

#define AMIC_DATA 0
#define AMIC_TYPE 1
#define AMIC_CODE 0
#define AMIC_DEPGROUP 1

#define AMIC_BYTE32_SIZE 32
#define AMIC_HASH_SIZE 32
#define AMIC_OUTPOINT_SIZE 36
#define AMIC_CELLINPUT_SIZE 44
#define AMIC_CELLDEP_SIZE 37
#define AMIC_RAWHEADER_SIZE 192
#define AMIC_HEADER_SIZE 208
#define AMIC_PROPOSALSHORTID_SIZE 10

typedef struct {
  void* p;
  uint32_t length;
} N(Slice);

N(Slice) N(SliceSlice)(N(Slice) * s, uint32_t start, uint32_t end) {
  N(Slice) r;
  r.p = &((uint8_t*)s->p)[start];
  r.length = end - start;
  return r;
}

typedef struct {
  N(Slice) s;
} N(Byte32);

bool N(Byte32Verify)(N(Byte32) * p, bool _compatible) {
  return p->s.length == AMIC_BYTE32_SIZE;
}

typedef struct {
  N(Slice) s;
} N(Hash);

bool N(HashVerify)(N(Hash) * p, bool _compatible) {
  return p->s.length == AMIC_HASH_SIZE;
}

typedef struct {
  N(Slice) s;
} N(ScriptHashType);

bool N(ScriptHashTypeVerify)(N(ScriptHashType) * p, bool _compatible) {
  if (p->s.length != 1) {
    return 0;
  }
  uint8_t* a = (uint8_t*)p->s.p;
  return (a[0] == AMIC_DATA) || (a[0] == AMIC_TYPE);
}

uint8_t N(ScriptHashTypeValue)(N(ScriptHashType) * p) {
  return ((uint8_t*)p->s.p)[0];
}

typedef struct {
  N(Slice) s;
} N(DepType);

bool N(DepTypeVerify)(N(DepType) * p, bool _compatible) {
  if (p->s.length != 1) {
    return 0;
  }
  uint8_t* a = (uint8_t*)p->s.p;
  return (a[0] == AMIC_CODE) || (a[0] == AMIC_DEPGROUP);
}

uint8_t N(DepTypeValue)(N(DepType) * p) { return ((uint8_t*)p->s.p)[0]; }

typedef struct {
  N(Slice) s;
} N(Bytes);

bool N(BytesVerify)(N(Bytes) * p, bool _compatible) {
  if (p->s.length < 4) {
    return false;
  }
  uint32_t count = *((uint32_t*)p->s.p);
  return p->s.length == count + 4;
}

void* N(BytesValue)(N(Bytes) * p, uint32_t* out_len) {
  if (out_len) {
    *out_len = p->s.length - 4;
  }
  return &((uint8_t*)p->s.p)[4];
}

typedef struct {
  N(Slice) s;
} N(OutPoint);

N(Hash) N(OutPointTxHash)(N(OutPoint) * p) {
  N(Hash) h;
  h.s = N(SliceSlice)(&p->s, 0, 32);
  return h;
}

uint32_t N(OutPointIndex)(N(OutPoint) * p) { return ((uint32_t*)p->s.p)[8]; }

bool N(OutPointVerify)(N(OutPoint) * p, bool compatible) {
  if (p->s.length != AMIC_OUTPOINT_SIZE) {
    return false;
  }
  Hash h = N(OutPointTxHash)(p);
  return N(HashVerify)(&h, compatible);
}

typedef struct {
  N(Slice) s;
} N(CellInput);

uint64_t N(CellInputSince)(N(CellInput) * p) { return *((uint64_t*)p->s.p); }

N(OutPoint) N(CellInputPreviousOutput)(N(CellInput) * p) {
  N(OutPoint) o;
  o.s = N(SliceSlice)(&p->s, 8, 44);
  return o;
}

bool N(CellInputVerify)(N(CellInput) * p, bool compatible) {
  if (p->s.length != AMIC_CELLINPUT_SIZE) {
    return false;
  }
  N(OutPoint) o = N(CellInputPreviousOutput)(p);
  return N(OutPointVerify)(&o, compatible);
}

int extractOffsetCount(const N(Slice) * s) {
  if (s->length < 4) {
    return -1;
  }
  uint32_t slice_len = *((uint32_t*)s->p);
  if (slice_len != s->length) {
    return -1;
  }
  if (slice_len == 4) {
    return 0;
  }
  if (slice_len < 8) {
    return -1;
  }
  uint32_t first_offset = ((uint32_t*)s->p)[1];
  if ((first_offset % 4 != 0) || (first_offset < 8)) {
    return -1;
  }
  return first_offset / 4 - 1;
}

int verifyAndExtractOffsetCount(const N(Slice) * s, int expected_field_count,
                                bool compatible) {
  int offset_count = extractOffsetCount(s);
  if (offset_count < 0) {
    return offset_count;
  }
  if (offset_count < expected_field_count) {
    return -2;
  } else if ((!compatible) && (offset_count > expected_field_count)) {
    return -2;
  }
  return offset_count;
}

uint32_t extractOffset(const N(Slice) * s, int index, int offset_count) {
  if (index < offset_count) {
    return ((uint32_t*)s->p)[index + 1];
  } else {
    return s->length;
  }
}

N(Slice) uncheckedField(N(Slice) * s, uint32_t index, bool last) {
  uint32_t start = index + 1;
  uint32_t offset = ((uint32_t*)s->p)[start];
  uint32_t offset_end;
  if (!last) {
    offset_end = ((uint32_t*)s->p)[start + 1];
  } else {
    uint32_t field_count = ((uint32_t*)s->p)[1] / 4 - 1;
    if (index + 1 < field_count) {
      offset_end = ((uint32_t*)s->p)[start + 1];
    } else {
      offset_end = s->length;
    }
  }
  return N(SliceSlice)(s, offset, offset_end);
}

typedef struct {
  N(Slice) s;
} N(Script);

bool N(ScriptVerify)(N(Script) * p, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&p->s, 3, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&p->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&p->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&p->s, 2, offset_count);
  uint32_t offset3 = extractOffset(&p->s, 3, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1) || (offset3 < offset2)) {
    return false;
  }
  N(Hash) h;
  h.s = N(SliceSlice)(&p->s, offset0, offset1);
  if (!N(HashVerify)(&h, compatible)) {
    return false;
  }
  N(ScriptHashType) t;
  t.s = N(SliceSlice)(&p->s, offset1, offset2);
  if (!N(ScriptHashTypeVerify)(&t, compatible)) {
    return false;
  }
  N(Bytes) b;
  b.s = N(SliceSlice)(&p->s, offset2, offset3);
  if (!N(BytesVerify)(&b, compatible)) {
    return false;
  }
  return true;
}

N(Hash) N(ScriptCodeHash)(N(Script) * s) {
  N(Hash) h;
  h.s = uncheckedField(&s->s, 0, false);
  return h;
}

N(ScriptHashType) N(ScriptScriptHashType)(N(Script) * s) {
  N(ScriptHashType) t;
  t.s = uncheckedField(&s->s, 1, false);
  return t;
}

N(Bytes) N(ScriptArgs)(N(Script) * s) {
  N(Bytes) b;
  b.s = uncheckedField(&s->s, 2, true);
  return b;
}

typedef struct {
  N(Slice) s;
} N(CellOutput);

bool N(CellOutputVerify)(N(CellOutput) * c, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&c->s, 3, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&c->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&c->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&c->s, 2, offset_count);
  uint32_t offset3 = extractOffset(&c->s, 3, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1) || (offset3 < offset2)) {
    return false;
  }
  if (offset1 - offset0 != 8) {
    return false;
  }
  N(Script) lock;
  lock.s = N(SliceSlice)(&c->s, offset1, offset2);
  if (!N(ScriptVerify)(&lock, compatible)) {
    return false;
  }
  if (offset3 - offset2 > 0) {
    N(Script) type;
    type.s = N(SliceSlice)(&c->s, offset2, offset3);
    if (!N(ScriptVerify)(&type, compatible)) {
      return false;
    }
  }
  return true;
}

uint64_t N(CellOutputCapacity)(N(Script) * s) {
  N(Slice) slice = uncheckedField(&s->s, 0, false);
  return *((uint64_t*)slice.p);
}

N(Script) N(CellOutputLock)(N(Script) * s) {
  N(Script) lock;
  lock.s = uncheckedField(&s->s, 1, false);
  return lock;
}

bool N(CellOutputHasType)(N(Script) * s) {
  return uncheckedField(&s->s, 2, true).length > 0;
}

N(Script) N(CellOutputType)(N(Script) * s) {
  N(Script) type;
  type.s = uncheckedField(&s->s, 2, true);
  return type;
}

#undef N

#endif /* AMIC_H_ */
