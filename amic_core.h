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

#define AMIC_UINT128_SIZE 16
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
} N(Uint128);

bool N(Uint128Verify)(N(Uint128) * p, bool _compatible) {
  return p->s.length == AMIC_UINT128_SIZE;
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
  N(Hash) h = N(OutPointTxHash)(p);
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

typedef struct {
  N(Slice) s;
} N(CellDep);

N(OutPoint) N(CellDepOutPoint)(N(CellDep) * c) {
  N(OutPoint) o;
  o.s = N(SliceSlice)(&c->s, 0, 36);
  return o;
}

N(DepType) N(CellDepDepType)(N(CellDep) * c) {
  N(DepType) d;
  d.s = N(SliceSlice)(&c->s, 36, 37);
  return d;
}

bool N(CellDepVerify)(N(CellDep) * c, bool compatible) {
  if (c->s.length != AMIC_CELLDEP_SIZE) {
    return false;
  }
  N(OutPoint) o = N(CellDepOutPoint)(c);
  N(DepType) d = N(CellDepDepType)(c);
  return (N(OutPointVerify)(&o, compatible)) &&
         (N(DepTypeVerify)(&d, compatible));
}

typedef struct {
  N(Slice) s;
} N(CellDepFixVec);

uint32_t N(CellDepFixVecLen)(N(CellDepFixVec) * c) {
  return *((uint32_t*)c->s.p);
}

N(CellDep) N(CellDepFixVecGet)(N(CellDepFixVec) * c, uint32_t i) {
  uint32_t start = 4 + i * AMIC_CELLDEP_SIZE;
  N(CellDep) d;
  d.s = N(SliceSlice)(&c->s, start, start + AMIC_CELLDEP_SIZE);
  return d;
}

bool N(CellDepFixVecVerify)(N(CellDepFixVec) * c, bool compatible) {
  if (c->s.length < 4) {
    return false;
  }
  uint32_t count = N(CellDepFixVecLen)(c);
  if (c->s.length != 4 + count * AMIC_CELLDEP_SIZE) {
    return false;
  }
  for (uint32_t i = 0; i < count; i++) {
    N(CellDep) d = N(CellDepFixVecGet)(c, i);
    if (!N(CellDepVerify)(&d, compatible)) {
      return false;
    }
  }
  return true;
}

typedef struct {
  N(Slice) s;
} N(HashFixVec);

uint32_t N(HashFixVecLen)(N(HashFixVec) * c) { return *((uint32_t*)c->s.p); }

N(Hash) N(HashFixVecGet)(N(HashFixVec) * c, uint32_t i) {
  uint32_t start = 4 + i * AMIC_CELLDEP_SIZE;
  N(Hash) d;
  d.s = N(SliceSlice)(&c->s, start, start + AMIC_CELLDEP_SIZE);
  return d;
}

bool N(HashFixVecVerify)(N(HashFixVec) * c, bool compatible) {
  if (c->s.length < 4) {
    return false;
  }
  uint32_t count = N(HashFixVecLen)(c);
  if (c->s.length != 4 + count * AMIC_CELLDEP_SIZE) {
    return false;
  }
  for (uint32_t i = 0; i < count; i++) {
    N(Hash) d = N(HashFixVecGet)(c, i);
    if (!N(HashVerify)(&d, compatible)) {
      return false;
    }
  }
  return true;
}

typedef struct {
  N(Slice) s;
} N(CellInputFixVec);

uint32_t N(CellInputFixVecLen)(N(CellInputFixVec) * c) {
  return *((uint32_t*)c->s.p);
}

N(CellInput) N(CellInputFixVecGet)(N(CellInputFixVec) * c, uint32_t i) {
  uint32_t start = 4 + i * AMIC_CELLDEP_SIZE;
  N(CellInput) d;
  d.s = N(SliceSlice)(&c->s, start, start + AMIC_CELLDEP_SIZE);
  return d;
}

bool N(CellInputFixVecVerify)(N(CellInputFixVec) * c, bool compatible) {
  if (c->s.length < 4) {
    return false;
  }
  uint32_t count = N(CellInputFixVecLen)(c);
  if (c->s.length != 4 + count * AMIC_CELLDEP_SIZE) {
    return false;
  }
  for (uint32_t i = 0; i < count; i++) {
    N(CellInput) d = N(CellInputFixVecGet)(c, i);
    if (!N(CellInputVerify)(&d, compatible)) {
      return false;
    }
  }
  return true;
}

typedef struct {
  N(Slice) s;
} N(CellOutputDynVec);

bool N(CellOutputDynVecVerify)(N(CellOutputDynVec) * c, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&c->s, 0, true);
  if (offset_count < 0) {
    return false;
  }
  for (int i = 0; i < offset_count; i++) {
    uint32_t start = extractOffset(&c->s, i, offset_count);
    uint32_t end = extractOffset(&c->s, i + 1, offset_count);
    if (end < start) {
      return false;
    }
    N(CellOutput) o;
    o.s = N(SliceSlice)(&c->s, start, end);
    if (!N(CellOutputVerify)(&o, compatible)) {
      return false;
    }
  }
  return true;
}

uint32_t N(CellOutputDynVecLen)(N(CellOutputDynVec) * c) {
  if (c->s.length < 8) {
    return 0;
  } else {
    return ((uint32_t*)c->s.p)[1] / 4 - 1;
  }
}

N(CellOutput) N(CellOutputDynVecGet)(N(CellOutputDynVec) * c, uint32_t i) {
  N(CellOutput) o;
  o.s = uncheckedField(&c->s, i, true);
  return o;
}

typedef struct {
  N(Slice) s;
} N(BytesDynVec);

bool N(BytesDynVecVerify)(N(BytesDynVec) * c, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&c->s, 0, true);
  if (offset_count < 0) {
    return false;
  }
  for (int i = 0; i < offset_count; i++) {
    uint32_t start = extractOffset(&c->s, i, offset_count);
    uint32_t end = extractOffset(&c->s, i + 1, offset_count);
    if (end < start) {
      return false;
    }
    N(Bytes) o;
    o.s = N(SliceSlice)(&c->s, start, end);
    if (!N(BytesVerify)(&o, compatible)) {
      return false;
    }
  }
  return true;
}

uint32_t N(BytesDynVecLen)(N(BytesDynVec) * c) {
  if (c->s.length < 8) {
    return 0;
  } else {
    return ((uint32_t*)c->s.p)[1] / 4 - 1;
  }
}

N(Bytes) N(BytesDynVecGet)(N(BytesDynVec) * c, uint32_t i) {
  N(Bytes) o;
  o.s = uncheckedField(&c->s, i, true);
  return o;
}

typedef struct {
  N(Slice) s;
} N(RawTransaction);

bool N(RawTransactionVerify)(N(RawTransaction) * t, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&t->s, 6, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offsets[7];
  for (int i = 0; i < 7; i++) {
    offsets[i] = extractOffset(&t->s, i, offset_count);
    if ((i > 0) && (offsets[i] < offsets[i - 1])) {
      return false;
    }
  }
  if (offsets[1] - offsets[0] != 4) {
    return false;
  }
  N(CellDepFixVec) dv;
  dv.s = N(SliceSlice)(&t->s, offsets[1], offsets[2]);
  if (!N(CellDepFixVecVerify)(&dv, compatible)) {
    return false;
  }
  N(HashFixVec) hv;
  hv.s = N(SliceSlice)(&t->s, offsets[2], offsets[3]);
  if (!N(HashFixVecVerify)(&hv, compatible)) {
    return false;
  }
  N(CellInputFixVec) iv;
  iv.s = N(SliceSlice)(&t->s, offsets[3], offsets[4]);
  if (!N(CellInputFixVecVerify)(&iv, compatible)) {
    return false;
  }
  N(CellOutputDynVec) ov;
  ov.s = N(SliceSlice)(&t->s, offsets[4], offsets[5]);
  if (!N(CellOutputDynVecVerify)(&ov, compatible)) {
    return false;
  }
  N(BytesDynVec) bv;
  bv.s = N(SliceSlice)(&t->s, offsets[5], offsets[6]);
  if (!N(BytesDynVecVerify)(&bv, compatible)) {
    return false;
  }
  return true;
}

uint32_t N(RawTransactionVersion)(N(RawTransaction) * t) {
  N(Slice) slice = uncheckedField(&t->s, 0, false);
  return *((uint32_t*)slice.p);
}

N(CellDepFixVec) N(RawTransactionCellDeps)(N(RawTransaction) * t) {
  N(CellDepFixVec) v;
  v.s = uncheckedField(&t->s, 1, false);
  return v;
}

N(HashFixVec) N(RawTransactionHeaderDeps)(N(RawTransaction) * t) {
  N(HashFixVec) v;
  v.s = uncheckedField(&t->s, 2, false);
  return v;
}

N(CellInputFixVec) N(RawTransactionInputs)(N(RawTransaction) * t) {
  N(CellInputFixVec) v;
  v.s = uncheckedField(&t->s, 3, false);
  return v;
}

N(CellOutputDynVec) N(RawTransactionOutputs)(N(RawTransaction) * t) {
  N(CellOutputDynVec) v;
  v.s = uncheckedField(&t->s, 4, false);
  return v;
}

N(BytesDynVec) N(RawTransactionOutputsData)(N(RawTransaction) * t) {
  N(BytesDynVec) v;
  v.s = uncheckedField(&t->s, 5, true);
  return v;
}

typedef struct {
  N(Slice) s;
} N(Transaction);

bool N(TransactionVerify)(N(Transaction) * t, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&t->s, 2, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&t->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&t->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&t->s, 2, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1)) {
    return false;
  }
  N(RawTransaction) rt;
  rt.s = N(SliceSlice)(&t->s, offset0, offset1);
  if (!N(RawTransactionVerify)(&rt, compatible)) {
    return false;
  }
  N(BytesDynVec) v;
  v.s = N(SliceSlice)(&t->s, offset1, offset2);
  if (!N(BytesDynVecVerify)(&v, compatible)) {
    return false;
  }
  return true;
}

typedef struct {
  N(Slice) s;
} N(RawHeader);

uint32_t N(RawHeaderVersion)(N(RawHeader) * h) { return *((uint32_t*)h->s.p); }

uint32_t N(RawHeaderCompactTarget)(N(RawHeader) * h) {
  return ((uint32_t*)h->s.p)[1];
}

uint64_t N(RawHeaderTimestamp)(N(RawHeader) * h) {
  return ((uint64_t*)h->s.p)[1];
}

uint64_t N(RawHeaderNumber)(N(RawHeader) * h) { return ((uint64_t*)h->s.p)[2]; }

uint64_t N(RawHeaderEpoch)(N(RawHeader) * h) { return ((uint64_t*)h->s.p)[3]; }

N(Hash) N(RawHeaderParentHash)(N(RawHeader) * h) {
  N(Hash) r;
  r.s = N(SliceSlice)(&h->s, 32, 64);
  return r;
}

N(Hash) N(RawHeaderTransactionsRoot)(N(RawHeader) * h) {
  N(Hash) r;
  r.s = N(SliceSlice)(&h->s, 64, 96);
  return r;
}

N(Hash) N(RawHeaderProposalsHash)(N(RawHeader) * h) {
  N(Hash) r;
  r.s = N(SliceSlice)(&h->s, 96, 128);
  return r;
}

N(Hash) N(RawHeaderUnclesHash)(N(RawHeader) * h) {
  N(Hash) r;
  r.s = N(SliceSlice)(&h->s, 128, 160);
  return r;
}

N(Byte32) N(RawHeaderDao)(N(RawHeader) * h) {
  N(Byte32) r;
  r.s = N(SliceSlice)(&h->s, 160, 196);
  return r;
}

bool N(RawHeaderVerify)(N(RawHeader) * h, bool compatible) {
  if (h->s.length != AMIC_RAWHEADER_SIZE) {
    return false;
  }
  N(Hash) parentHash = N(RawHeaderParentHash)(h);
  N(Hash) transactionsRoot = N(RawHeaderTransactionsRoot)(h);
  N(Hash) proposalsHash = N(RawHeaderProposalsHash)(h);
  N(Hash) unclesHash = N(RawHeaderUnclesHash)(h);
  N(Byte32) dao = N(RawHeaderDao)(h);

  return (N(HashVerify)(&parentHash, compatible)) &&
         (N(HashVerify)(&transactionsRoot, compatible)) &&
         (N(HashVerify(&proposalsHash, compatible))) &&
         (N(HashVerify(&unclesHash, compatible))) &&
         (N(Byte32Verify(&dao, compatible)));
}

typedef struct {
  N(Slice) s;
} N(Header);

N(RawHeader) N(HeaderRawHeader)(N(Header) * h) {
  N(RawHeader) r;
  r.s = N(SliceSlice)(&h->s, 0, 192);
  return r;
}

N(Uint128) N(HeaderNonce)(N(Header) * h) {
  N(Uint128) u;
  u.s = N(SliceSlice)(&h->s, 192, 208);
  return u;
}

bool N(HeaderVerify)(N(Header) * h, bool compatible) {
  if (h->s.length != AMIC_HEADER_SIZE) {
    return false;
  }
  N(RawHeader) r = N(HeaderRawHeader)(h);
  N(Uint128) u = N(HeaderNonce)(h);
  return (N(RawHeaderVerify)(&r, compatible)) &&
         (N(Uint128Verify)(&u, compatible));
}

typedef struct {
  N(Slice) s;
} N(ProposalShortId);

bool N(ProposalShortIdVerify)(N(ProposalShortId) * p, bool _compatible) {
  return p->s.length == AMIC_PROPOSALSHORTID_SIZE;
}

typedef struct {
  N(Slice) s;
} N(ProposalShortIdFixVec);

uint32_t N(ProposalShortIdFixVecLen)(N(ProposalShortIdFixVec) * c) {
  return *((uint32_t*)c->s.p);
}

N(ProposalShortId)
N(ProposalShortIdFixVecGet)(N(ProposalShortIdFixVec) * c, uint32_t i) {
  uint32_t start = 4 + i * AMIC_CELLDEP_SIZE;
  N(ProposalShortId) d;
  d.s = N(SliceSlice)(&c->s, start, start + AMIC_CELLDEP_SIZE);
  return d;
}

bool N(ProposalShortIdFixVecVerify)(N(ProposalShortIdFixVec) * c,
                                    bool compatible) {
  if (c->s.length < 4) {
    return false;
  }
  uint32_t count = N(ProposalShortIdFixVecLen)(c);
  if (c->s.length != 4 + count * AMIC_CELLDEP_SIZE) {
    return false;
  }
  for (uint32_t i = 0; i < count; i++) {
    N(ProposalShortId) d = N(ProposalShortIdFixVecGet)(c, i);
    if (!N(ProposalShortIdVerify)(&d, compatible)) {
      return false;
    }
  }
  return true;
}

typedef struct {
  N(Slice) s;
} N(UncleBlock);

bool N(UncleBlockVerify)(N(UncleBlock) * b, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&b->s, 2, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&b->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&b->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&b->s, 2, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1)) {
    return false;
  }
  N(Header) h;
  h.s = N(SliceSlice)(&b->s, offset0, offset1);
  if (!N(HeaderVerify)(&h, compatible)) {
    return false;
  }
  N(ProposalShortIdFixVec) v;
  v.s = N(SliceSlice)(&b->s, offset1, offset2);
  if (!N(ProposalShortIdFixVecVerify)(&v, compatible)) {
    return false;
  }
  return true;
}

N(Header) N(UncleBlockHeader)(N(UncleBlock) * b) {
  N(Header) h;
  h.s = uncheckedField(&b->s, 0, false);
  return h;
}

N(ProposalShortIdFixVec) N(UncleBlockProposals)(N(UncleBlock) * b) {
  N(ProposalShortIdFixVec) v;
  v.s = uncheckedField(&b->s, 1, true);
  return v;
}

typedef struct {
  N(Slice) s;
} N(UncleBlockDynVec);

bool N(UncleBlockDynVecVerify)(N(UncleBlockDynVec) * c, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&c->s, 0, true);
  if (offset_count < 0) {
    return false;
  }
  for (int i = 0; i < offset_count; i++) {
    uint32_t start = extractOffset(&c->s, i, offset_count);
    uint32_t end = extractOffset(&c->s, i + 1, offset_count);
    if (end < start) {
      return false;
    }
    N(UncleBlock) o;
    o.s = N(SliceSlice)(&c->s, start, end);
    if (!N(UncleBlockVerify)(&o, compatible)) {
      return false;
    }
  }
  return true;
}

uint32_t N(UncleBlockDynVecLen)(N(UncleBlockDynVec) * c) {
  if (c->s.length < 8) {
    return 0;
  } else {
    return ((uint32_t*)c->s.p)[1] / 4 - 1;
  }
}

N(UncleBlock) N(UncleBlockDynVecGet)(N(UncleBlockDynVec) * c, uint32_t i) {
  N(UncleBlock) o;
  o.s = uncheckedField(&c->s, i, true);
  return o;
}

typedef struct {
  N(Slice) s;
} N(TransactionDynVec);

bool N(TransactionDynVecVerify)(N(TransactionDynVec) * c, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&c->s, 0, true);
  if (offset_count < 0) {
    return false;
  }
  for (int i = 0; i < offset_count; i++) {
    uint32_t start = extractOffset(&c->s, i, offset_count);
    uint32_t end = extractOffset(&c->s, i + 1, offset_count);
    if (end < start) {
      return false;
    }
    N(Transaction) o;
    o.s = N(SliceSlice)(&c->s, start, end);
    if (!N(TransactionVerify)(&o, compatible)) {
      return false;
    }
  }
  return true;
}

uint32_t N(TransactionDynVecLen)(N(TransactionDynVec) * c) {
  if (c->s.length < 8) {
    return 0;
  } else {
    return ((uint32_t*)c->s.p)[1] / 4 - 1;
  }
}

N(Transaction) N(TransactionDynVecGet)(N(TransactionDynVec) * c, uint32_t i) {
  N(Transaction) o;
  o.s = uncheckedField(&c->s, i, true);
  return o;
}

typedef struct {
  N(Slice) s;
} N(Block);

bool N(BlockVerify)(N(Block) * b, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&b->s, 4, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&b->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&b->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&b->s, 2, offset_count);
  uint32_t offset3 = extractOffset(&b->s, 3, offset_count);
  uint32_t offset4 = extractOffset(&b->s, 4, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1) || (offset3 < offset2) ||
      (offset4 < offset3)) {
    return false;
  }
  N(Header) h;
  h.s = N(SliceSlice)(&b->s, offset0, offset1);
  if (!N(HeaderVerify)(&h, compatible)) {
    return false;
  }
  N(UncleBlockDynVec) bv;
  bv.s = N(SliceSlice)(&b->s, offset1, offset2);
  if (!N(UncleBlockDynVecVerify)(&bv, compatible)) {
    return false;
  }
  N(TransactionDynVec) tv;
  tv.s = N(SliceSlice)(&b->s, offset2, offset3);
  if (!N(TransactionDynVecVerify)(&tv, compatible)) {
    return false;
  }
  N(ProposalShortIdFixVec) v;
  v.s = N(SliceSlice)(&b->s, offset3, offset4);
  if (!N(ProposalShortIdFixVecVerify)(&v, compatible)) {
    return false;
  }
  return true;
}

N(Header) N(BlockHeader)(N(Block) * b) {
  N(Header) h;
  h.s = uncheckedField(&b->s, 0, false);
  return h;
}

N(UncleBlockDynVec) N(BlockUncles)(N(Block) * b) {
  N(UncleBlockDynVec) v;
  v.s = uncheckedField(&b->s, 1, false);
  return v;
}

N(TransactionDynVec) N(BlockTransactions)(N(Block) * b) {
  N(TransactionDynVec) v;
  v.s = uncheckedField(&b->s, 2, false);
  return v;
}

N(ProposalShortIdFixVec) N(BlockProposals)(N(Block) * b) {
  N(ProposalShortIdFixVec) v;
  v.s = uncheckedField(&b->s, 3, true);
  return v;
}

typedef struct {
  N(Slice) s;
} N(CellbaseWitness);

bool N(CellbaseWitnessVerify)(N(CellbaseWitness) * w, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&w->s, 2, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&w->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&w->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&w->s, 2, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1)) {
    return false;
  }
  N(Script) lock;
  lock.s = N(SliceSlice)(&w->s, offset0, offset1);
  if (!N(ScriptVerify)(&lock, compatible)) {
    return false;
  }
  N(Bytes) message;
  message.s = N(SliceSlice)(&w->s, offset1, offset2);
  if (!N(BytesVerify)(&message, compatible)) {
    return false;
  }
  return true;
}

N(Script) N(CellbaseWitnessLock)(N(CellbaseWitness) * w) {
  N(Script) lock;
  lock.s = uncheckedField(&w->s, 0, false);
  return lock;
}

N(Bytes) N(CellbaseWitnessMessage)(N(CellbaseWitness) * w) {
  N(Bytes) message;
  message.s = uncheckedField(&w->s, 1, true);
  return message;
}

typedef struct {
  N(Slice) s;
} N(WitnessArgs);

bool N(WitnessArgsVerify)(N(WitnessArgs) * a, bool compatible) {
  int offset_count = verifyAndExtractOffsetCount(&a->s, 3, compatible);
  if (offset_count < 0) {
    return false;
  }
  uint32_t offset0 = extractOffset(&a->s, 0, offset_count);
  uint32_t offset1 = extractOffset(&a->s, 1, offset_count);
  uint32_t offset2 = extractOffset(&a->s, 2, offset_count);
  uint32_t offset3 = extractOffset(&a->s, 3, offset_count);
  if ((offset1 < offset0) || (offset2 < offset1) || (offset3 < offset2)) {
    return false;
  }
  if (offset1 - offset0 > 0) {
    N(Script) lock;
    lock.s = N(SliceSlice)(&a->s, offset0, offset1);
    if (!N(ScriptVerify)(&lock, compatible)) {
      return false;
    }
  }
  if (offset2 - offset1 > 0) {
    N(Script) inputType;
    inputType.s = N(SliceSlice)(&a->s, offset1, offset2);
    if (!N(ScriptVerify)(&inputType, compatible)) {
      return false;
    }
  }
  if (offset3 - offset2 > 0) {
    N(Script) outputType;
    outputType.s = N(SliceSlice)(&a->s, offset2, offset3);
    if (!N(ScriptVerify)(&outputType, compatible)) {
      return false;
    }
  }
  return true;
}

bool N(WitnessArgsHasLock)(N(WitnessArgs) * a) {
  return uncheckedField(&a->s, 0, false).length > 0;
}

N(Script) N(WitnessArgsLock)(N(WitnessArgs) * a) {
  N(Script) s;
  s.s = uncheckedField(&a->s, 0, false);
  return s;
}

bool N(WitnessArgsHasInputType)(N(WitnessArgs) * a) {
  return uncheckedField(&a->s, 0, false).length > 0;
}

N(Script) N(WitnessArgsInputType)(N(WitnessArgs) * a) {
  N(Script) s;
  s.s = uncheckedField(&a->s, 0, false);
  return s;
}

bool N(WitnessArgsHasOutputType)(N(WitnessArgs) * a) {
  return uncheckedField(&a->s, 0, false).length > 0;
}

N(Script) N(WitnessArgsOutputType)(N(WitnessArgs) * a) {
  N(Script) s;
  s.s = uncheckedField(&a->s, 0, false);
  return s;
}

#undef N

#endif /* AMIC_H_ */
