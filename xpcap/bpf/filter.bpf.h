#ifndef XPCAP_FILTER_BPF_H
#define XPCAP_FILTER_BPF_H

#include <linux/filter.h>

struct capture_filter {
  __u32 length;
  struct sock_filter instructions[XPCAP_MAX_FILTER_INSNS];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct capture_filter);
} capture_filter SEC(".maps");

static __always_inline bool filter_read(const void *data, __u32 len, __u32 off,
                                        __u16 size, __u32 *value) {
  const char *start = data;
  if (off > len)
    return false;
  if (size == BPF_W) {
    __u8 bytes[4];
    if (len - off < 4 || bpf_probe_read_kernel(bytes, 4, start + off))
      return false;
    *value = ((__u32)bytes[0] << 24) | ((__u32)bytes[1] << 16) |
             ((__u32)bytes[2] << 8) | bytes[3];
  } else if (size == BPF_H) {
    __u8 bytes[2];
    if (len - off < 2 || bpf_probe_read_kernel(bytes, 2, start + off))
      return false;
    *value = ((__u32)bytes[0] << 8) | bytes[1];
  } else if (size == BPF_B) {
    __u8 byte;
    if (len - off < 1 || bpf_probe_read_kernel(&byte, 1, start + off))
      return false;
    *value = byte;
  } else
    return false;
  return true;
}

struct filter_state {
  const void *data;
  const struct capture_filter *filter;
  __u32 len;
  __u32 packet_len;
  __u32 count;
  __u32 a;
  __u32 x;
  __u32 memory;
  __u32 pc;
  bool accepted;
};

static long filter_step(__u32 step, void *context) {
  struct filter_state *state = context;
  if (state->pc >= state->count || state->pc >= XPCAP_MAX_FILTER_INSNS)
    return 1;
  __u32 index = state->pc;
  asm volatile("%0 &= 127" : "+r"(index));
  const struct sock_filter *insn = &state->filter->instructions[index];
  state->pc++;
  __u16 code = insn->code;
  __u32 k = insn->k;
  switch (BPF_CLASS(code)) {
  case BPF_LD:
    if (BPF_MODE(code) == BPF_ABS || BPF_MODE(code) == BPF_IND) {
      __u32 off = BPF_MODE(code) == BPF_ABS ? k : state->x + k;
      if (!filter_read(state->data, state->len, off, BPF_SIZE(code), &state->a))
        return 1;
    } else if (BPF_MODE(code) == BPF_LEN)
      state->a = state->packet_len;
    else if (BPF_MODE(code) == BPF_IMM)
      state->a = k;
    else if (BPF_MODE(code) == BPF_MEM && k == 0)
      state->a = state->memory;
    else
      return 1;
    break;
  case BPF_LDX:
    if (BPF_MODE(code) == BPF_MSH && BPF_SIZE(code) == BPF_B) {
      __u32 byte;
      if (!filter_read(state->data, state->len, k, BPF_B, &byte))
        return 1;
      state->x = 4 * (byte & 15);
    } else if (BPF_MODE(code) == BPF_LEN)
      state->x = state->packet_len;
    else if (BPF_MODE(code) == BPF_IMM)
      state->x = k;
    else if (BPF_MODE(code) == BPF_MEM && k == 0)
      state->x = state->memory;
    else
      return 1;
    break;
  case BPF_ST:
    if (k != 0)
      return 1;
    state->memory = state->a;
    break;
  case BPF_STX:
    if (k != 0)
      return 1;
    state->memory = state->x;
    break;
  case BPF_ALU: {
    __u32 v = BPF_SRC(code) == BPF_X ? state->x : k;
    switch (BPF_OP(code)) {
    case BPF_ADD:
      state->a += v;
      break;
    case BPF_SUB:
      state->a -= v;
      break;
    case BPF_MUL:
      state->a *= v;
      break;
    case BPF_DIV:
      if (!v)
        return 1;
      state->a /= v;
      break;
    case BPF_OR:
      state->a |= v;
      break;
    case BPF_AND:
      state->a &= v;
      break;
    case BPF_LSH:
      state->a <<= v & 31;
      break;
    case BPF_RSH:
      state->a >>= v & 31;
      break;
    case BPF_NEG:
      state->a = -state->a;
      break;
    case BPF_XOR:
      state->a ^= v;
      break;
    default:
      return 1;
    }
    break;
  }
  case BPF_JMP:
    if (BPF_OP(code) == BPF_JA) {
      state->pc += k;
      break;
    }
    __u32 v = BPF_SRC(code) == BPF_X ? state->x : k;
    bool taken;
    switch (BPF_OP(code)) {
    case BPF_JEQ:
      taken = state->a == v;
      break;
    case BPF_JGT:
      taken = state->a > v;
      break;
    case BPF_JGE:
      taken = state->a >= v;
      break;
    case BPF_JSET:
      taken = (state->a & v) != 0;
      break;
    default:
      return 1;
    }
    state->pc += taken ? insn->jt : insn->jf;
    break;
  case BPF_RET:
    state->accepted = (BPF_RVAL(code) == BPF_A ? state->a : k) != 0;
    return 1;
  case BPF_MISC:
    if (BPF_MISCOP(code) == BPF_TAX)
      state->x = state->a;
    else if (BPF_MISCOP(code) == BPF_TXA)
      state->a = state->x;
    else
      return 1;
    break;
  default:
    return 1;
  }
  return 0;
}

static __attribute__((noinline)) bool filter_matches(const void *data,
                                                     __u32 len,
                                                     __u32 packet_len) {
  __u32 key = 0;
  const struct capture_filter *filter =
      bpf_map_lookup_elem(&capture_filter, &key);
  if (!filter)
    return false;
  __u32 count = filter->length;
  if (!count)
    return true;
  if (count > XPCAP_MAX_FILTER_INSNS || !data)
    return false;
  struct filter_state state = {
      .data = data,
      .filter = filter,
      .len = len,
      .packet_len = packet_len,
      .count = count,
  };
  bpf_loop(count, filter_step, &state, 0);
  return state.accepted;
}

#endif
