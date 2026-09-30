use anyhow::{bail, Result};
use pktbaffle::bpf::*;
use pktbaffle::{Insn, Program};

pub const MAX_FILTER_INSNS: usize = 128;
const FILTER_VALUE_SIZE: usize = 4 + MAX_FILTER_INSNS * 8;

pub fn encode(program: Option<&Program>) -> Result<Vec<u8>> {
    let mut value = vec![0; FILTER_VALUE_SIZE];
    let Some(program) = program else {
        return Ok(value);
    };
    let instructions = program
        .as_classic()
        .ok_or_else(|| anyhow::anyhow!("capture filter must use classic BPF"))?
        .instructions();
    validate(instructions)?;
    value[..4].copy_from_slice(&(instructions.len() as u32).to_ne_bytes());
    for (index, insn) in instructions.iter().enumerate() {
        let offset = 4 + index * 8;
        value[offset..offset + 2].copy_from_slice(&insn.code.to_ne_bytes());
        value[offset + 2] = insn.jt;
        value[offset + 3] = insn.jf;
        value[offset + 4..offset + 8].copy_from_slice(&insn.k.to_ne_bytes());
    }
    Ok(value)
}

fn validate(instructions: &[Insn]) -> Result<()> {
    if instructions.is_empty() || instructions.len() > MAX_FILTER_INSNS {
        bail!(
            "capture filter needs 1..={MAX_FILTER_INSNS} instructions, got {}",
            instructions.len()
        );
    }
    for (index, insn) in instructions.iter().enumerate() {
        let code = insn.code;
        let mode = code & 0xe0;
        let size = code & 0x18;
        let supported = match code & 0x07 {
            BPF_LD => match mode {
                BPF_ABS | BPF_IND => matches!(size, BPF_W | BPF_H | BPF_B),
                BPF_LEN | BPF_IMM => size == BPF_W,
                BPF_MEM => size == BPF_W && insn.k == 0,
                _ => false,
            },
            BPF_LDX => match mode {
                BPF_MSH => size == BPF_B,
                BPF_LEN | BPF_IMM => size == BPF_W,
                BPF_MEM => size == BPF_W && insn.k == 0,
                _ => false,
            },
            BPF_ST | BPF_STX => insn.k == 0 && (code == BPF_ST || code == BPF_STX),
            BPF_ALU => {
                let operation = code & 0xf0;
                matches!(
                    operation,
                    BPF_ADD
                        | BPF_SUB
                        | BPF_MUL
                        | BPF_DIV
                        | BPF_OR
                        | BPF_AND
                        | BPF_LSH
                        | BPF_RSH
                        | BPF_NEG
                        | BPF_XOR
                ) && !(operation == BPF_DIV && code & BPF_X == 0 && insn.k == 0)
            }
            BPF_JMP => {
                let operation = code & 0xf0;
                if operation == BPF_JA {
                    code == BPF_JMP
                        && index
                            .checked_add(1)
                            .and_then(|next| next.checked_add(insn.k as usize))
                            .is_some_and(|target| target < instructions.len())
                } else {
                    matches!(operation, BPF_JEQ | BPF_JGT | BPF_JGE | BPF_JSET)
                        && [insn.jt, insn.jf]
                            .iter()
                            .all(|offset| index + 1 + usize::from(*offset) < instructions.len())
                }
            }
            BPF_RET => code == BPF_RET || code == (BPF_RET | BPF_A),
            BPF_MISC => code == (BPF_MISC | BPF_TAX) || code == (BPF_MISC | BPF_TXA),
            _ => false,
        };
        if !supported {
            bail!("capture filter instruction {index} (code 0x{code:04x}) cannot run in the probe");
        }
    }
    if instructions
        .last()
        .is_none_or(|insn| insn.code & 0x07 != BPF_RET)
    {
        bail!("capture filter must end in a return instruction");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pktbaffle::{compile, LinkType, Target};

    #[test]
    fn encodes_common_filters_for_probe() {
        for expression in [
            "tcp and (port 80 or port 443)",
            "udp and src net 192.0.2.0/24 and dst port 9000",
            "host 2001:db8::1",
            "tcp[13] & 2 != 0",
        ] {
            let program = compile(expression, LinkType::Ethernet, Target::Classic).unwrap();
            let bytes = encode(Some(&program)).unwrap();
            assert_eq!(bytes.len(), FILTER_VALUE_SIZE);
            assert_eq!(
                u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize,
                program.len()
            );
        }
    }

    #[test]
    fn rejects_filters_that_cannot_run_in_probe() {
        assert!(validate(&vec![Insn::ret_k(1); MAX_FILTER_INSNS + 1]).is_err());
        assert!(validate(&[
            Insn {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k: 1
            },
            Insn::ret_k(1)
        ])
        .is_err());
        assert!(validate(&[Insn::ja(100), Insn::ret_k(1)]).is_err());
        assert_eq!(encode(None).unwrap()[..4], [0; 4]);
    }
}
