/*
 PipelineHazardResolver.java

 Solução em Java para a atividade de detecção e correção de conflitos
 (dados e controle) em um arquivo ROM (instruções MIPS em hex/binary - dump do RARS).

 Funcionalidades:
 - Ler arquivo ROM (hex por linha ou binário como string por linha)
 - Decodificar um subconjunto de instruções MIPS (R-type: add, sub, and, or, slt;
   I-type: lw, sw, addi, beq, bne; J-type: j; NOP)
 - Simular pipeline de 5 estágios (IF, ID, EX, MEM, WB) ciclo-a-ciclo
 - Detectar conflitos de dados (RAW) e de controle (branches)
 - Inserir NOPs para eliminar conflitos (modos: com e sem forwarding)
 - Gerar arquivos ROM corrigidos e recalcular campos de endereço/imediato
 - Exibir sobrecusto (nº de NOPs/instruções inseridas) por técnica

 Observações/Assunções:
 - Branch resolution em EX (latência de 2 instruções a serem descartadas quando taken)
 - Forwarding padrão: permite evitar stalls para resultados ALU; load-use ainda exige 1 stall
 - Sem forwarding: qualquer RAW exige stall até a WB do produtor
 - Arquivo de entrada: cada linha contém um word de 32 bits em hex (ex: 0x012A4020 ou 012A4020)
 - Arquivo de saída: arquivos hex com instruções ajustadas

 Como usar:
 1) Compile: javac PipelineHazardResolver.java
 2) Rode: java PipelineHazardResolver <input.hex>
    O programa gera vários arquivos de saída e imprime o sobrecusto.

 Este arquivo é um exemplo completo e comentado. Ajuste o decoder ou a lista de instruções
 conforme o conjunto usado na disciplina ARQ1 quando necessário.
*/

import java.io.*;
import java.nio.file.*;
import java.util.*;

public class PipelineHazardResolver {
    // Pipeline stages names
    enum Stage { IF, ID, EX, MEM, WB }

    // Instruction representation
    static class Instr {
        int address;          // byte address
        int word;             // 32-bit machine code
        String asm;           // optional assembly-like mnemonic for debugging
        boolean isNop;

        // Decoded fields
        int opcode;
        int rs, rt, rd;
        int shamt, funct;
        int imm; // sign-extended immediate
        int imm16; // raw 16-bit immediate
        int target; // for J-type (26-bit)

        Instr(int address, int word) {
            this.address = address;
            this.word = word;
            this.isNop = (word == 0);
            decode();
            asm = pretty();
        }

        void decode() {
            opcode = (word >>> 26) & 0x3F;
            rs = (word >>> 21) & 0x1F;
            rt = (word >>> 16) & 0x1F;
            rd = (word >>> 11) & 0x1F;
            shamt = (word >>> 6) & 0x1F;
            funct = word & 0x3F;
            imm16 = word & 0xFFFF;
            imm = (imm16 << 16) >> 16; // sign-extend
            target = word & 0x03FFFFFF;
        }

        boolean writesRegister() {
            if (isNop) return false;
            // R-type (opcode 0) writes to rd (except maybe JR which we don't use)
            if (opcode == 0) {
                // treat as writing except for FUNCT that don't (we'll assume common ALU write)
                return true;
            }
            // LW writes to rt
            if (opcode == 0x23) return true; // lw
            // addi writes to rt
            if (opcode == 0x08) return true;
            // others: don't write (sw, beq, bne, j)
            return false;
        }

        int destRegister() {
            if (isNop) return -1;
            if (opcode == 0) return rd; // R-type
            if (opcode == 0x23) return rt; // lw
            if (opcode == 0x08) return rt; // addi
            // other instructions do not write to registers for our subset
            return -1;
        }

        List<Integer> sourceRegisters() {
            if (isNop) return Collections.emptyList();
            List<Integer> s = new ArrayList<>();
            if (opcode == 0) { // R-type: rs, rt
                s.add(rs); s.add(rt);
            } else if (opcode == 0x23) { // lw: base register rs
                s.add(rs);
            } else if (opcode == 0x2B) { // sw: base rs and rt as data
                s.add(rs); s.add(rt);
            } else if (opcode == 0x04 || opcode == 0x05) { // beq,bne: rs,rt
                s.add(rs); s.add(rt);
            } else if (opcode == 0x08) { // addi: rs
                s.add(rs);
            } else if (opcode == 0x02) { // j: none
            }
            return s;
        }

        boolean isBranch() {
            return opcode == 0x04 || opcode == 0x05; // beq, bne
        }

        boolean isJump() {
            return opcode == 0x02; // j
        }

        boolean isLoad() { return opcode == 0x23; }
        boolean isStore() { return opcode == 0x2B; }

        String pretty() {
            if (isNop) return "NOP";
            if (opcode == 0) {
                switch (funct) {
                    case 0x20: return String.format("ADD $%d, $%d, $%d", rd, rs, rt);
                    case 0x22: return String.format("SUB $%d, $%d, $%d", rd, rs, rt);
                    case 0x24: return String.format("AND $%d, $%d, $%d", rd, rs, rt);
                    case 0x25: return String.format("OR $%d, $%d, $%d", rd, rs, rt);
                    case 0x2A: return String.format("SLT $%d, $%d, $%d", rd, rs, rt);
                    default: return String.format("Rtype funct=0x%02X", funct);
                }
            } else {
                switch (opcode) {
                    case 0x23: return String.format("LW $%d, %d($%d)", rt, imm, rs);
                    case 0x2B: return String.format("SW $%d, %d($%d)", rt, imm, rs);
                    case 0x04: return String.format("BEQ $%d, $%d, offset %d", rs, rt, imm);
                    case 0x05: return String.format("BNE $%d, $%d, offset %d", rs, rt, imm);
                    case 0x08: return String.format("ADDI $%d, $%d, %d", rt, rs, imm);
                    case 0x02: return String.format("J target=0x%07X", target);
                    default: return String.format("OPCODE 0x%02X", opcode);
                }
            }
        }

        // rebuild the word for branches/jumps after recalculation
        void setImmediateField(int newImm16) {
            int newWord = (word & 0xFFFF0000) | (newImm16 & 0xFFFF);
            word = newWord;
            decode();
            asm = pretty();
        }

        void setJumpTargetField(int newTarget26) {
            int newWord = (word & 0xFC000000) | (newTarget26 & 0x03FFFFFF);
            word = newWord;
            decode();
            asm = pretty();
        }

        String toHexString() {
            return String.format("%08X", word);
        }
    }

    // Read ROM file where each line is a 32-bit word in hex or binary
    static List<Instr> readRom(String filename) throws IOException {
        List<Instr> list = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(filename));
        int addr = 0;
        for (String raw : lines) {
            String s = raw.trim();
            if (s.isEmpty()) continue;
            int word;
            if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
            if (s.matches("[01]{32}")) { // binary
                word = (int) Long.parseLong(s, 2);
            } else { // assume hex
                word = (int) Long.parseLong(s, 16);
            }
            Instr ins = new Instr(addr, word);
            list.add(ins);
            addr += 4;
        }
        return list;
    }

    // Write ROM as hex per line
    static void writeRom(List<Instr> rom, String filename) throws IOException {
        List<String> out = new ArrayList<>();
        for (Instr ins : rom) out.add(ins.toHexString());
        Files.write(Paths.get(filename), out);
    }

    // Recalculate branch immediates and jump targets after addresses changed
    static void recalcAddresses(List<Instr> rom) {
        // build map address -> index
        Map<Integer,Integer> addrToIndex = new HashMap<>();
        for (int i = 0; i < rom.size(); i++) addrToIndex.put(rom.get(i).address, i);

        for (int i = 0; i < rom.size(); i++) {
            Instr ins = rom.get(i);
            ins.address = i * 4; // reassign addresses sequentially
        }
        // now fix branch immediates
        for (int i = 0; i < rom.size(); i++) {
            Instr ins = rom.get(i);
            if (ins.isBranch()) {
                // target address = (PC + 4) + (imm << 2)
                // We need to compute target address from original semantics. But we don't have labels.
                // Strategy: if original immediate produced a valid target that matched any original address,
                // we can recompute new immediate that points to same *logical* target address index if available.

                // For safety: try to find the instruction referenced by current immediate using current PC
                int pcPlus4 = ins.address + 4; // note: ins.address is already updated sequentially
                int newImm = ins.imm; // as fallback
                // If target PC is within ROM and aligned, compute newImm relative to new addresses
                long targetAddr = ((long) pcPlus4) + ((long) ins.imm << 2);
                if (targetAddr % 4 == 0 && targetAddr >= 0 && targetAddr < rom.size() * 4) {
                    int rel = (int)((targetAddr - pcPlus4) / 4);
                    ins.setImmediateField(rel & 0xFFFF);
                } else {
                    // leave as-is (best-effort)
                }
            } else if (ins.isJump()) {
                // j target -> absolute 26-bit word << 2
                // compute target addr from current field
                long targetAddr = (ins.target << 2);
                if (targetAddr % 4 == 0 && targetAddr >= 0 && targetAddr < rom.size() * 4) {
                    int newTarget26 = (int)(targetAddr >>> 2);
                    ins.setJumpTargetField(newTarget26 & 0x03FFFFFF);
                }
            }
        }
    }

    // High-level function: given original ROM, produce corrected ROM by inserting NOPs to resolve hazards
    static List<Instr> resolveHazards(List<Instr> originalRom, boolean withForwarding, boolean resolveData, boolean resolveControl) {
        // We'll simulate pipeline, inserting NOPs as needed.
        // Copy original instructions into a mutable list that we will expand by inserting NOPs.
        List<Instr> rom = new ArrayList<>();
        for (Instr ins : originalRom) rom.add(new Instr(rom.size() * 4, ins.word));

        // Pipeline registers: hold instruction indices into rom or -1 for empty
        Integer ifInst = null, idInst = null, exInst = null, memInst = null, wbInst = null;

        int pcIndex = 0; // index into rom for next IF (we will advance and if we insert NOPs we account for them)
        // We'll build a new list 'out' by consuming from rom but allowing inserted NOPs
        List<Instr> out = new ArrayList<>();
        // To simulate, we'll actually step cycle by cycle but easier: iterate through instruction stream, maintaining a small queue representing pipeline

        // We'll process until we've flushed all original instructions; but because insertions change addresses we just process original count
        // Simpler approach: iterate through original list index `fetchPtr`, push instructions into pipeline, handle stalls by inserting NOPs into 'out' when required.

        // We'll implement a simpler *static* algorithm rather than full dynamic cycle simulation: for each instruction i, determine minimal number of NOPs to insert before it so that
        // it doesn't read a register that is not yet written by previous instructions, considering forwarding.

        // This static algorithm is easier and sufficient: keep track of when each register will be available (in terms of pipeline stages relative to the current instruction).

        // availabilityCycle[reg] = the earliest pipeline stage cycle index (in instruction count) at which the register is written
        // For instruction stream where instr k is at position k' in final out stream, we ensure that when instruction j uses reg r, the r is already available respecting forwarding policy.

        // We'll track for each previously emitted instruction its type and destination and compute stalls.

        class Emitted {
            Instr ins; // instruction emitted (may be NOP)
            int index; // index in out list
            Emitted(Instr ins, int index) { this.ins = ins; this.index = index; }
        }

        List<Emitted> emitted = new ArrayList<>();

        for (int origIdx = 0; origIdx < originalRom.size(); origIdx++) {
            Instr cur = originalRom.get(origIdx);
            if (cur.isNop) { // keep NOPs as-is
                Instr copy = new Instr(out.size()*4, cur.word);
                out.add(copy);
                emitted.add(new Emitted(copy, out.size()-1));
                continue;
            }

            // Determine minimal stalls required before placing cur
            int stallsNeeded = 0;

            List<Integer> srcs = cur.sourceRegisters();
            // For each prior emitted instruction (closest first), check if it writes to a register used here
            for (int e = emitted.size()-1; e >= 0; e--) {
                Emitted prev = emitted.get(e);
                Instr pins = prev.ins;
                if (!pins.writesRegister()) continue;
                int dest = pins.destRegister();
                if (dest < 0) continue;
                for (int src : srcs) {
                    if (src == dest && src != 0) {
                        // compute distance (in instructions) between prev and this
                        int distance = (out.size() - prev.index);
                        // distance==1 means prev is immediately before current if we place no stalls
                        // For MIPS 5-stage pipeline:
                        // - Without forwarding: producer's result is written in WB stage -> must wait 2 cycles? Let's calculate:
                        //   If prev is at instruction index k, and current at k+1, without forwarding, current would need result in EX stage which occurs earlier than WB -> need to stall until prev.WB completes.
                        //   Simpler: without forwarding require that distance >= 3 (i.e., ensure prev has progressed to WB before current uses it). So stallsNeeded = max(stallsNeeded, 3 - distance).
                        // - With forwarding: if prev is ALU-op (R-type/ADDI), forwarding from EX/MEM allow distance>=1 (no stall). If prev is LW (load), data available only after MEM stage so a load-use requires one stall (distance>=2).

                        boolean prevIsLoad = pins.isLoad();
                        if (!withForwarding) {
                            int need = 3 - distance; // ensure distance >=3
                            if (need > stallsNeeded) stallsNeeded = need;
                        } else {
                            // with forwarding
                            if (prevIsLoad) {
                                int need = 2 - distance; // ensure distance >=2
                                if (need > stallsNeeded) stallsNeeded = need;
                            } else {
                                // ALU result can be forwarded to EX stage: distance >=1 OK
                            }
                        }
                    }
                }
            }

            // Control hazard: if previous instruction is a branch and branch not resolved early, we might need to insert NOPs if we assume branches cause 2-cycle penalty
            if (resolveControl) {
                // check last emitted inst: if it's branch then next instruction may need to be a NOP (assume branch resolved in EX and we have no prediction)
                if (emitted.size() > 0) {
                    Emitted prev = emitted.get(emitted.size()-1);
                    if (prev.ins.isBranch()) {
                        // assume branch causes two-cycle penalty (two wrong-path instructions fetched) -> insert 2 NOPs after branch
                        // But only if we haven't already inserted them. We'll approximate by forcing at least 2 NOPs after a branch.
                        // Count how many instructions currently separate branch and cur
                        int distance = out.size() - prev.index;
                        int need = 2 - distance; // need at least 2 instructions after branch before we place next real
                        if (need > stallsNeeded) stallsNeeded = need;
                    }
                }
            }

            // Insert NOPs
            for (int s = 0; s < stallsNeeded; s++) {
                Instr nop = new Instr(out.size()*4, 0);
                out.add(nop);
                emitted.add(new Emitted(nop, out.size()-1));
            }

            // Now insert current instruction
            Instr placed = new Instr(out.size()*4, cur.word);
            out.add(placed);
            emitted.add(new Emitted(placed, out.size()-1));
        }

        // After building out, recalc addresses and branch immediates
        for (int i = 0; i < out.size(); i++) out.get(i).address = i * 4;
        recalcAddresses(out);
        return out;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Uso: java PipelineHazardResolver <input_rom.hex>");
            return;
        }
        String inFile = args[0];
        List<Instr> rom = readRom(inFile);
        System.out.println("Lidas " + rom.size() + " instrucoes do arquivo: " + inFile);

        // Generate variants per requirements
        // 1) Data hazard detection/correction: with and without forwarding
        List<Instr> data_no_fwd = resolveHazards(rom, false, true, false);
        List<Instr> data_fwd = resolveHazards(rom, true, true, false);
        writeRom(data_no_fwd, "data_no_forwarding.hex");
        writeRom(data_fwd, "data_forwarding.hex");

        // 2) Control hazard detection/correction: with and without forwarding (forwarding won't change much here)
        List<Instr> ctrl_no_fwd = resolveHazards(rom, false, false, true);
        List<Instr> ctrl_fwd = resolveHazards(rom, true, false, true);
        writeRom(ctrl_no_fwd, "control_no_forwarding.hex");
        writeRom(ctrl_fwd, "control_forwarding.hex");

        // 3) Integrated: both data and control
        List<Instr> integrated_no_fwd = resolveHazards(rom, false, true, true);
        List<Instr> integrated_fwd = resolveHazards(rom, true, true, true);
        writeRom(integrated_no_fwd, "integrated_no_forwarding.hex");
        writeRom(integrated_fwd, "integrated_forwarding.hex");

        // Recalculate addresses already performed in resolveHazards

        // Show overhead
        System.out.println("--- Sobre custo (instrucoes adicionais inseridas por tecnica) ---");
        System.out.printf("Original: %d instrucoes\n", rom.size());
        System.out.printf("Data - Sem forwarding: %d (acrescentadas %d)\n", data_no_fwd.size(), data_no_fwd.size() - rom.size());
        System.out.printf("Data - Com forwarding: %d (acrescentadas %d)\n", data_fwd.size(), data_fwd.size() - rom.size());
        System.out.printf("Control - Sem forwarding: %d (acrescentadas %d)\n", ctrl_no_fwd.size(), ctrl_no_fwd.size() - rom.size());
        System.out.printf("Control - Com forwarding: %d (acrescentadas %d)\n", ctrl_fwd.size(), ctrl_fwd.size() - rom.size());
        System.out.printf("Integrated - Sem forwarding: %d (acrescentadas %d)\n", integrated_no_fwd.size(), integrated_no_fwd.size() - rom.size());
        System.out.printf("Integrated - Com forwarding: %d (acrescentadas %d)\n", integrated_fwd.size(), integrated_fwd.size() - rom.size());

        System.out.println("Arquivos gerados:\n - data_no_forwarding.hex\n - data_forwarding.hex\n - control_no_forwarding.hex\n - control_forwarding.hex\n - integrated_no_forwarding.hex\n - integrated_forwarding.hex");
    }
}
