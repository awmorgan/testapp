package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/awmorgan/coresight"
)

const snapshotDir = "../coresight/cmd/trc_pkt_lister/testdata/trace_cov_a15"
const outputFileName = "./trace_cov_a15.ppl"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Open and prepare output file
	outFile, err := os.Create(outputFileName)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Print header to match the golden output exactly
	printHeader(outFile)

	// 2. Open all virtual memory mapping files
	mappingsList := []struct {
		address uint64
		size    uint64
		file    string
	}{
		{0x80000000, 632, "mem_Cortex-A15_0_0_VECTORS.bin"},
		{0x80000278, 6576, "mem_Cortex-A15_0_1_RO_CODE.bin"},
		{0x80001C28, 304, "mem_Cortex-A15_0_2_RO_DATA.bin"},
		{0x80001D58, 16, "mem_Cortex-A15_0_3_RW_DATA.bin"},
		{0x80001D68, 576, "mem_Cortex-A15_0_4_ZI_DATA.bin"},
		{0x80040000, 262144, "mem_Cortex-A15_0_5_ARM_LIB_HEAP.bin"},
		{0x80080000, 65536, "mem_Cortex-A15_0_6_ARM_LIB_STACK.bin"},
		{0x80090000, 65536, "mem_Cortex-A15_0_7_IRQ_STACK.bin"},
		{0x80100000, 16384, "mem_Cortex-A15_0_8_TTB.bin"},
	}

	mappings := make([]coresight.Mapping, 0, len(mappingsList))
	for _, m := range mappingsList {
		filePath := filepath.Join(snapshotDir, m.file)
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open memory image %s: %w", m.file, err)
		}
		defer f.Close()

		mappings = append(mappings, coresight.Mapping{
			BaseAddress: m.address,
			Size:        m.size,
			Space:       coresight.SpaceSecure,
			Source:      f,
		})
	}

	// 3. Initialize Coresight Engine
	cfg := coresight.EngineConfig{
		FramedInput: false, // Ingesting direct source trace stream (non-framed)
		Mappings:    mappings,
	}

	engine, err := coresight.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	defer engine.Close()

	// 4. Configure PTM decoder matching the device5.ini state:
	// ETMCR(id:0x0)=0x20000400
	// ETMCCR(id:0x1)=0x8D294004
	// ETMCCER(id:0x7A)=0x34C01AC2
	// ETMIDR(id:0x79)=0x411CF312
	// ETMTRACEIDR(id:0x80)=0x00000002
	ptmCfg := coresight.PTMConfig{
		IDR:         0x411CF312,
		Control:     0x20000400,
		CCER:        0x34C01AC2,
		ArchVersion: coresight.ArchV7,
		CoreProfile: coresight.ProfileCortexA,
		PacketObserver: func(index uint64, pkt fmt.Stringer, rawData []byte) {
			if len(rawData) == 0 {
				return
			}
			// Write formatted packet to file. ID is 0 for non-framed pipelines.
			outFile.WriteString(formatPacket(index, 0, pkt, rawData))
		},
		TraceEndObserver: func() {
			fmt.Fprintf(outFile, "ID:0\tEND OF TRACE DATA\r\n")
		},
	}

	// Register PTM for Trace ID 2
	err = engine.RegisterPTM(2, ptmCfg, func(elem coresight.Element) {
		outFile.WriteString(formatElement(elem))
	})
	if err != nil {
		return fmt.Errorf("failed to register PTM decoder: %w", err)
	}

	// 5. Read raw trace stream bytes (PTM_0_2.bin)
	traceBytes, err := os.ReadFile(filepath.Join(snapshotDir, "PTM_0_2.bin"))
	if err != nil {
		return fmt.Errorf("failed to read trace stream binary: %w", err)
	}

	// 6. Write trace bytes into the Engine
	n, err := engine.Write(traceBytes)
	if err != nil {
		return fmt.Errorf("engine write failure: %w", err)
	}

	// 7. Flush and close engine to emit EOT elements
	if err := engine.Close(); err != nil {
		return fmt.Errorf("engine close failure: %w", err)
	}

	// Log processed bytes
	fmt.Fprintf(outFile, "Trace Packet Lister : Trace buffer done, processed %d bytes.\r\n", n)

	return nil
}

func printHeader(w io.Writer) {
	fmt.Fprint(w, "Trace Packet Lister: CS Decode library testing\r\n")
	fmt.Fprint(w, "-----------------------------------------------\r\n")
	fmt.Fprint(w, "\r\n")
	fmt.Fprint(w, "\r\n")
	fmt.Fprint(w, "Test Command Line:-\r\n")
	fmt.Fprint(w, "C:\\Users\\arthu\\git\\OpenCSD\\decoder\\tests\\bin\\mingw64\\rel\\trc_pkt_lister.exe   -ss_dir  ./snapshots/trace_cov_a15  -decode  -no_time_print  -logfilename  ./results/trace_cov_a15.ppl  \r\n")
	fmt.Fprint(w, "\r\n")
	fmt.Fprint(w, "Trace Packet Lister : reading snapshot from path ./snapshots/trace_cov_a15\r\n")
	fmt.Fprint(w, "Using PTM_0_2 as trace source\r\n")
	fmt.Fprint(w, "Trace Packet Lister : Protocol printer PTM on Trace ID 0x0\r\n")
	fmt.Fprint(w, "Trace Packet Lister : Set trace element decode printer\r\n")
	fmt.Fprint(w, "Gen_Info : Mapped Memory Accessors\r\n")

	mappings := []struct {
		start, end uint64
		file       string
	}{
		{0x80000000, 0x80000277, "mem_Cortex-A15_0_0_VECTORS.bin"},
		{0x80000278, 0x80001c27, "mem_Cortex-A15_0_1_RO_CODE.bin"},
		{0x80001c28, 0x80001d57, "mem_Cortex-A15_0_2_RO_DATA.bin"},
		{0x80001d58, 0x80001d67, "mem_Cortex-A15_0_3_RW_DATA.bin"},
		{0x80001d68, 0x80001fa7, "mem_Cortex-A15_0_4_ZI_DATA.bin"},
		{0x80040000, 0x8007ffff, "mem_Cortex-A15_0_5_ARM_LIB_HEAP.bin"},
		{0x80080000, 0x8008ffff, "mem_Cortex-A15_0_6_ARM_LIB_STACK.bin"},
		{0x80090000, 0x8009ffff, "mem_Cortex-A15_0_7_IRQ_STACK.bin"},
		{0x80100000, 0x80103fff, "mem_Cortex-A15_0_8_TTB.bin"},
	}
	for _, m := range mappings {
		fmt.Fprintf(w, "Gen_Info : FileAcc; Range::0x%x:%x; Mem Space::Any S\r\n", m.start, m.end)
		fmt.Fprintf(w, "Filename=./snapshots/trace_cov_a15/%s\r\n", m.file)
	}
	fmt.Fprint(w, "Gen_Info : ========================\r\n")
}

func formatPacket(index uint64, id uint8, pkt fmt.Stringer, rawData []byte) string {
	var sb strings.Builder
	sb.WriteString("Idx:")
	sb.WriteString(strconv.FormatUint(index, 10))
	sb.WriteString("; ID:")
	sb.WriteString(strconv.FormatUint(uint64(id), 16))
	sb.WriteString("; [")

	const hex = "0123456789abcdef"
	for _, b := range rawData {
		sb.WriteString("0x")
		sb.WriteByte(hex[b>>4])
		sb.WriteByte(hex[b&0x0f])
		sb.WriteByte(' ')
	}
	sb.WriteString("];\t")
	sb.WriteString(pkt.String())
	sb.WriteString("\r\n")
	return sb.String()
}

func unsyncName(info coresight.UnsyncInfo) string {
	switch info {
	case coresight.UnsyncUnknown:
		return "undefined"
	case coresight.UnsyncInitDecoder:
		return "init-decoder"
	case coresight.UnsyncResetDecoder:
		return "reset-decoder"
	case coresight.UnsyncOverflow:
		return "overflow"
	case coresight.UnsyncDiscard:
		return "discard"
	case coresight.UnsyncBadPacket:
		return "bad-packet"
	case coresight.UnsyncBadImage:
		return "bad-program-image"
	case coresight.UnsyncEOT:
		return "end-of-trace"
	default:
		return "undefined"
	}
}

func traceOnName(reason coresight.TraceOnReason) string {
	switch reason {
	case coresight.TraceOnNormal:
		return "begin or filter"
	case coresight.TraceOnOverflow:
		return "overflow"
	case coresight.TraceOnExDebug:
		return "debug restart"
	default:
		return "begin or filter"
	}
}

func isaName(isa coresight.ISA) string {
	switch isa {
	case coresight.ISAArm:
		return "A32"
	case coresight.ISAThumb2:
		return "T32"
	case coresight.ISAAArch64:
		return "A64"
	case coresight.ISATee:
		return "TEE"
	case coresight.ISAJazelle:
		return "Jaz"
	case coresight.ISACustom:
		return "Cst"
	default:
		return "Unk"
	}
}

func securityLevelName(level coresight.SecLevel) string {
	switch level {
	case coresight.SecSecure:
		return "S; "
	case coresight.SecNonsecure:
		return "N; "
	case coresight.SecRoot:
		return "Root; "
	case coresight.SecRealm:
		return "Realm; "
	default:
		return ""
	}
}

func formatPEContext(e coresight.Element) string {
	var sb strings.Builder
	sb.WriteString("(ISA=")
	sb.WriteString(isaName(e.ISA))
	sb.WriteString(") ")
	if e.Context.ExceptionLevel > coresight.ELUnknown && e.Context.ELValid {
		sb.WriteString("EL")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.ExceptionLevel), 10))
	}
	sb.WriteString(securityLevelName(e.Context.SecurityLevel))
	if e.Context.Bits64 {
		sb.WriteString("64-bit; ")
	} else {
		sb.WriteString("32-bit; ")
	}
	if e.Context.VMIDValid {
		sb.WriteString("VMID=0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.VMID), 16))
		sb.WriteString("; ")
	}
	if e.Context.ContextIDValid {
		sb.WriteString("CTXTID=0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.ContextID), 16))
		sb.WriteString("; ")
	}
	return sb.String()
}

func instrTypeName(t coresight.InstrType) string {
	switch t {
	case coresight.InstrOther:
		return "--- "
	case coresight.InstrBr:
		return "BR  "
	case coresight.InstrBrIndirect:
		return "iBR "
	case coresight.InstrIsb:
		return "ISB "
	case coresight.InstrDsbDmb:
		return "DSB.DMB"
	case coresight.InstrWfiWfe:
		return "WFI.WFE"
	case coresight.InstrTstart:
		return "TSTART"
	default:
		return ""
	}
}

func instrSubtypeName(s coresight.InstrSubtype) string {
	switch s {
	case coresight.SInstrNone:
		return "--- "
	case coresight.SInstrBrLink:
		return "b+link "
	case coresight.SInstrV8Ret:
		return "A64:ret "
	case coresight.SInstrV8Eret:
		return "A64:eret "
	case coresight.SInstrV7ImpliedRet:
		return "V7:impl ret"
	default:
		return ""
	}
}

func formatInstrRange(e coresight.Element) string {
	var sb strings.Builder
	sb.WriteString("exec range=0x")
	sb.WriteString(strconv.FormatUint(uint64(e.StartAddr), 16))
	sb.WriteString(":[0x")
	sb.WriteString(strconv.FormatUint(uint64(e.EndAddr), 16))
	sb.WriteString("] num_i(")
	sb.WriteString(strconv.FormatUint(uint64(e.Payload.NumInstrRange), 10))
	sb.WriteString(") last_sz(")
	sb.WriteString(strconv.FormatUint(uint64(e.LastInstrSize), 10))
	sb.WriteString(") (ISA=")
	sb.WriteString(isaName(e.ISA))
	sb.WriteString(") ")
	if e.LastInstrExecuted {
		sb.WriteString("E ")
	} else {
		sb.WriteString("N ")
	}
	sb.WriteString(instrTypeName(e.LastInstrType))
	if e.LastInstrSubtype != coresight.SInstrNone {
		sb.WriteString(instrSubtypeName(e.LastInstrSubtype))
	}
	if e.LastInstrCond {
		sb.WriteString(" <cond>")
	}
	return sb.String()
}

func formatException(e coresight.Element) string {
	var sb strings.Builder
	if e.ExceptionRetAddr {
		sb.WriteString("pref ret addr:0x")
		sb.WriteString(strconv.FormatUint(uint64(e.EndAddr), 16))
		if e.ExceptionRetAddrBrTgt {
			sb.WriteString(" [addr also prev br tgt]")
		}
		sb.WriteString("; ")
	}
	sb.WriteString("excep num (0x")
	if e.Payload.ExceptionNum < 0x10 {
		sb.WriteByte('0')
	}
	sb.WriteString(strconv.FormatUint(uint64(e.Payload.ExceptionNum), 16))
	sb.WriteString(") ")
	return sb.String()
}

func formatElement(e coresight.Element) string {
	var sb strings.Builder
	sb.WriteString("Idx:")
	sb.WriteString(strconv.FormatUint(uint64(e.Index), 10))
	sb.WriteString("; ID:")
	sb.WriteString(strconv.FormatUint(uint64(e.TraceID), 16))
	sb.WriteString("; ")

	switch e.ElemType {
	case coresight.GenElemNoSync:
		sb.WriteString("OCSD_GEN_TRC_ELEM_NO_SYNC(")
		sb.WriteString(" [")
		sb.WriteString(unsyncName(e.Payload.UnsyncEOTInfo))
		sb.WriteString("])")
	case coresight.GenElemTraceOn:
		sb.WriteString("OCSD_GEN_TRC_ELEM_TRACE_ON(")
		sb.WriteString(" [")
		sb.WriteString(traceOnName(e.Payload.TraceOnReason))
		sb.WriteString("])")
	case coresight.GenElemPeContext:
		sb.WriteString("OCSD_GEN_TRC_ELEM_PE_CONTEXT(")
		sb.WriteString(formatPEContext(e))
		sb.WriteString(")")
	case coresight.GenElemInstrRange:
		sb.WriteString("OCSD_GEN_TRC_ELEM_INSTR_RANGE(")
		sb.WriteString(formatInstrRange(e))
		sb.WriteString(")")
	case coresight.GenElemException:
		sb.WriteString("OCSD_GEN_TRC_ELEM_EXCEPTION(")
		sb.WriteString(formatException(e))
		sb.WriteString(")")
	case coresight.GenElemEOTrace:
		sb.WriteString("OCSD_GEN_TRC_ELEM_EO_TRACE(")
		sb.WriteString(" [")
		sb.WriteString(unsyncName(e.Payload.UnsyncEOTInfo))
		sb.WriteString("])")
	default:
		sb.WriteString("OCSD_GEN_TRC_ELEM_UNKNOWN()")
	}
	sb.WriteString("\r\n")
	return sb.String()
}
