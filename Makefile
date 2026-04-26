SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM

SGX_COMMON_FLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64

ifeq ($(SGX_MODE), SIM)
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
    Urts_Library_Name := sgx_urts_sim
else
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
    Urts_Library_Name := sgx_urts
endif

# --- Common flags for untrusted side (Server, Client, Common) ---
Untrusted_C_Flags := $(SGX_COMMON_FLAGS) -fPIC -Wall -Wno-attributes \
    -IInclude -ICommon \
    -I$(SGX_SDK)/include

# --- Server (links the enclave) ---
Server_C_Flags := $(Untrusted_C_Flags) -I.
Server_Link_Flags := -L$(SGX_LIBRARY_PATH) \
    -l$(Urts_Library_Name) -lpthread -lm

Server_Cpp_Files := Server/server_main.cpp Server/parties_loader.cpp \
    Common/framing.cpp Common/tcp_util.cpp
Server_Cpp_Objects := $(Server_Cpp_Files:.cpp=.o)

Server_C_Files := Common/third_party/cJSON.c
Server_C_Objects := $(Server_C_Files:.c=.o)

# --- Client (no enclave, OpenSSL for ECDSA/ECDH/HKDF) ---
# OpenSSL 3 deprecated EC_KEY/EC_POINT/SHA256_* in favour of EVP-only
# APIs; suppress those warnings — migration is tracked separately.
# SAHC_HW switches the default attestation policy: SIM tolerates the
# missing DCAP signature chain, HW requires it (overridable at runtime
# via SAHC_REQUIRE_DCAP=0|1).
ifeq ($(SGX_MODE), HW)
    Client_HW_Flag := -DSAHC_HW=1
else
    Client_HW_Flag := -DSAHC_HW=0
endif
Client_C_Flags := $(Untrusted_C_Flags) -Wno-deprecated-declarations $(Client_HW_Flag)
Client_Link_Flags := -lpthread -lcrypto

Client_Cpp_Files := Client/client_main.cpp Client/session.cpp \
    Client/quote_verify.cpp Client/identity.cpp Client/secure_frame.cpp \
    Client/csv_loader.cpp Common/framing.cpp Common/tcp_util.cpp
Client_Cpp_Objects := $(Client_Cpp_Files:.cpp=.o)

# --- Enclave (trusted) ---
Enclave_C_Flags := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden \
    -fpie -ffunction-sections -fdata-sections \
    -DSAHC_BACKEND_SGX \
    -IInclude -ICommon -IEnclaveLogic \
    -I$(SGX_SDK)/include \
    -I$(SGX_SDK)/include/tlibc \
    -I$(SGX_SDK)/include/libcxx

Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs \
    -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
    -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto \
    -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections

.PHONY: all clean enclave sgx_server sgx_client sgx_bench mrenclave gramine_server gramine_manifest

all: sgx_server sgx_client enclave Include/expected_mrenclave.h

sgx_bench: sgx_bench_bin

# Auto-pin: extract MRENCLAVE from the freshly-signed enclave so the
# client header matches what the enclave will report at handshake.
# Reads the SIGSTRUCT directly via `sgx_sign dump` — no enclave runtime
# needed, so the client can be cross-built on a machine without SGX.
Include/expected_mrenclave.h: enclave.signed.so scripts/extract_mrenclave.sh
	./scripts/extract_mrenclave.sh

mrenclave: Include/expected_mrenclave.h

enclave: enclave.signed.so

sgx_server: sgx_server_bin

sgx_client: sgx_client_bin

# --- EDL-generated wrappers ---
Enclave/Enclave_t.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted Enclave/Enclave.edl \
		--search-path $(SGX_SDK)/include \
		--trusted-dir Enclave

Enclave_u.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted Enclave/Enclave.edl \
		--search-path $(SGX_SDK)/include

# --- Enclave build ---
Enclave/Enclave_t.o: Enclave/Enclave_t.c
	gcc $(Enclave_C_Flags) -c $< -o $@

Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.c
	g++ $(Enclave_C_Flags) -IEnclave -c Enclave/Enclave.cpp -o $@

# EnclaveLogic — SDK-neutral logic + SGX backend implementations.
Enclave_Logic_Cpp := EnclaveLogic/enclave_logic.cpp \
    EnclaveLogic/crypto_backend_sgx.cpp \
    EnclaveLogic/identity_backend_sgx.cpp \
    EnclaveLogic/seal_backend_sgx.cpp \
    EnclaveLogic/query_engine_artisanal.cpp
Enclave_Logic_Obj := $(Enclave_Logic_Cpp:.cpp=.o)

EnclaveLogic/%.o: EnclaveLogic/%.cpp
	g++ $(Enclave_C_Flags) -c $< -o $@

enclave.so: Enclave/Enclave.o Enclave/Enclave_t.o $(Enclave_Logic_Obj)
	g++ Enclave/Enclave.o Enclave/Enclave_t.o $(Enclave_Logic_Obj) \
		-o enclave.so -shared $(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem \
		-enclave enclave.so -out enclave.signed.so \
		-config Enclave/Enclave.config.xml

# --- Untrusted compile rules ---
Enclave_u.o: Enclave_u.c
	gcc $(Server_C_Flags) -c $< -o $@

Server/%.o: Server/%.cpp Enclave_u.c
	g++ $(Server_C_Flags) -c $< -o $@

Client/%.o: Client/%.cpp Include/expected_mrenclave.h
	g++ $(Client_C_Flags) -c $< -o $@

Common/%.o: Common/%.cpp
	g++ $(Untrusted_C_Flags) -c $< -o $@

Common/third_party/%.o: Common/third_party/%.c
	gcc $(Untrusted_C_Flags) -c $< -o $@

# --- Final binaries ---
sgx_server_bin: $(Server_Cpp_Objects) $(Server_C_Objects) Enclave_u.o enclave.signed.so
	g++ $(Server_Cpp_Objects) $(Server_C_Objects) Enclave_u.o -o sgx_server $(Server_Link_Flags)

sgx_client_bin: $(Client_Cpp_Objects)
	g++ $(Client_Cpp_Objects) -o sgx_client $(Client_Link_Flags)

# --- Bench harness (reuses Client/session.* + crypto deps) ---
Bench_Cpp_Files := Bench/bench.cpp Client/session.cpp Client/quote_verify.cpp \
    Client/identity.cpp Client/secure_frame.cpp Client/csv_loader.cpp \
    Common/framing.cpp Common/tcp_util.cpp
Bench_Cpp_Objects := $(Bench_Cpp_Files:.cpp=.o)

Bench/%.o: Bench/%.cpp Include/expected_mrenclave.h
	g++ $(Client_C_Flags) -IClient -c $< -o $@

sgx_bench_bin: $(Bench_Cpp_Objects)
	g++ $(Bench_Cpp_Objects) -o sgx_bench $(Client_Link_Flags)

# --- Gramine variant: same logic, OpenSSL + Gramine attestation backends.
# Built standalone, no SGX SDK runtime; meant to run under
# gramine-direct (smoke) or gramine-sgx (production).
Gramine_C_Flags := $(SGX_COMMON_FLAGS) -fPIC -Wall -Wno-attributes \
    -IInclude -ICommon -IServer -IEnclaveLogic
Gramine_Link_Flags := -lpthread -lcrypto

Gramine_Cpp_Files := Gramine/server_main.cpp \
    EnclaveLogic/enclave_logic.cpp \
    EnclaveLogic/crypto_backend_openssl.cpp \
    EnclaveLogic/identity_backend_gramine.cpp \
    EnclaveLogic/seal_backend_gramine.cpp \
    EnclaveLogic/query_engine_duckdb.cpp \
    Server/parties_loader.cpp \
    Common/framing.cpp Common/tcp_util.cpp
Gramine_Cpp_Objects := $(Gramine_Cpp_Files:.cpp=.gramine.o)
Gramine_C_Objects   := Common/third_party/cJSON.gramine.o

# DuckDB ships a precompiled libduckdb.so in their release bundle —
# we use that instead of compiling the 20 MB amalgamation. The .so
# lives next to the headers under Common/third_party/duckdb/. For
# gramine-sgx HW the .so must be added to sgx.trusted_files in the
# manifest so its hash is measured at load time.
Duckdb_Dir       := Common/third_party/duckdb
# $ORIGIN-relative rpath: resolves to the binary's directory at load
# time. Works both on the host (project root) and inside Gramine
# (project mounted as /sahc), so we don't need to pin an absolute path.
Duckdb_Link      := -L$(Duckdb_Dir) -lduckdb \
                    -Wl,-rpath,'$$ORIGIN/$(Duckdb_Dir)'

# query_engine_duckdb needs the DuckDB header on its include path.
EnclaveLogic/query_engine_duckdb.gramine.o: EnclaveLogic/query_engine_duckdb.cpp \
                                            EnclaveLogic/query_engine.h \
                                            Common/third_party/duckdb/duckdb.hpp
	g++ $(Gramine_C_Flags) -std=c++17 -D_GLIBCXX_USE_CXX11_ABI=0 \
	    -I$(Duckdb_Dir) -c $< -o $@

%.gramine.o: %.cpp
	g++ $(Gramine_C_Flags) -c $< -o $@

%.gramine.o: %.c
	gcc $(Gramine_C_Flags) -c $< -o $@

# Trigger the fetch script if libduckdb.so is missing — fresh checkouts
# don't have the .so (gitignored, ~57 MB).
$(Duckdb_Dir)/libduckdb.so:
	./scripts/fetch_duckdb.sh

gramine_server: $(Gramine_Cpp_Objects) $(Gramine_C_Objects) \
                $(Duckdb_Dir)/libduckdb.so
	g++ $(Gramine_Cpp_Objects) $(Gramine_C_Objects) \
	    -o gramine_server $(Gramine_Link_Flags) $(Duckdb_Link)

# Render the manifest with substitutions; sign for gramine-sgx so HW runs
# work too (gramine-direct only needs the unsigned .manifest). Run from
# the project root so file:foo URIs resolve against the actual binary
# and json paths.
gramine_manifest: gramine_server Gramine/server.manifest.template
	gramine-manifest \
		-Dlog_level=error \
		-Darch_libdir=/lib/x86_64-linux-gnu \
		-Dproject_root=$(CURDIR) \
		Gramine/server.manifest.template gramine_server.manifest
	gramine-sgx-sign \
		--manifest gramine_server.manifest \
		--output   gramine_server.manifest.sgx \
		|| echo "(gramine-sgx-sign skipped — fine if no signing key)"

clean:
	rm -f Server/*.o Client/*.o Bench/*.o Common/*.o Common/third_party/*.o \
		Enclave/*.o EnclaveLogic/*.o Gramine/*.o *.o *.so \
		Server/*.gramine.o EnclaveLogic/*.gramine.o Gramine/*.gramine.o \
		Common/*.gramine.o Common/third_party/*.gramine.o \
		sgx_server sgx_client sgx_bench gramine_server \
		gramine_server.manifest gramine_server.manifest.sgx \
		gramine_server.sig \
		Enclave/Enclave_t.* Enclave_u.* \
		Include/expected_mrenclave.h
