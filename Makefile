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
Client_C_Flags := $(Untrusted_C_Flags) -Wno-deprecated-declarations
Client_Link_Flags := -lpthread -lcrypto

Client_Cpp_Files := Client/client_main.cpp Client/identity.cpp \
    Client/secure_frame.cpp Client/csv_loader.cpp \
    Common/framing.cpp Common/tcp_util.cpp
Client_Cpp_Objects := $(Client_Cpp_Files:.cpp=.o)

# --- Enclave (trusted) ---
Enclave_C_Flags := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden \
    -fpie -ffunction-sections -fdata-sections \
    -IInclude -ICommon \
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

.PHONY: all clean enclave sgx_server sgx_client

all: sgx_server sgx_client enclave

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

enclave.so: Enclave/Enclave.o Enclave/Enclave_t.o
	g++ Enclave/Enclave.o Enclave/Enclave_t.o -o enclave.so -shared \
		$(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem \
		-enclave enclave.so -out enclave.signed.so \
		-config Enclave/Enclave.config.xml

# --- Untrusted compile rules ---
Enclave_u.o: Enclave_u.c
	gcc $(Server_C_Flags) -c $< -o $@

Server/%.o: Server/%.cpp Enclave_u.c
	g++ $(Server_C_Flags) -c $< -o $@

Client/%.o: Client/%.cpp
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

clean:
	rm -f Server/*.o Client/*.o Common/*.o Common/third_party/*.o \
		Enclave/*.o *.o *.so \
		sgx_server sgx_client \
		Enclave/Enclave_t.* Enclave_u.*
