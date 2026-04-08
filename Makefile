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

# --- App (untrusted) ---
App_C_Flags := $(SGX_COMMON_FLAGS) -fPIC -Wno-attributes \
    -I. -IApp -IInclude \
    -I$(SGX_SDK)/include -I/usr/include/openssl

App_Link_Flags := -L$(SGX_LIBRARY_PATH) \
    -l$(Urts_Library_Name) -lpthread -lssl -lcrypto

App_Cpp_Files := App/app_main.cpp App/csv_loader.cpp App/crypto.cpp \
    App/helpers.cpp App/attestation.cpp App/upload.cpp App/query.cpp
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

# --- Enclave (trusted) ---
Enclave_C_Flags := $(SGX_COMMON_FLAGS) -nostdinc -fvisibility=hidden \
    -fpie -ffunction-sections -fdata-sections \
    -IInclude \
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

.PHONY: all clean

all: app

# Gerar os ficheiros _t e _u a partir do EDL
Enclave/Enclave_t.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted Enclave/Enclave.edl \
		--search-path $(SGX_SDK)/include \
		--trusted-dir Enclave

Enclave_u.c: Enclave/Enclave.edl
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted Enclave/Enclave.edl \
		--search-path $(SGX_SDK)/include

# Compilar o enclave
Enclave/Enclave_t.o: Enclave/Enclave_t.c
	gcc $(Enclave_C_Flags) -c Enclave/Enclave_t.c -o Enclave/Enclave_t.o

Enclave/Enclave.o: Enclave/Enclave.cpp Enclave/Enclave_t.c
	g++ $(Enclave_C_Flags) -IEnclave -c Enclave/Enclave.cpp -o Enclave/Enclave.o

enclave.so: Enclave/Enclave.o Enclave/Enclave_t.o
	g++ Enclave/Enclave.o Enclave/Enclave_t.o -o enclave.so -shared \
		$(Enclave_Link_Flags)

enclave.signed.so: enclave.so
	$(SGX_SDK)/bin/x64/sgx_sign sign -key Enclave/Enclave_private.pem \
		-enclave enclave.so -out enclave.signed.so \
		-config Enclave/Enclave.config.xml

# Compilar a app
Enclave_u.o: Enclave_u.c
	gcc $(App_C_Flags) -c Enclave_u.c -o Enclave_u.o

App/%.o: App/%.cpp
	g++ $(App_C_Flags) -c $< -o $@

app: Enclave_u.o $(App_Cpp_Objects) enclave.signed.so
	g++ $(App_Cpp_Objects) Enclave_u.o -o app $(App_Link_Flags)

clean:
	rm -f App/*.o Enclave/*.o *.o *.so app Enclave/Enclave_t.* Enclave_u.*
