#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#if defined(__ARM_ARCH)
#include "xmrig/crypto/CryptoNight_arm.h"
#else
#include "xmrig/extra.h"
#include "xmrig/crypto/CryptoNight_x86.h"
#endif

#include "xmrig/Mem.h"

#include "xmrig/crypto/randomx/randomx.h"

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
#define SOFT_AES false
#else
#warning Using software AES
#define SOFT_AES true
#endif

static struct cryptonight_ctx* ctx = nullptr;
static randomx_cache* rx_cache[xmrig::VARIANT_MAX] = {nullptr};
static randomx_vm* rx_vm[xmrig::VARIANT_MAX] = {nullptr};
static xmrig::Variant rx_variant = xmrig::VARIANT_MAX;
static uint8_t rx_seed_hash[xmrig::VARIANT_MAX][32] = {};

void init_ctx() {
    if (ctx) return;
    Mem::create(&ctx, xmrig::CRYPTONIGHT_HEAVY, 1);
}

void init_rx(const uint8_t* seed_hash_data, xmrig::Variant variant) {
    bool update_cache = false;
    if (!rx_cache[variant]) {
        rx_cache[variant] = randomx_alloc_cache(static_cast<randomx_flags>(RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES));
        if (!rx_cache[variant]) {
            rx_cache[variant] = randomx_alloc_cache(RANDOMX_FLAG_JIT);
        }
        update_cache = true;
    }
    else if (memcmp(rx_seed_hash[variant], seed_hash_data, sizeof(rx_seed_hash[0])) != 0) {
        update_cache = true;
    }

    //if (variant != rx_variant) {
        switch (variant) {
            case xmrig::VARIANT_0:
                randomx_apply_config(RandomX_MoneroConfig);
                break;
            case xmrig::VARIANT_RX_WOW:
                randomx_apply_config(RandomX_WowneroConfig);
                break;
            case xmrig::VARIANT_RX_LOKI:
                randomx_apply_config(RandomX_LokiConfig);
                break;
            default:
                throw std::domain_error("Unknown RandomX variant");
        }
        //rx_variant = variant;
        //update_cache = true;
    //}

    if (update_cache) {
        memcpy(rx_seed_hash[variant], seed_hash_data, sizeof(rx_seed_hash[0]));
        randomx_init_cache(rx_cache[variant], rx_seed_hash[variant], sizeof(rx_seed_hash[0]));
        if (rx_vm[variant]) {
            randomx_vm_set_cache(rx_vm[variant], rx_cache[variant]);
        }
    }

    if (!rx_vm[variant]) {
        int flags = RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_JIT;
#if !SOFT_AES
        flags |= RANDOMX_FLAG_HARD_AES;
#endif

        rx_vm[variant] = randomx_create_vm(static_cast<randomx_flags>(flags), rx_cache[variant], nullptr);
        if (!rx_vm[variant]) {
            rx_vm[variant] = randomx_create_vm(static_cast<randomx_flags>(flags - RANDOMX_FLAG_LARGE_PAGES), rx_cache[variant], nullptr);
        }
    }
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(randomx) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    Local<Object> seed_hash = info[1]->ToObject();
    if (!Buffer::HasInstance(seed_hash)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
    if (Buffer::Length(seed_hash) != sizeof(rx_seed_hash[0])) return THROW_ERROR_EXCEPTION("Argument 2 size should be 32 bytes.");

    int variant = 0;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        variant = Nan::To<int>(info[2]).FromMaybe(0);
    }

    try {
        init_rx(reinterpret_cast<const uint8_t*>(Buffer::Data(seed_hash)), static_cast<xmrig::Variant>(variant));
    } catch (const std::domain_error &e) {
        return THROW_ERROR_EXCEPTION(e.what());
    }

    char output[32];
    randomx_calculate_hash(rx_vm[variant], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output));

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;
    bool height_set = false;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
        height_set = true;
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;

       case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;

       case 9:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_HALF>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;
       case 11: cryptonight_single_hash_gpu<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_GPU>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 12:
                if (!height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");

#if !SOFT_AES && (defined(CPU_INTEL) || defined(CPU_AMD))
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_WOW, xmrig::ASM_AUTO>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_WOW>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;
       case 13:
                if (!height_set) return THROW_ERROR_EXCEPTION("Cryptonight4 requires block template height as Argument 3");

#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_INTEL> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_RYZEN> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_4>         (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
                break;

       case 14:
                cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RWZ>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;

       case 15:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_ZLS>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;

       case 16:
#if !SOFT_AES && defined(CPU_INTEL)
                #warning Using IvyBridge assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD)
                #warning Using Ryzen assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                #warning Using Bulldozer assembler implementation
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_DOUBLE>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
#endif
		break;

       default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
                break;
       default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_pico) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    init_ctx();
    switch (variant) {
       case 0:
#if !SOFT_AES && defined(CPU_INTEL)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#endif
                break;
       default:
#if !SOFT_AES && defined(CPU_INTEL)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#else
                cryptonight_single_hash    <xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>             (reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);
#endif
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CCryptonightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];
        MemInfo m_info;

    public:

        CCryptonightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_info = Mem::create(&m_ctx, xmrig::CRYPTONIGHT, 1);
        }

        ~CCryptonightAsync() {
            Mem::release(&m_ctx, 1, m_info);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_0>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 3:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XTL>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 4:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_MSR>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 6:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_XAO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 7:  cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RTO>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 8:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_2, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_2>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 9:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_HALF, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_HALF>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 11: cryptonight_single_hash_gpu<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_GPU>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 12:
#if !SOFT_AES && (defined(CPU_INTEL) || defined(CPU_AMD))
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_WOW, xmrig::ASM_AUTO>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash    <xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_WOW>         (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 13:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_4, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_4>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 14: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_RWZ>               (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;

                case 15:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_ZLS, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_ZLS>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                case 16:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT, xmrig::VARIANT_DOUBLE, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_DOUBLE>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
#endif
                         break;

                default: cryptonight_single_hash<xmrig::CRYPTONIGHT, SOFT_AES, xmrig::VARIANT_1>  (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    if ((variant == xmrig::VARIANT_WOW || variant == xmrig::VARIANT_4) && (callback_arg_num < 3)) {
        return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}

class CCryptonightLightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];

    public:

        CCryptonightLightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_LITE_MEMORY, 4096));
        }

        ~CCryptonightLightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_LITE, SOFT_AES, xmrig::VARIANT_1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_light_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        variant = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightLightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}

class CCryptonightHeavyAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        const uint64_t m_height;
        char m_output[32];

    public:

        CCryptonightHeavyAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant, const uint64_t height)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant), m_height(height) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_HEAVY_MEMORY, 4096));
        }

        ~CCryptonightHeavyAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 1:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_XHV >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                case 2:  cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_TUBE>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
                         break;
                default: cryptonight_single_hash<xmrig::CRYPTONIGHT_HEAVY, SOFT_AES, xmrig::VARIANT_0   >(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, m_height);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_heavy_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        variant = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightHeavyAsync(callback, Buffer::Data(target), Buffer::Length(target), variant, height));
}


class CCryptonightPicoAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightPicoAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(xmrig::CRYPTONIGHT_PICO_MEMORY, 4096));
        }

        ~CCryptonightPicoAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            switch (m_variant) {
                case 0:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#endif
			 break;
                default:
#if !SOFT_AES && defined(CPU_INTEL)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_INTEL>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_RYZEN>     (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#elif !SOFT_AES && defined(CPU_AMD_OLD)
                         cryptonight_single_hash_asm<xmrig::CRYPTONIGHT_PICO, xmrig::VARIANT_TRTL, xmrig::ASM_BULLDOZER> (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#else
                         cryptonight_single_hash<xmrig::CRYPTONIGHT_PICO, SOFT_AES, xmrig::VARIANT_TRTL>                 (reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &m_ctx, 0);
#endif
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_pico_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightPicoAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_pico").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_pico)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_pico_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_pico_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("randomx").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(randomx)).ToLocalChecked());
}

NODE_MODULE(cryptonight, init)
