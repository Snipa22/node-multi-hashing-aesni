#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

//extern "C" {
//    #include "slow_hash.h"
//}

#include "xmrig/CryptoNight_x86.h"

#if defined(__AES__) && (__AES__ == 1)
#define SOFT_AES false
#else
#warning Using software AES
#define SOFT_AES true
#endif

static struct cryptonight_ctx* ctx = NULL;

void init_ctx() {
    if (ctx) return;
    ctx = static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16));
    ctx->memory = static_cast<uint8_t *>(_mm_malloc(MONERO_MEMORY, 16));
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    //cn_slow_hash(Buffer::Data(target), Buffer::Length(target), output, variant);
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
                break;
       case 1:  cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
                break;
       default: cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int variant = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = Nan::To<int>(info[1]).FromMaybe(0);
    }

    char output[32];
    //cn_slow_hash(Buffer::Data(target), Buffer::Length(target), output, variant);
    init_ctx();
    switch (variant) {
       case 0:  cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 0>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
                break;
       case 1:  cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
                break;
       default: cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), ctx);
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

class CCryptonightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* const m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(MONERO_MEMORY, 16));
        }

        ~CCryptonightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            //cn_slow_hash(m_input, m_input_len, m_output, m_variant);
            switch (m_variant) {
                case 0:  cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
                         break;
                case 1:  cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
                         break;
                default: cryptonight_single_hash<MONERO_ITER, MONERO_MEMORY, MONERO_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv);
        }
};

NAN_METHOD(cryptonight_async) {
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
    Nan::AsyncQueueWorker(new CCryptonightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

class CCryptonightLightAsync : public Nan::AsyncWorker {

    private:

        struct cryptonight_ctx* const m_ctx;
        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CCryptonightLightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_ctx(static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16))),
              m_input(input), m_input_len(input_len), m_variant(variant) {
            m_ctx->memory = static_cast<uint8_t *>(_mm_malloc(AEON_MEMORY, 16));
        }

        ~CCryptonightLightAsync() {
            _mm_free(m_ctx->memory);
            _mm_free(m_ctx);
        }

        void Execute () {
            //cn_slow_hash(m_input, m_input_len, m_output, m_variant);
            switch (m_variant) {
                case 0:  cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 0>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
                         break;
                case 1:  cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
                         break;
                default: cryptonight_single_hash<AEON_ITER, AEON_MEMORY, AEON_MASK, SOFT_AES, 1>(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), m_ctx);
            }
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv);
        }
};

NAN_METHOD(cryptonight_light_async) {
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
    Nan::AsyncQueueWorker(new CCryptonightLightAsync(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_async)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light_async)).ToLocalChecked());
}

NODE_MODULE(cryptonight, init)
