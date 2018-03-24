#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "slow_hash.h"
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
        variant = info[1]->ToNumber()->NumberValue();
    }

    char output[32];
    cn_slow_hash(Buffer::Data(target), Buffer::Length(target), output, variant);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

class CNAsyncWorker : public Nan::AsyncWorker {

    private:

        const char* const m_input;
        const uint32_t m_input_len;
        const int m_variant;
        char m_output[32];

    public:

        CNAsyncWorker(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int variant)
            : Nan::AsyncWorker(callback), m_input(input), m_input_len(input_len), m_variant(variant) {}

        ~CNAsyncWorker() {}

        void Execute () {
            cn_slow_hash(m_input, m_input_len, m_output, m_variant);
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

    Callback *callback = new Nan::Callback(info[0].As<v8::Function>());
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int variant = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if(!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        variant = info[1]->ToNumber()->NumberValue();
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Local<Object> target = info[callback_arg_num]->ToObject();
    Nan::AsyncQueueWorker(new CNAsyncWorker(callback, Buffer::Data(target), Buffer::Length(target), variant));
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_async)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
