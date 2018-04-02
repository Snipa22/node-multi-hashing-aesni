#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>
#include "multihashing.h"

extern "C" {
    #include "cryptonight.h"
    #include "cryptonight_light.h"
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
  free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(cryptonight) {

    bool fast = false;
    uint32_t cn_variant = 0;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    if (info.Length() >= 2) {
        if(info[1]->IsBoolean())
            fast = info[1]->ToBoolean()->BooleanValue();
       else if(info[1]->IsUint32())
            cn_variant = info[1]->ToUint32()->Uint32Value();
       else
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean or uint32_t");
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
        else {
            if (cn_variant > 0 && input_len < 43)
             return THROW_ERROR_EXCEPTION("Argument must be 43 bytes for monero variant 1+");
             cryptonight_hash(input, output, input_len, cn_variant);
        }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

class CNAsyncWorker : public Nan::AsyncWorker{
    public:
        CNAsyncWorker(Nan::Callback *callback, char * input, uint32_t input_len)
            : Nan::AsyncWorker(callback), input(input), input_len(input_len){}
        ~CNAsyncWorker() {}

    void Execute () {
        uint32_t cn_variant = 0;
        cryptonight_hash(input, output, input_len, cn_variant);
      }

    void HandleOKCallback () {
        Nan::HandleScope scope;

        v8::Local<v8::Value> argv[] = {
            Nan::Null()
          , v8::Local<v8::Value>(Nan::CopyBuffer(output, 32).ToLocalChecked())
        };

        callback->Call(2, argv);
      }

    private:
        uint32_t input_len;
        char * input;
        char output[32];
        uint32_t cn_variant;

};

NAN_METHOD(CNAsync) {

    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);

    Nan::AsyncQueueWorker(new CNAsyncWorker(callback, input, input_len));
}

class CNLAsyncWorker : public Nan::AsyncWorker{
    public:
        CNLAsyncWorker(Nan::Callback *callback, char * input, uint32_t input_len)
            : Nan::AsyncWorker(callback), input(input), input_len(input_len){}
        ~CNLAsyncWorker() {}

    void Execute () {
        cryptonight_light_hash(input, output, input_len,cn_variant);
      }

    void HandleOKCallback () {
        Nan::HandleScope scope;

        v8::Local<v8::Value> argv[] = {
            Nan::Null()
          , v8::Local<v8::Value>(Nan::CopyBuffer(output, 32).ToLocalChecked())
        };

        callback->Call(2, argv);
      }

    private:
        uint32_t input_len;
        char * input;
        char output[32];
        uint32_t cn_variant;
};

NAN_METHOD(CNLAsync) {

    if (info.Length() != 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

    char * input = Buffer::Data(target);
    uint32_t input_len = Buffer::Length(target);

    Nan::AsyncQueueWorker(new CNLAsyncWorker(callback, input, input_len));
}

NAN_METHOD(cryptonight_light) {

         bool fast = false;
        uint32_t cn_variant = 0;

        if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

        if (info.Length() >= 2) {
            if (info[1]->IsBoolean())
                fast = info[1]->ToBoolean()->BooleanValue();
            else if (info[1]->IsUint32())
                cn_variant = info[1]->ToUint32()->Uint32Value();
            else
                return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean or uint32_t");
        }

        Local<Object> target = info[0]->ToObject();

        if (!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

        char * input = Buffer::Data(target);
        char output[32];

        uint32_t input_len = Buffer::Length(target);

        if (fast)
        cryptonight_fast_hash(input, output, input_len);
        else {
            if (cn_variant > 0 && input_len < 43)
                return THROW_ERROR_EXCEPTION("Argument must be 43 bytes for monero variant 1+");
            cryptonight_light_hash(input, output, input_len, cn_variant);
        }

        v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
        info.GetReturnValue().Set(
        returnValue
        );
}


NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("CNAsync").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CNAsync)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("CNLAsync").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CNAsync)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)