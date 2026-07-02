// native/src/secure_gemm_op.cpp
#include "onnxruntime_c_api.h"
#include "pal.h"
#include "crypto_engine.h"
#include <vector>
#include <string>
#include <cmath>
#include <cstring>
#include <iostream>
#include <cstdlib>

// Custom operator kernel for SecureGemm
struct SecureGemmKernel {
    SecureGemmKernel(const OrtApi* api, const OrtKernelInfo* info) : api_(api), info_(info) {
        // Retrieve custom attributes: shape and dtype of the weight matrix
        size_t size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", nullptr, &size);
        std::vector<int64_t> shape_attr(size);
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", shape_attr.data(), &size);
        
        out_features_ = shape_attr[0];
        in_features_ = shape_attr[1];

        // Retrieve weight_name attribute
        size_t name_len = 0;
        OrtStatus* status = api_->KernelInfoGetAttribute_string(info_, "weight_name", nullptr, &name_len);
        if (status == nullptr && name_len > 0) {
            std::vector<char> name_buf(name_len);
            api_->KernelInfoGetAttribute_string(info_, "weight_name", name_buf.data(), &name_len);
            weight_name_ = std::string(name_buf.data());
        } else {
            weight_name_ = "unknown";
        }
        if (status != nullptr) api_->ReleaseStatus(status);

        // Retrieve dtype attribute
        size_t dtype_len = 0;
        status = api_->KernelInfoGetAttribute_string(info_, "dtype", nullptr, &dtype_len);
        if (status == nullptr && dtype_len > 0) {
            std::vector<char> dtype_buf(dtype_len);
            api_->KernelInfoGetAttribute_string(info_, "dtype", dtype_buf.data(), &dtype_len);
            dtype_ = std::string(dtype_buf.data());
        } else {
            dtype_ = "float32";
        }
        if (status != nullptr) api_->ReleaseStatus(status);
    }

    ~SecureGemmKernel() {}

    void Compute(OrtKernelContext* context) {
        // 1. Get input tensors
        const OrtValue* input_x = nullptr;
        const OrtValue* input_w_enc = nullptr;
        const OrtValue* input_iv = nullptr;
        const OrtValue* input_tag = nullptr;
        const OrtValue* input_bias = nullptr;
        
        api_->KernelContext_GetInput(context, 0, &input_x);
        api_->KernelContext_GetInput(context, 1, &input_w_enc);
        api_->KernelContext_GetInput(context, 2, &input_iv);
        api_->KernelContext_GetInput(context, 3, &input_tag);
        
        // Get pointers to input data
        float* x_data = nullptr;
        uint8_t* w_enc_data = nullptr;
        uint8_t* iv_data = nullptr;
        uint8_t* tag_data = nullptr;
        
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_x), reinterpret_cast<void**>(&x_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_w_enc), reinterpret_cast<void**>(&w_enc_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_iv), reinterpret_cast<void**>(&iv_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_tag), reinterpret_cast<void**>(&tag_data));
        
        // Get ciphertext length using standard GetTensorTypeAndShape API
        OrtTensorTypeAndShapeInfo* w_enc_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_w_enc, &w_enc_info_ptr);
        size_t ciphertext_len = 0;
        api_->GetTensorShapeElementCount(w_enc_info_ptr, &ciphertext_len);
        api_->ReleaseTensorTypeAndShapeInfo(w_enc_info_ptr);
        
        // Get batch size from input shape: X shape is [batch_size, in_features]
        OrtTensorTypeAndShapeInfo* x_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_x, &x_info_ptr);
        size_t x_dim_count = 0;
        api_->GetDimensionsCount(x_info_ptr, &x_dim_count);
        std::vector<int64_t> x_shape(x_dim_count);
        api_->GetDimensions(x_info_ptr, x_shape.data(), x_dim_count);
        api_->ReleaseTensorTypeAndShapeInfo(x_info_ptr);
        
        int64_t batch_size = x_shape[0];
        
        // 2. Load master key from secure memory storage directly (Thread-safe on stack)
        uint8_t master_key[32] = {0};
        if (!pal_retrieve_key(master_key, 32)) {
            pal_kill_if_debugged(); // Key not found or integrity compromised
        }
        
        // 3. Allocate secure, page-protected buffer for the weight matrix
        size_t weight_size_bytes = out_features_ * in_features_ * sizeof(float);
        size_t allocated_size = weight_size_bytes;
        void* decrypted_weights_ptr = pal_lease_secure_slot(weight_size_bytes, &allocated_size);
        if (!decrypted_weights_ptr) {
            pal_secure_zero(master_key, 32);
            return;
        }
        
        // 4. Unlock page to writable and decrypt JIT
        pal_unlock(decrypted_weights_ptr, allocated_size);
        
        // Construct Associated Authenticated Data (AAD)
        std::string shape_str = "[" + std::to_string(out_features_) + ", " + std::to_string(in_features_) + "]";
        std::string aad_str = weight_name_ + ":" + shape_str + ":" + dtype_;
        
        bool success = vajraa_decrypt_gcm(
            w_enc_data, ciphertext_len,
            master_key, iv_data, tag_data,
            reinterpret_cast<const uint8_t*>(aad_str.c_str()), aad_str.length(),
            reinterpret_cast<uint8_t*>(decrypted_weights_ptr)
        );
        
        // Wipe master key from stack immediately
        pal_secure_zero(master_key, 32);
        
        if (!success) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        void* read_weights_ptr = pal_get_read_view(decrypted_weights_ptr, allocated_size);
        const float* w_data = reinterpret_cast<const float*>(read_weights_ptr);
        
        // 5. Check if bias is supplied as 5th input
        float* bias_data = nullptr;
        size_t input_count = 0;
        api_->KernelContext_GetInputCount(context, &input_count);
        if (input_count > 4) {
            api_->KernelContext_GetInput(context, 4, &input_bias);
            if (input_bias) {
                api_->GetTensorMutableData(const_cast<OrtValue*>(input_bias), reinterpret_cast<void**>(&bias_data));
            }
        }
        
        // 6. Allocate output tensor of shape [batch_size, out_features]
        std::vector<int64_t> output_shape = {batch_size, out_features_};
        OrtValue* output_y = nullptr;
        OrtStatus* status = api_->KernelContext_GetOutput(context, 0, output_shape.data(), output_shape.size(), &output_y);
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        float* y_data = nullptr;
        status = api_->GetTensorMutableData(output_y, reinterpret_cast<void**>(&y_data));
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        // 7. Compute Gemm: Y = X * W^T + Bias
        if (batch_size > 1) {
            #pragma omp parallel for if(batch_size > 4)
            for (int64_t b = 0; b < batch_size; ++b) {
                for (int64_t o = 0; o < out_features_; ++o) {
                    float sum = 0.0f;
                    for (int64_t i = 0; i < in_features_; ++i) {
                        sum += x_data[b * in_features_ + i] * w_data[o * in_features_ + i];
                    }
                    if (bias_data) {
                        sum += bias_data[o];
                    }
                    y_data[b * out_features_ + o] = sum;
                }
            }
        } else {
            #pragma omp parallel for if(out_features_ > 64)
            for (int64_t o = 0; o < out_features_; ++o) {
                float sum = 0.0f;
                for (int64_t i = 0; i < in_features_; ++i) {
                    sum += x_data[i] * w_data[o * in_features_ + i];
                }
                if (bias_data) {
                    sum += bias_data[o];
                }
                y_data[o] = sum;
            }
        }
        
        // 8. Wipe decrypted weights from physical RAM immediately
        pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
    }

private:
    const OrtApi* api_;
    const OrtKernelInfo* info_;
    int64_t out_features_;
    int64_t in_features_;
    
    std::string weight_name_;
    std::string dtype_;
};

// Custom operator kernel for SecureConv
struct SecureConvKernel {
    SecureConvKernel(const OrtApi* api, const OrtKernelInfo* info) : api_(api), info_(info) {
        size_t size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", nullptr, &size);
        std::vector<int64_t> shape_attr(size);
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", shape_attr.data(), &size);
        
        out_channels_ = shape_attr[0];
        in_channels_ = shape_attr[1];
        kernel_h_ = shape_attr[2];
        kernel_w_ = shape_attr[3];
        
        // Retrieve strides
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "strides", nullptr, &size);
        if (size > 0) {
            strides_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "strides", strides_.data(), &size);
        } else {
            strides_ = {1, 1};
        }
        
        // Retrieve pads
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "pads", nullptr, &size);
        if (size > 0) {
            pads_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "pads", pads_.data(), &size);
        } else {
            pads_ = {0, 0, 0, 0};
        }
        
        // Retrieve dilations
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "dilations", nullptr, &size);
        if (size > 0) {
            dilations_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "dilations", dilations_.data(), &size);
        } else {
            dilations_ = {1, 1};
        }

        // Retrieve weight_name attribute
        size_t name_len = 0;
        OrtStatus* status = api_->KernelInfoGetAttribute_string(info_, "weight_name", nullptr, &name_len);
        if (status == nullptr && name_len > 0) {
            std::vector<char> name_buf(name_len);
            api_->KernelInfoGetAttribute_string(info_, "weight_name", name_buf.data(), &name_len);
            weight_name_ = std::string(name_buf.data());
        } else {
            weight_name_ = "unknown";
        }
        if (status != nullptr) api_->ReleaseStatus(status);

        // Retrieve dtype attribute
        size_t dtype_len = 0;
        status = api_->KernelInfoGetAttribute_string(info_, "dtype", nullptr, &dtype_len);
        if (status == nullptr && dtype_len > 0) {
            std::vector<char> dtype_buf(dtype_len);
            api_->KernelInfoGetAttribute_string(info_, "dtype", dtype_buf.data(), &dtype_len);
            dtype_ = std::string(dtype_buf.data());
        } else {
            dtype_ = "float32";
        }
        if (status != nullptr) api_->ReleaseStatus(status);
    }
    
    ~SecureConvKernel() {}

    void Compute(OrtKernelContext* context) {
        const OrtValue* input_x = nullptr;
        const OrtValue* input_w_enc = nullptr;
        const OrtValue* input_iv = nullptr;
        const OrtValue* input_tag = nullptr;
        const OrtValue* input_bias = nullptr;
        
        api_->KernelContext_GetInput(context, 0, &input_x);
        api_->KernelContext_GetInput(context, 1, &input_w_enc);
        api_->KernelContext_GetInput(context, 2, &input_iv);
        api_->KernelContext_GetInput(context, 3, &input_tag);
        
        float* x_data = nullptr;
        uint8_t* w_enc_data = nullptr;
        uint8_t* iv_data = nullptr;
        uint8_t* tag_data = nullptr;
        
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_x), reinterpret_cast<void**>(&x_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_w_enc), reinterpret_cast<void**>(&w_enc_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_iv), reinterpret_cast<void**>(&iv_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_tag), reinterpret_cast<void**>(&tag_data));
        
        OrtTensorTypeAndShapeInfo* w_enc_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_w_enc, &w_enc_info_ptr);
        size_t ciphertext_len = 0;
        api_->GetTensorShapeElementCount(w_enc_info_ptr, &ciphertext_len);
        api_->ReleaseTensorTypeAndShapeInfo(w_enc_info_ptr);
        
        OrtTensorTypeAndShapeInfo* x_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_x, &x_info_ptr);
        size_t x_dim_count = 0;
        api_->GetDimensionsCount(x_info_ptr, &x_dim_count);
        std::vector<int64_t> x_shape(x_dim_count);
        api_->GetDimensions(x_info_ptr, x_shape.data(), x_dim_count);
        api_->ReleaseTensorTypeAndShapeInfo(x_info_ptr);
        
        int64_t batch_size = x_shape[0];
        int64_t in_c = x_shape[1];
        int64_t in_h = x_shape[2];
        int64_t in_w = x_shape[3];
        
        // Thread-safe stack key retrieval
        uint8_t master_key[32] = {0};
        if (!pal_retrieve_key(master_key, 32)) {
            pal_kill_if_debugged();
        }
        
        size_t weight_size_bytes = out_channels_ * in_channels_ * kernel_h_ * kernel_w_ * sizeof(float);
        size_t allocated_size = weight_size_bytes;
        void* decrypted_weights_ptr = pal_lease_secure_slot(weight_size_bytes, &allocated_size);
        if (!decrypted_weights_ptr) {
            pal_secure_zero(master_key, 32);
            return;
        }
        
        pal_unlock(decrypted_weights_ptr, allocated_size);
        
        // Construct Associated Authenticated Data (AAD)
        std::string shape_str = "[" + std::to_string(out_channels_) + ", " + std::to_string(in_channels_) + ", " + std::to_string(kernel_h_) + ", " + std::to_string(kernel_w_) + "]";
        std::string aad_str = weight_name_ + ":" + shape_str + ":" + dtype_;
        
        bool success = vajraa_decrypt_gcm(
            w_enc_data, ciphertext_len,
            master_key, iv_data, tag_data,
            reinterpret_cast<const uint8_t*>(aad_str.c_str()), aad_str.length(),
            reinterpret_cast<uint8_t*>(decrypted_weights_ptr)
        );
        
        pal_secure_zero(master_key, 32);
        
        if (!success) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        void* read_weights_ptr = pal_get_read_view(decrypted_weights_ptr, allocated_size);
        const float* w_data = reinterpret_cast<const float*>(read_weights_ptr);
        
        int64_t out_h = (in_h + pads_[0] + pads_[2] - dilations_[0] * (kernel_h_ - 1) - 1) / strides_[0] + 1;
        int64_t out_w = (in_w + pads_[1] + pads_[3] - dilations_[1] * (kernel_w_ - 1) - 1) / strides_[1] + 1;
        
        float* bias_data = nullptr;
        size_t input_count = 0;
        api_->KernelContext_GetInputCount(context, &input_count);
        if (input_count > 4) {
            api_->KernelContext_GetInput(context, 4, &input_bias);
            if (input_bias) {
                api_->GetTensorMutableData(const_cast<OrtValue*>(input_bias), reinterpret_cast<void**>(&bias_data));
            }
        }
        
        std::vector<int64_t> output_shape = {batch_size, out_channels_, out_h, out_w};
        OrtValue* output_y = nullptr;
        OrtStatus* status = api_->KernelContext_GetOutput(context, 0, output_shape.data(), output_shape.size(), &output_y);
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        float* y_data = nullptr;
        status = api_->GetTensorMutableData(output_y, reinterpret_cast<void**>(&y_data));
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        #pragma omp parallel for collapse(2) if(batch_size * out_channels_ > 4)
        for (int64_t b = 0; b < batch_size; ++b) {
            for (int64_t oc = 0; oc < out_channels_; ++oc) {
                for (int64_t oh = 0; oh < out_h; ++oh) {
                    for (int64_t ow = 0; ow < out_w; ++ow) {
                        float sum = 0.0f;
                        for (int64_t ic = 0; ic < in_channels_; ++ic) {
                            for (int64_t kh = 0; kh < kernel_h_; ++kh) {
                                for (int64_t kw = 0; kw < kernel_w_; ++kw) {
                                    int64_t ih = oh * strides_[0] + kh * dilations_[0] - pads_[0];
                                    int64_t iw = ow * strides_[1] + kw * dilations_[1] - pads_[1];
                                    if (ih >= 0 && ih < in_h && iw >= 0 && iw < in_w) {
                                        sum += x_data[((b * in_c + ic) * in_h + ih) * in_w + iw] * 
                                               w_data[((oc * in_channels_ + ic) * kernel_h_ + kh) * kernel_w_ + kw];
                                    }
                                }
                            }
                        }
                        if (bias_data) {
                            sum += bias_data[oc];
                        }
                        y_data[((b * out_channels_ + oc) * out_h + oh) * out_w + ow] = sum;
                    }
                }
            }
        }
        
        pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
    }
    
private:
    const OrtApi* api_;
    const OrtKernelInfo* info_;
    int64_t out_channels_;
    int64_t in_channels_;
    int64_t kernel_h_;
    int64_t kernel_w_;
    
    std::vector<int64_t> strides_;
    std::vector<int64_t> pads_;
    std::vector<int64_t> dilations_;
    
    std::string weight_name_;
    std::string dtype_;
};

// Custom operator kernel for SecureConvTranspose
struct SecureConvTransposeKernel {
    SecureConvTransposeKernel(const OrtApi* api, const OrtKernelInfo* info) : api_(api), info_(info) {
        size_t size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", nullptr, &size);
        std::vector<int64_t> shape_attr(size);
        api_->KernelInfoGetAttributeArray_int64(info_, "shape", shape_attr.data(), &size);
        
        in_channels_ = shape_attr[0];
        out_channels_ = shape_attr[1];
        kernel_h_ = shape_attr[2];
        kernel_w_ = shape_attr[3];
        
        // Retrieve strides
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "strides", nullptr, &size);
        if (size > 0) {
            strides_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "strides", strides_.data(), &size);
        } else {
            strides_ = {1, 1};
        }
        
        // Retrieve pads
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "pads", nullptr, &size);
        if (size > 0) {
            pads_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "pads", pads_.data(), &size);
        } else {
            pads_ = {0, 0, 0, 0};
        }
        
        // Retrieve output_padding
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "output_padding", nullptr, &size);
        if (size > 0) {
            output_padding_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "output_padding", output_padding_.data(), &size);
        } else {
            output_padding_ = {0, 0};
        }
        
        // Retrieve dilations
        size = 0;
        api_->KernelInfoGetAttributeArray_int64(info_, "dilations", nullptr, &size);
        if (size > 0) {
            dilations_.resize(size);
            api_->KernelInfoGetAttributeArray_int64(info_, "dilations", dilations_.data(), &size);
        } else {
            dilations_ = {1, 1};
        }

        // Retrieve weight_name attribute
        size_t name_len = 0;
        OrtStatus* status = api_->KernelInfoGetAttribute_string(info_, "weight_name", nullptr, &name_len);
        if (status == nullptr && name_len > 0) {
            std::vector<char> name_buf(name_len);
            api_->KernelInfoGetAttribute_string(info_, "weight_name", name_buf.data(), &name_len);
            weight_name_ = std::string(name_buf.data());
        } else {
            weight_name_ = "unknown";
        }
        if (status != nullptr) api_->ReleaseStatus(status);

        // Retrieve dtype attribute
        size_t dtype_len = 0;
        status = api_->KernelInfoGetAttribute_string(info_, "dtype", nullptr, &dtype_len);
        if (status == nullptr && dtype_len > 0) {
            std::vector<char> dtype_buf(dtype_len);
            api_->KernelInfoGetAttribute_string(info_, "dtype", dtype_buf.data(), &dtype_len);
            dtype_ = std::string(dtype_buf.data());
        } else {
            dtype_ = "float32";
        }
        if (status != nullptr) api_->ReleaseStatus(status);
    }
    
    ~SecureConvTransposeKernel() {}

    void Compute(OrtKernelContext* context) {
        const OrtValue* input_x = nullptr;
        const OrtValue* input_w_enc = nullptr;
        const OrtValue* input_iv = nullptr;
        const OrtValue* input_tag = nullptr;
        const OrtValue* input_bias = nullptr;
        
        api_->KernelContext_GetInput(context, 0, &input_x);
        api_->KernelContext_GetInput(context, 1, &input_w_enc);
        api_->KernelContext_GetInput(context, 2, &input_iv);
        api_->KernelContext_GetInput(context, 3, &input_tag);
        
        float* x_data = nullptr;
        uint8_t* w_enc_data = nullptr;
        uint8_t* iv_data = nullptr;
        uint8_t* tag_data = nullptr;
        
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_x), reinterpret_cast<void**>(&x_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_w_enc), reinterpret_cast<void**>(&w_enc_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_iv), reinterpret_cast<void**>(&iv_data));
        api_->GetTensorMutableData(const_cast<OrtValue*>(input_tag), reinterpret_cast<void**>(&tag_data));
        
        OrtTensorTypeAndShapeInfo* w_enc_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_w_enc, &w_enc_info_ptr);
        size_t ciphertext_len = 0;
        api_->GetTensorShapeElementCount(w_enc_info_ptr, &ciphertext_len);
        api_->ReleaseTensorTypeAndShapeInfo(w_enc_info_ptr);
        
        OrtTensorTypeAndShapeInfo* x_info_ptr = nullptr;
        api_->GetTensorTypeAndShape(input_x, &x_info_ptr);
        size_t x_dim_count = 0;
        api_->GetDimensionsCount(x_info_ptr, &x_dim_count);
        std::vector<int64_t> x_shape(x_dim_count);
        api_->GetDimensions(x_info_ptr, x_shape.data(), x_dim_count);
        api_->ReleaseTensorTypeAndShapeInfo(x_info_ptr);
        
        int64_t batch_size = x_shape[0];
        int64_t in_c = x_shape[1];
        int64_t in_h = x_shape[2];
        int64_t in_w = x_shape[3];
        
        // Thread-safe stack key retrieval
        uint8_t master_key[32] = {0};
        if (!pal_retrieve_key(master_key, 32)) {
            pal_kill_if_debugged();
        }
        
        size_t weight_size_bytes = in_channels_ * out_channels_ * kernel_h_ * kernel_w_ * sizeof(float);
        size_t allocated_size = weight_size_bytes;
        void* decrypted_weights_ptr = pal_lease_secure_slot(weight_size_bytes, &allocated_size);
        if (!decrypted_weights_ptr) {
            pal_secure_zero(master_key, 32);
            return;
        }
        
        pal_unlock(decrypted_weights_ptr, allocated_size);
        
        // Construct Associated Authenticated Data (AAD)
        std::string shape_str = "[" + std::to_string(in_channels_) + ", " + std::to_string(out_channels_) + ", " + std::to_string(kernel_h_) + ", " + std::to_string(kernel_w_) + "]";
        std::string aad_str = weight_name_ + ":" + shape_str + ":" + dtype_;
        
        bool success = vajraa_decrypt_gcm(
            w_enc_data, ciphertext_len,
            master_key, iv_data, tag_data,
            reinterpret_cast<const uint8_t*>(aad_str.c_str()), aad_str.length(),
            reinterpret_cast<uint8_t*>(decrypted_weights_ptr)
        );
        
        pal_secure_zero(master_key, 32);
        
        if (!success) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        void* read_weights_ptr = pal_get_read_view(decrypted_weights_ptr, allocated_size);
        const float* w_data = reinterpret_cast<const float*>(read_weights_ptr);
        
        int64_t out_h = strides_[0] * (in_h - 1) + output_padding_[0] + dilations_[0] * (kernel_h_ - 1) + 1 - pads_[0] - pads_[2];
        int64_t out_w = strides_[1] * (in_w - 1) + output_padding_[1] + dilations_[1] * (kernel_w_ - 1) + 1 - pads_[1] - pads_[3];
        
        float* bias_data = nullptr;
        size_t input_count = 0;
        api_->KernelContext_GetInputCount(context, &input_count);
        if (input_count > 4) {
            api_->KernelContext_GetInput(context, 4, &input_bias);
            if (input_bias) {
                api_->GetTensorMutableData(const_cast<OrtValue*>(input_bias), reinterpret_cast<void**>(&bias_data));
            }
        }
        
        std::vector<int64_t> output_shape = {batch_size, out_channels_, out_h, out_w};
        OrtValue* output_y = nullptr;
        OrtStatus* status = api_->KernelContext_GetOutput(context, 0, output_shape.data(), output_shape.size(), &output_y);
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        float* y_data = nullptr;
        status = api_->GetTensorMutableData(output_y, reinterpret_cast<void**>(&y_data));
        if (status != nullptr) {
            pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
            return;
        }
        
        // Naive CPU Transpose Convolution
        memset(y_data, 0, batch_size * out_channels_ * out_h * out_w * sizeof(float));
        
        #pragma omp parallel for collapse(2) if(batch_size * in_channels_ > 4)
        for (int64_t b = 0; b < batch_size; ++b) {
            for (int64_t ic = 0; ic < in_channels_; ++ic) {
                for (int64_t oh = 0; oh < in_h; ++oh) {
                    for (int64_t ow = 0; ow < in_w; ++ow) {
                        float val = x_data[((b * in_c + ic) * in_h + oh) * in_w + ow];
                        for (int64_t oc = 0; oc < out_channels_; ++oc) {
                            for (int64_t kh = 0; kh < kernel_h_; ++kh) {
                                for (int64_t kw = 0; kw < kernel_w_; ++kw) {
                                    int64_t y_h = oh * strides_[0] + kh * dilations_[0] - pads_[0];
                                    int64_t y_w = ow * strides_[1] + kw * dilations_[1] - pads_[1];
                                    if (y_h >= 0 && y_h < out_h && y_w >= 0 && y_w < out_w) {
                                        #pragma omp atomic
                                        y_data[((b * out_channels_ + oc) * out_h + y_h) * out_w + y_w] += 
                                            val * w_data[((ic * out_channels_ + oc) * kernel_h_ + kh) * kernel_w_ + kw];
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (bias_data) {
            #pragma omp parallel for collapse(2)
            for (int64_t b = 0; b < batch_size; ++b) {
                for (int64_t oc = 0; oc < out_channels_; ++oc) {
                    for (int64_t oh = 0; oh < out_h; ++oh) {
                        for (int64_t ow = 0; ow < out_w; ++ow) {
                            y_data[((b * out_channels_ + oc) * out_h + oh) * out_w + ow] += bias_data[oc];
                        }
                    }
                }
            }
        }
        
        pal_release_secure_slot(decrypted_weights_ptr, allocated_size);
    }
    
private:
    const OrtApi* api_;
    const OrtKernelInfo* info_;
    int64_t in_channels_;
    int64_t out_channels_;
    int64_t kernel_h_;
    int64_t kernel_w_;
    
    std::vector<int64_t> strides_;
    std::vector<int64_t> pads_;
    std::vector<int64_t> output_padding_;
    std::vector<int64_t> dilations_;
    
    std::string weight_name_;
    std::string dtype_;
};

// Define custom operator schema and bindings for SecureGemmOp
struct SecureGemmOp : OrtCustomOp {
    SecureGemmOp() {
        version = ORT_API_VERSION;
        
        GetName = [](const OrtCustomOp*) -> const char* { return "SecureGemm"; };
        GetExecutionProviderType = [](const OrtCustomOp*) -> const char* { return "CPUExecutionProvider"; };
        
        GetInputTypeCount = [](const OrtCustomOp*) -> size_t { return 5; };
        GetInputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            if (index == 0) return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;      // X
            if (index == 1) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // W_enc
            if (index == 2) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // IV
            if (index == 3) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // Tag
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;                      // Bias
        };
        
        GetInputCharacteristic = [](const OrtCustomOp*, size_t index) -> OrtCustomOpInputOutputCharacteristic {
            if (index == 4) return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_OPTIONAL;
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };

        GetOutputTypeCount = [](const OrtCustomOp*) -> size_t { return 1; };
        GetOutputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        };
        GetOutputCharacteristic = [](const OrtCustomOp*, size_t) -> OrtCustomOpInputOutputCharacteristic {
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };
        
        CreateKernel = [](const OrtCustomOp* this_, const OrtApi* api, const OrtKernelInfo* info) -> void* {
            return new SecureGemmKernel(api, info);
        };
        
        KernelCompute = [](void* op_kernel, OrtKernelContext* context) {
            static_cast<SecureGemmKernel*>(op_kernel)->Compute(context);
        };
        
        KernelDestroy = [](void* op_kernel) {
            delete static_cast<SecureGemmKernel*>(op_kernel);
        };
        
        GetInputMemoryType = [](const OrtCustomOp*, size_t) -> OrtMemType { return OrtMemTypeDefault; };
        GetVariadicInputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicInputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        
        CreateKernelV2 = nullptr;
        KernelComputeV2 = nullptr;
        GetMayInplace = nullptr;
        ReleaseMayInplace = nullptr;
        GetAliasMap = nullptr;
        ReleaseAliasMap = nullptr;
        
        GetStartVersion = [](const OrtCustomOp*) -> int { return 1; };
        GetEndVersion = [](const OrtCustomOp*) -> int { return 2147483647; };
        InferOutputShapeFn = nullptr;
    }
};

// Define custom operator schema and bindings for SecureConvOp
struct SecureConvOp : OrtCustomOp {
    SecureConvOp() {
        version = ORT_API_VERSION;
        
        GetName = [](const OrtCustomOp*) -> const char* { return "SecureConv"; };
        GetExecutionProviderType = [](const OrtCustomOp*) -> const char* { return "CPUExecutionProvider"; };
        
        GetInputTypeCount = [](const OrtCustomOp*) -> size_t { return 5; };
        GetInputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            if (index == 0) return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;      // X
            if (index == 1) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // W_enc
            if (index == 2) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // IV
            if (index == 3) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // Tag
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;                      // Bias
        };
        
        GetInputCharacteristic = [](const OrtCustomOp*, size_t index) -> OrtCustomOpInputOutputCharacteristic {
            if (index == 4) return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_OPTIONAL;
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };

        GetOutputTypeCount = [](const OrtCustomOp*) -> size_t { return 1; };
        GetOutputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        };
        GetOutputCharacteristic = [](const OrtCustomOp*, size_t) -> OrtCustomOpInputOutputCharacteristic {
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };
        
        CreateKernel = [](const OrtCustomOp* this_, const OrtApi* api, const OrtKernelInfo* info) -> void* {
            return new SecureConvKernel(api, info);
        };
        
        KernelCompute = [](void* op_kernel, OrtKernelContext* context) {
            static_cast<SecureConvKernel*>(op_kernel)->Compute(context);
        };
        
        KernelDestroy = [](void* op_kernel) {
            delete static_cast<SecureConvKernel*>(op_kernel);
        };
        
        GetInputMemoryType = [](const OrtCustomOp*, size_t) -> OrtMemType { return OrtMemTypeDefault; };
        GetVariadicInputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicInputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        
        CreateKernelV2 = nullptr;
        KernelComputeV2 = nullptr;
        GetMayInplace = nullptr;
        ReleaseMayInplace = nullptr;
        GetAliasMap = nullptr;
        ReleaseAliasMap = nullptr;
        
        GetStartVersion = [](const OrtCustomOp*) -> int { return 1; };
        GetEndVersion = [](const OrtCustomOp*) -> int { return 2147483647; };
        InferOutputShapeFn = nullptr;
    }
};

// Define custom operator schema and bindings for SecureConvTransposeOp
struct SecureConvTransposeOp : OrtCustomOp {
    SecureConvTransposeOp() {
        version = ORT_API_VERSION;
        
        GetName = [](const OrtCustomOp*) -> const char* { return "SecureConvTranspose"; };
        GetExecutionProviderType = [](const OrtCustomOp*) -> const char* { return "CPUExecutionProvider"; };
        
        GetInputTypeCount = [](const OrtCustomOp*) -> size_t { return 5; };
        GetInputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            if (index == 0) return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;      // X
            if (index == 1) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // W_enc
            if (index == 2) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // IV
            if (index == 3) return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;      // Tag
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;                      // Bias
        };
        
        GetInputCharacteristic = [](const OrtCustomOp*, size_t index) -> OrtCustomOpInputOutputCharacteristic {
            if (index == 4) return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_OPTIONAL;
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };

        GetOutputTypeCount = [](const OrtCustomOp*) -> size_t { return 1; };
        GetOutputType = [](const OrtCustomOp*, size_t index) -> ONNXTensorElementDataType {
            return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
        };
        GetOutputCharacteristic = [](const OrtCustomOp*, size_t) -> OrtCustomOpInputOutputCharacteristic {
            return OrtCustomOpInputOutputCharacteristic::INPUT_OUTPUT_REQUIRED;
        };
        
        CreateKernel = [](const OrtCustomOp* this_, const OrtApi* api, const OrtKernelInfo* info) -> void* {
            return new SecureConvTransposeKernel(api, info);
        };
        
        KernelCompute = [](void* op_kernel, OrtKernelContext* context) {
            static_cast<SecureConvTransposeKernel*>(op_kernel)->Compute(context);
        };
        
        KernelDestroy = [](void* op_kernel) {
            delete static_cast<SecureConvTransposeKernel*>(op_kernel);
        };
        
        GetInputMemoryType = [](const OrtCustomOp*, size_t) -> OrtMemType { return OrtMemTypeDefault; };
        GetVariadicInputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicInputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputMinArity = [](const OrtCustomOp*) -> int { return 0; };
        GetVariadicOutputHomogeneity = [](const OrtCustomOp*) -> int { return 0; };
        
        CreateKernelV2 = nullptr;
        KernelComputeV2 = nullptr;
        GetMayInplace = nullptr;
        ReleaseMayInplace = nullptr;
        GetAliasMap = nullptr;
        ReleaseAliasMap = nullptr;
        
        GetStartVersion = [](const OrtCustomOp*) -> int { return 1; };
        GetEndVersion = [](const OrtCustomOp*) -> int { return 2147483647; };
        InferOutputShapeFn = nullptr;
    }
};

// Entrypoint for loading custom operators dynamically in ONNX Runtime
extern "C" {
#ifdef _WIN32
__declspec(dllexport)
#endif
OrtStatus* ORT_API_CALL RegisterCustomOps(OrtSessionOptions* options, const OrtApiBase* api) {
    const OrtApi* api_ptr = api->GetApi(ORT_API_VERSION);
    static SecureGemmOp secure_gemm_op;
    static SecureConvOp secure_conv_op;
    static SecureConvTransposeOp secure_conv_transpose_op;
    
    // Register the custom op domain 'vajraa'
    OrtCustomOpDomain* domain = nullptr;
    OrtStatus* status = api_ptr->CreateCustomOpDomain("vajraa", &domain);
    if (status != nullptr) return status;
    
    status = api_ptr->CustomOpDomain_Add(domain, &secure_gemm_op);
    if (status != nullptr) return status;
    
    status = api_ptr->CustomOpDomain_Add(domain, &secure_conv_op);
    if (status != nullptr) return status;
    
    status = api_ptr->CustomOpDomain_Add(domain, &secure_conv_transpose_op);
    if (status != nullptr) return status;
    
    // Register the custom op domain with session options directly
    return api_ptr->AddCustomOpDomain(options, domain);
}
}
