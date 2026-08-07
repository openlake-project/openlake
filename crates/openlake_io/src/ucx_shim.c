#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ucp/api/ucp.h>

#define OL_UCX_CONTROL_TAG ((ucp_tag_t)0x4f4c4354524c0001ULL)
#define OL_UCX_NO_MESSAGE 1

typedef struct {
    ucp_context_h context;
    ucp_worker_h worker;
} ol_ucx_worker;

typedef struct {
    ol_ucx_worker *owner;
    ucp_ep_h ep;
    ucs_status_t status;
} ol_ucx_endpoint;

typedef struct {
    ol_ucx_worker *owner;
    ucp_mem_h memh;
} ol_ucx_memory;

typedef struct {
    ucp_rkey_h rkey;
} ol_ucx_rkey;

static int ol_error(char *error, size_t error_len, const char *operation,
                    ucs_status_t status) {
    if (error != NULL && error_len != 0) {
        snprintf(error, error_len, "%s: %s", operation,
                 ucs_status_string(status));
    }
    return (int)status;
}

static int ol_wait(ol_ucx_worker *worker, void *request, char *error,
                   size_t error_len, const char *operation) {
    if (request == NULL) {
        return 0;
    }
    if (UCS_PTR_IS_ERR(request)) {
        return ol_error(error, error_len, operation, UCS_PTR_STATUS(request));
    }

    ucs_status_t status;
    do {
        ucp_worker_progress(worker->worker);
        status = ucp_request_check_status(request);
    } while (status == UCS_INPROGRESS);
    ucp_request_free(request);
    return status == UCS_OK ? 0
                            : ol_error(error, error_len, operation, status);
}

int ol_ucx_worker_create(ol_ucx_worker **out, char *error, size_t error_len) {
    *out = NULL;
    ucp_config_t *config = NULL;
    ucs_status_t status = ucp_config_read(NULL, NULL, &config);
    if (status != UCS_OK) {
        return ol_error(error, error_len, "ucp_config_read", status);
    }

    ol_ucx_worker *worker = calloc(1, sizeof(*worker));
    if (worker == NULL) {
        ucp_config_release(config);
        return ol_error(error, error_len, "allocate UCX worker", UCS_ERR_NO_MEMORY);
    }

    ucp_params_t params;
    memset(&params, 0, sizeof(params));
    params.field_mask = UCP_PARAM_FIELD_FEATURES;
    params.features = UCP_FEATURE_RMA | UCP_FEATURE_TAG;
    status = ucp_init(&params, config, &worker->context);
    ucp_config_release(config);
    if (status != UCS_OK) {
        free(worker);
        return ol_error(error, error_len, "ucp_init", status);
    }

    ucp_worker_params_t worker_params;
    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
    status = ucp_worker_create(worker->context, &worker_params, &worker->worker);
    if (status != UCS_OK) {
        ucp_cleanup(worker->context);
        free(worker);
        return ol_error(error, error_len, "ucp_worker_create", status);
    }

    *out = worker;
    return 0;
}

void ol_ucx_worker_destroy(ol_ucx_worker *worker) {
    if (worker == NULL) {
        return;
    }
    ucp_worker_destroy(worker->worker);
    ucp_cleanup(worker->context);
    free(worker);
}

unsigned ol_ucx_worker_progress(ol_ucx_worker *worker) {
    return ucp_worker_progress(worker->worker);
}

int ol_ucx_worker_address(ol_ucx_worker *worker, uint8_t **out,
                          size_t *out_len, char *error, size_t error_len) {
    *out = NULL;
    *out_len = 0;
    ucp_address_t *address = NULL;
    size_t length = 0;
    ucs_status_t status =
        ucp_worker_get_address(worker->worker, &address, &length);
    if (status != UCS_OK) {
        return ol_error(error, error_len, "ucp_worker_get_address", status);
    }
    uint8_t *copy = malloc(length);
    if (copy == NULL) {
        ucp_worker_release_address(worker->worker, address);
        return ol_error(error, error_len, "copy UCX worker address",
                        UCS_ERR_NO_MEMORY);
    }
    memcpy(copy, address, length);
    ucp_worker_release_address(worker->worker, address);
    *out = copy;
    *out_len = length;
    return 0;
}

void ol_ucx_free(void *pointer) { free(pointer); }

int ol_ucx_endpoint_connect(ol_ucx_worker *worker, const uint8_t *address,
                            size_t address_len, ol_ucx_endpoint **out,
                            char *error, size_t error_len) {
    *out = NULL;
    if (address == NULL || address_len == 0) {
        return ol_error(error, error_len, "empty remote worker address",
                        UCS_ERR_INVALID_ADDR);
    }
    ol_ucx_endpoint *endpoint = calloc(1, sizeof(*endpoint));
    if (endpoint == NULL) {
        return ol_error(error, error_len, "allocate UCX endpoint",
                        UCS_ERR_NO_MEMORY);
    }
    endpoint->owner = worker;
    endpoint->status = UCS_OK;

    ucp_ep_params_t params;
    memset(&params, 0, sizeof(params));
    params.field_mask = UCP_EP_PARAM_FIELD_REMOTE_ADDRESS;
    params.address = (const ucp_address_t *)address;
    ucs_status_t status = ucp_ep_create(worker->worker, &params, &endpoint->ep);
    if (status != UCS_OK) {
        free(endpoint);
        return ol_error(error, error_len, "ucp_ep_create", status);
    }
    *out = endpoint;
    return 0;
}

void ol_ucx_endpoint_destroy(ol_ucx_endpoint *endpoint) {
    if (endpoint == NULL) {
        return;
    }
    ucp_ep_destroy(endpoint->ep);
    free(endpoint);
}

int ol_ucx_memory_register(ol_ucx_worker *worker, uint64_t address,
                           uint64_t length, ol_ucx_memory **out,
                           char *error, size_t error_len) {
    *out = NULL;
    if (address == 0 || length == 0) {
        return ol_error(error, error_len, "invalid memory region",
                        UCS_ERR_INVALID_PARAM);
    }
    ol_ucx_memory *memory = calloc(1, sizeof(*memory));
    if (memory == NULL) {
        return ol_error(error, error_len, "allocate UCX memory handle",
                        UCS_ERR_NO_MEMORY);
    }
    memory->owner = worker;

    ucp_mem_map_params_t params;
    memset(&params, 0, sizeof(params));
    params.field_mask = UCP_MEM_MAP_PARAM_FIELD_ADDRESS |
                        UCP_MEM_MAP_PARAM_FIELD_LENGTH;
    params.address = (void *)(uintptr_t)address;
    params.length = (size_t)length;
    ucs_status_t status =
        ucp_mem_map(worker->context, &params, &memory->memh);
    if (status != UCS_OK) {
        free(memory);
        return ol_error(error, error_len, "ucp_mem_map", status);
    }
    *out = memory;
    return 0;
}

void ol_ucx_memory_destroy(ol_ucx_memory *memory) {
    if (memory == NULL) {
        return;
    }
    ucp_mem_unmap(memory->owner->context, memory->memh);
    free(memory);
}

int ol_ucx_memory_pack_rkey(ol_ucx_memory *memory, uint8_t **out,
                            size_t *out_len, char *error, size_t error_len) {
    *out = NULL;
    *out_len = 0;
    void *packed = NULL;
    size_t packed_len = 0;
    ucs_status_t status = ucp_rkey_pack(memory->owner->context, memory->memh,
                                        &packed, &packed_len);
    if (status != UCS_OK) {
        return ol_error(error, error_len, "ucp_rkey_pack", status);
    }
    uint8_t *copy = malloc(packed_len);
    if (copy == NULL) {
        ucp_rkey_buffer_release(packed);
        return ol_error(error, error_len, "copy UCX rkey", UCS_ERR_NO_MEMORY);
    }
    memcpy(copy, packed, packed_len);
    ucp_rkey_buffer_release(packed);
    *out = copy;
    *out_len = packed_len;
    return 0;
}

int ol_ucx_rkey_unpack(ol_ucx_endpoint *endpoint, const uint8_t *packed,
                       size_t packed_len, ol_ucx_rkey **out, char *error,
                       size_t error_len) {
    *out = NULL;
    if (packed == NULL || packed_len == 0) {
        return ol_error(error, error_len, "empty packed UCX rkey",
                        UCS_ERR_INVALID_PARAM);
    }
    ol_ucx_rkey *rkey = calloc(1, sizeof(*rkey));
    if (rkey == NULL) {
        return ol_error(error, error_len, "allocate UCX rkey",
                        UCS_ERR_NO_MEMORY);
    }
    ucs_status_t status =
        ucp_ep_rkey_unpack(endpoint->ep, packed, &rkey->rkey);
    if (status != UCS_OK) {
        free(rkey);
        return ol_error(error, error_len, "ucp_ep_rkey_unpack", status);
    }
    *out = rkey;
    return 0;
}

void ol_ucx_rkey_destroy(ol_ucx_rkey *rkey) {
    if (rkey == NULL) {
        return;
    }
    ucp_rkey_destroy(rkey->rkey);
    free(rkey);
}

int ol_ucx_put(ol_ucx_endpoint *endpoint, uint64_t local_address,
               uint64_t length, uint64_t remote_address,
               ol_ucx_rkey *rkey, char *error, size_t error_len) {
    if (endpoint->status != UCS_OK) {
        return ol_error(error, error_len, "UCX endpoint", endpoint->status);
    }
    ucp_request_param_t params;
    memset(&params, 0, sizeof(params));
    void *request = ucp_put_nbx(endpoint->ep,
                                (const void *)(uintptr_t)local_address,
                                (size_t)length, remote_address, rkey->rkey,
                                &params);
    return ol_wait(endpoint->owner, request, error, error_len, "ucp_put_nbx");
}

int ol_ucx_get(ol_ucx_endpoint *endpoint, uint64_t local_address,
               uint64_t length, uint64_t remote_address,
               ol_ucx_rkey *rkey, char *error, size_t error_len) {
    if (endpoint->status != UCS_OK) {
        return ol_error(error, error_len, "UCX endpoint", endpoint->status);
    }
    ucp_request_param_t params;
    memset(&params, 0, sizeof(params));
    void *request = ucp_get_nbx(endpoint->ep, (void *)(uintptr_t)local_address,
                                (size_t)length, remote_address, rkey->rkey,
                                &params);
    return ol_wait(endpoint->owner, request, error, error_len, "ucp_get_nbx");
}

int ol_ucx_endpoint_flush(ol_ucx_endpoint *endpoint, char *error,
                          size_t error_len) {
    if (endpoint->status != UCS_OK) {
        return ol_error(error, error_len, "UCX endpoint", endpoint->status);
    }
    ucp_request_param_t params;
    memset(&params, 0, sizeof(params));
    void *request = ucp_ep_flush_nbx(endpoint->ep, &params);
    return ol_wait(endpoint->owner, request, error, error_len,
                   "ucp_ep_flush_nbx");
}

int ol_ucx_tag_send(ol_ucx_endpoint *endpoint, const uint8_t *data,
                    size_t length, char *error, size_t error_len) {
    if (endpoint->status != UCS_OK) {
        return ol_error(error, error_len, "UCX endpoint", endpoint->status);
    }
    if (data == NULL || length == 0) {
        return ol_error(error, error_len, "empty UCX control message",
                        UCS_ERR_INVALID_PARAM);
    }
    ucp_request_param_t params;
    memset(&params, 0, sizeof(params));
    void *request = ucp_tag_send_nbx(endpoint->ep, data, length,
                                     OL_UCX_CONTROL_TAG, &params);
    return ol_wait(endpoint->owner, request, error, error_len,
                   "ucp_tag_send_nbx");
}

int ol_ucx_tag_poll(ol_ucx_worker *worker, uint8_t **out, size_t *out_len,
                    char *error, size_t error_len) {
    *out = NULL;
    *out_len = 0;
    ucp_worker_progress(worker->worker);

    ucp_tag_recv_info_t info;
    ucp_tag_message_h message = ucp_tag_probe_nb(
        worker->worker, OL_UCX_CONTROL_TAG, (ucp_tag_t)-1, 1, &info);
    if (message == NULL) {
        return OL_UCX_NO_MESSAGE;
    }

    uint8_t *copy = malloc(info.length == 0 ? 1 : info.length);
    if (copy == NULL) {
        return ol_error(error, error_len, "allocate UCX control message",
                        UCS_ERR_NO_MEMORY);
    }
    ucp_request_param_t params;
    memset(&params, 0, sizeof(params));
    void *request = ucp_tag_msg_recv_nbx(worker->worker, copy, info.length,
                                         message, &params);
    int status = ol_wait(worker, request, error, error_len,
                         "ucp_tag_msg_recv_nbx");
    if (status != 0) {
        free(copy);
        return status;
    }
    *out = copy;
    *out_len = info.length;
    return 0;
}
