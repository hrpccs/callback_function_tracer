struct test_struct_t {
    // callback
    void (*send)(int);
    void (*recv)(void);
};
enum callback_type {
    IBV_POST_SEND,
    IBV_POST_RECV,
};

struct callback_event {
    unsigned long long callback_vaddr;
    unsigned long long pid_tgid;
    enum callback_type type; 
};

enum event_type {
    IBV_POST_SEND_ENTER,
    IBV_POST_SEND_EXIT,
    IBV_POST_RECV_ENTER,
    IBV_POST_RECV_EXIT,
};

struct event {
    enum event_type type;
    unsigned long long timestamp;
    unsigned long long pid_tgid;
    union { // additional info for each type of event
        struct {
            
        } ibv_post_send_info;

        struct {

        } ibv_post_recv_info;
    };
};