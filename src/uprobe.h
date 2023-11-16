enum callback_type {
    IBV_POST_SEND,
    IBV_POST_RECV,
};


struct callback_event {
    unsigned long long callback_vaddr;
    unsigned long long pid_tgid;
    enum callback_type type; 
};


