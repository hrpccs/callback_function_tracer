enum callback_type {
    SEND,
    RECV
};


struct callback_event {
    unsigned long long callback_vaddr;
    unsigned long long pid_tgid;
    enum callback_type type; 
};


