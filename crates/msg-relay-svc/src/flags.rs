use url::Url;

xflags::xflags! {
    cmd msg-relay-svc {
        /// One or more address to listen on.
        /// Address in form ip:port.
        repeated --listen listen: String

        /// One or more peer endpoints.
        repeated --peer listen: Url

        /// Size of internal queue of ASK messages.
        /// If a peer is not ready (unavailable or busy)
        /// and output queue is full, the service will
        /// drop ASK message.
        ///
        /// Default size of 200 messages
        optional --queue-size queue_size: usize
    }
}
