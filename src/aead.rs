pub trait Algorithm {
    fn nonce_len(&self) -> usize;

    fn tag_len(&self) -> usize;
}
