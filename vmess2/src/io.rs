pub trait ReadExt: std::io::Read {
    fn read_to_end_alloc(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let n = self.read_to_end(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn read_exact_alloc(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(n);
        unsafe { buf.set_len(n) };
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}