pub enum Check<const CONDITION: bool> {}
pub trait True {}

impl True for Check<true> {}
