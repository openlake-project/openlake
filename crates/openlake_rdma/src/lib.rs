mod completion;
mod error;
mod memory;
mod queue_pair;
mod work;

pub mod backend;

pub use completion::{CompletionQueue, CompletionStatus, WorkCompletion};
pub use error::TransportError;
pub use memory::{AccessFlags, BufferKind, MemoryRegion, ProtectionDomain};
pub use queue_pair::{QpState, QueuePair, TransportType};
pub use work::{Opcode, ScatterGatherEntry, WorkRequest};

pub use backend::loopback::SoftFabric;
pub use backend::Fabric;

pub type Result<T> = core::result::Result<T, TransportError>;
