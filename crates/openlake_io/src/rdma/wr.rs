const TAG_SEND:  u64 = 1 << 56;
const TAG_RECV:  u64 = 2 << 56;
const TAG_ACK:   u64 = 3 << 56;
const TAG_CLOSE: u64 = 4 << 56;
const TAG_MASK_64: u64 = 0xFF << 56;

const IMM_TYPE_SHIFT:    u32 = 28;
const IMM_NODE_SHIFT:    u32 = 16;
const IMM_RUNTIME_SHIFT: u32 = 8;
const IMM_TYPE_MASK:     u32 = 0xF;
const IMM_NODE_MASK:     u32 = 0xFFF;
const IMM_RUNTIME_MASK:  u32 = 0xFF;
const IMM_COUNT_MASK:    u32 = 0xFF;

const IMM_TYPE_ACK:   u32 = 1;
const IMM_TYPE_CLOSE: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerKey {
    pub node_id:    u16,
    pub runtime_id: u16,
}

impl PeerKey {
    pub const fn new(node_id: u16, runtime_id: u16) -> Self {
        Self { node_id, runtime_id }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrType { Send, Recv, Ack, Close, Other }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SendKind {
    Other         = 0,
    Unary         = 1,
    ChunkReadReq  = 2,
    ChunkWriteReq = 3,
    Response      = 4,
}
impl SendKind {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => SendKind::Unary,
            2 => SendKind::ChunkReadReq,
            3 => SendKind::ChunkWriteReq,
            4 => SendKind::Response,
            _ => SendKind::Other,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WrId(pub u64);

impl WrId {
    pub fn send(signal_count: u32) -> Self { Self(TAG_SEND | signal_count as u64) }
    pub fn send_with_kind_seq(seq: u64, kind: SendKind) -> Self {
        Self(TAG_SEND | ((kind as u64 & 0xFF) << 48) | (seq & 0x0000_FFFF_FFFF_FFFF))
    }
    pub fn send_kind(self) -> SendKind { SendKind::from_u8(((self.0 >> 48) & 0xFF) as u8) }
    pub fn send_seq(self) -> u64 { self.0 & 0x0000_FFFF_FFFF_FFFF }
    pub fn recv(buf_idx: u32) -> Self { Self(TAG_RECV | buf_idx as u64) }
    pub fn ack()               -> Self { Self(TAG_ACK) }
    pub fn close()             -> Self { Self(TAG_CLOSE) }

    pub fn ty(self) -> WrType {
        match self.0 & TAG_MASK_64 {
            TAG_SEND  => WrType::Send,
            TAG_RECV  => WrType::Recv,
            TAG_ACK   => WrType::Ack,
            TAG_CLOSE => WrType::Close,
            _         => WrType::Other,
        }
    }
    pub fn signal_count(self) -> u32 { (self.0 & 0xFFFFFFFF) as u32 }
    pub fn buf_idx(self)      -> u32 { (self.0 & !TAG_MASK_64) as u32 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImmType { Ack, Close, Other }

#[derive(Clone, Copy, Debug)]
pub struct ImmData(pub u32);

impl ImmData {
    pub fn ack(src: PeerKey, count: u32) -> Self {
        Self((IMM_TYPE_ACK << IMM_TYPE_SHIFT)
           | ((src.node_id    as u32 & IMM_NODE_MASK)    << IMM_NODE_SHIFT)
           | ((src.runtime_id as u32 & IMM_RUNTIME_MASK) << IMM_RUNTIME_SHIFT)
           | (count & IMM_COUNT_MASK))
    }
    pub fn close(src: PeerKey) -> Self {
        Self((IMM_TYPE_CLOSE << IMM_TYPE_SHIFT)
           | ((src.node_id    as u32 & IMM_NODE_MASK)    << IMM_NODE_SHIFT)
           | ((src.runtime_id as u32 & IMM_RUNTIME_MASK) << IMM_RUNTIME_SHIFT))
    }
    pub fn ty(self) -> ImmType {
        match (self.0 >> IMM_TYPE_SHIFT) & IMM_TYPE_MASK {
            IMM_TYPE_ACK   => ImmType::Ack,
            IMM_TYPE_CLOSE => ImmType::Close,
            _              => ImmType::Other,
        }
    }
    pub fn src(self) -> PeerKey {
        PeerKey {
            node_id:    ((self.0 >> IMM_NODE_SHIFT)    & IMM_NODE_MASK)    as u16,
            runtime_id: ((self.0 >> IMM_RUNTIME_SHIFT) & IMM_RUNTIME_MASK) as u16,
        }
    }
    pub fn count(self) -> u32 { self.0 & IMM_COUNT_MASK }
}
