const TAG_SHIFT: u32 = 24;
const TAG_MASK_32: u32 = (1 << TAG_SHIFT) - 1;
const TAG_SEND:  u64 = 1 << 56;
const TAG_RECV:  u64 = 2 << 56;
const TAG_ACK:   u64 = 3 << 56;
const TAG_CLOSE: u64 = 4 << 56;
const TAG_MASK_64: u64 = 0xFF << 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrType { Send, Recv, Ack, Close, Other }

#[derive(Clone, Copy, Debug)]
pub struct WrId(pub u64);

impl WrId {
    pub fn send(signal_count: u32) -> Self { Self(TAG_SEND | signal_count as u64) }
    pub fn recv(buf_idx: u32)      -> Self { Self(TAG_RECV | buf_idx as u64) }
    pub fn ack()                   -> Self { Self(TAG_ACK) }
    pub fn close()                 -> Self { Self(TAG_CLOSE) }

    pub fn ty(self) -> WrType {
        match self.0 & TAG_MASK_64 {
            TAG_SEND  => WrType::Send,
            TAG_RECV  => WrType::Recv,
            TAG_ACK   => WrType::Ack,
            TAG_CLOSE => WrType::Close,
            _         => WrType::Other,
        }
    }
    pub fn signal_count(self) -> u32 { (self.0 & !TAG_MASK_64) as u32 }
    pub fn buf_idx(self)      -> u32 { (self.0 & !TAG_MASK_64) as u32 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImmType { Ack, Close, Other }

#[derive(Clone, Copy, Debug)]
pub struct ImmData(pub u32);

impl ImmData {
    pub fn ack(count: u32)   -> Self { Self((1 << TAG_SHIFT) | (count & TAG_MASK_32)) }
    pub fn close()           -> Self { Self(2 << TAG_SHIFT) }
    pub fn ty(self) -> ImmType {
        match self.0 >> TAG_SHIFT {
            1 => ImmType::Ack,
            2 => ImmType::Close,
            _ => ImmType::Other,
        }
    }
    pub fn data(self) -> u32 { self.0 & TAG_MASK_32 }
}
