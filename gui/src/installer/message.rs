use liana::miniscript::{
    bitcoin::{bip32::Fingerprint, Network},
    DescriptorPublicKey,
};
use std::path::PathBuf;

use super::{context, Error};
use crate::{
    download::Progress,
    hw::HardwareWalletMessage,
    lianalite::client::{auth::AuthClient, backend::api},
    node::{
        bitcoind::{Bitcoind, ConfigField, RpcAuthType},
        electrum, NodeType,
    },
};
use async_hwi::{DeviceKind, Version};

#[derive(Debug, Clone)]
pub enum Message {
    UserActionDone(bool),
    Exit(PathBuf, Option<Bitcoind>),
    Clibpboard(String),
    Next,
    Skip,
    Previous,
    BackToLauncher(Network),
    Install,
    Close,
    Reload,
    Select(usize),
    UseHotSigner,
    Installed(Result<PathBuf, Error>),
    CreateTaprootDescriptor(bool),
    SelectBackend(SelectBackend),
    ImportRemoteWallet(ImportRemoteWallet),
    SelectBitcoindType(SelectBitcoindTypeMsg),
    InternalBitcoind(InternalBitcoindMsg),
    DefineNode(DefineNode),
    DefineDescriptor(DefineDescriptor),
    ImportXpub(Fingerprint, Result<DescriptorPublicKey, Error>),
    HardwareWallets(HardwareWalletMessage),
    WalletRegistered(Result<(Fingerprint, Option<[u8; 32]>), Error>),
    MnemonicWord(usize, String),
    ImportMnemonic(bool),
}

#[derive(Debug, Clone)]
pub enum SelectBackend {
    // view messages
    RequestOTP,
    EditEmail,
    EmailEdited(String),
    OTPEdited(String),
    ContinueWithLocalWallet(bool),
    // Commands messages
    OTPRequested(Result<(AuthClient, String), Error>),
    OTPResent(Result<(), Error>),
    Connected(Result<context::RemoteBackend, Error>),
}

#[derive(Debug, Clone)]
pub enum ImportRemoteWallet {
    RemoteWallets(Result<Vec<api::Wallet>, Error>),
    ImportDescriptor(String),
    ConfirmDescriptor,
    ImportInvitationToken(String),
    FetchInvitation,
    InvitationFetched(Result<api::WalletInvitation, Error>),
    AcceptInvitation,
    InvitationAccepted(Result<api::Wallet, Error>),
}

#[derive(Debug, Clone)]
pub enum DefineBitcoind {
    ConfigFieldEdited(ConfigField, String),
    RpcAuthTypeSelected(RpcAuthType),
}

#[derive(Debug, Clone)]
pub enum DefineElectrum {
    ConfigFieldEdited(electrum::ConfigField, String),
}

#[derive(Debug, Clone)]
pub enum DefineNode {
    NodeTypeSelected(NodeType),
    DefineBitcoind(DefineBitcoind),
    DefineElectrum(DefineElectrum),
    PingResult((NodeType, Result<(), Error>)),
    Ping,
}

#[derive(Debug, Clone)]
pub enum SelectBitcoindTypeMsg {
    UseExternal(bool),
}

#[derive(Debug, Clone)]
pub enum InternalBitcoindMsg {
    Previous,
    Reload,
    DefineConfig,
    Download,
    DownloadProgressed(Progress),
    Install,
    Start,
}

#[derive(Debug, Clone)]
pub enum DefineDescriptor {
    ImportDescriptor(String),
    PrimaryPath(DefinePath),
    RecoveryPath(usize, DefinePath),
    AddRecoveryPath,
    KeyModal(ImportKeyModal),
    SequenceModal(SequenceModal),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum DefinePath {
    AddKey,
    Key(usize, DefineKey),
    ThresholdEdited(usize),
    SequenceEdited(u16),
    EditSequence,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum DefineKey {
    Delete,
    Edit,
    Clipboard(String),
    Edited(
        String,
        DescriptorPublicKey,
        Option<DeviceKind>,
        Option<Version>,
    ),
}

#[derive(Debug, Clone)]
pub enum ImportKeyModal {
    HWXpubImported(Result<DescriptorPublicKey, Error>),
    XPubEdited(String),
    EditName,
    NameEdited(String),
    ConfirmXpub,
    SelectKey(usize),
}

#[derive(Debug, Clone)]
pub enum SequenceModal {
    SequenceEdited(String),
    ConfirmSequence,
}
