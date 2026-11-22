use crate::encoder::RootPaging;
use crate::kepoch::KepochMode;

pub const FORMAT_VERSION: u16 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FormatConfig {
    pub version: u16,
    pub line_info: bool,
    pub kmode: KepochMode,
    pub frame_const_probe: bool,
    pub framing: bool,
    pub sem_family: bool,
    pub instr_family: bool,
    pub state_family: bool,
    pub vm_traps: bool,
    pub d1: bool,
}

impl FormatConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn layout(
        line_info: bool,
        kmode: KepochMode,
        frame_const_probe: bool,
        framing: bool,
        sem_family: bool,
        instr_family: bool,
        state_family: bool,
    ) -> Self {
        FormatConfig {
            version: FORMAT_VERSION,
            line_info,
            kmode,
            frame_const_probe,
            framing,
            sem_family,
            instr_family,
            state_family,
            vm_traps: false,
            d1: false,
        }
    }

    pub fn feature_bits(&self) -> u32 {
        (self.line_info as u32)
            | (self.frame_const_probe as u32) << 1
            | (self.framing as u32) << 2
            | (self.sem_family as u32) << 3
            | (self.instr_family as u32) << 4
            | (self.state_family as u32) << 5
            | (self.vm_traps as u32) << 6
            | (self.d1 as u32) << 7
            | ((self.kmode as u32) & 0b11) << 9
    }

    pub fn identity(&self) -> FormatIdentity {
        FormatIdentity {
            version: self.version,
            feature_bits: self.feature_bits(),
        }
    }

    pub fn identity_bytes(&self) -> [u8; 6] {
        let mut b = [0u8; 6];
        b[0..2].copy_from_slice(&self.version.to_le_bytes());
        b[2..6].copy_from_slice(&self.feature_bits().to_le_bytes());
        b
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FormatIdentity {
    pub version: u16,
    pub feature_bits: u32,
}

pub const SEALED_VALUE_AD_DOMAIN: &[u8; 5] = b"BSVA2";

pub fn sealed_value_ad(fmt: &FormatConfig, id32: u32, salt: &[u8], class: u8) -> Vec<u8> {
    let mut ad = Vec::with_capacity(SEALED_VALUE_AD_DOMAIN.len() + 6 + 4 + salt.len() + 1);
    ad.extend_from_slice(SEALED_VALUE_AD_DOMAIN);
    ad.extend_from_slice(&fmt.identity_bytes());
    ad.extend_from_slice(&id32.to_le_bytes());
    ad.extend_from_slice(salt);
    ad.push(class);
    ad
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProtoEncodingMode {
    PagedRoot {
        activation_ticket: u32,
    },
    Child {
        patch_instrs: bool,
        ticket: Option<u32>,
        sealed: bool,
    },
    SealedInner,
}

impl ProtoEncodingMode {
    pub fn paging(self) -> RootPaging {
        match self {
            ProtoEncodingMode::PagedRoot { .. } => RootPaging::Paged,
            _ => RootPaging::Unpaged,
        }
    }

    pub fn patch_instrs(self) -> bool {
        match self {
            ProtoEncodingMode::PagedRoot { .. } => true,
            ProtoEncodingMode::Child { patch_instrs, .. } => patch_instrs,
            ProtoEncodingMode::SealedInner => false,
        }
    }

    pub fn parent_ticket(self) -> Option<u32> {
        match self {
            ProtoEncodingMode::PagedRoot { activation_ticket } => Some(activation_ticket),
            ProtoEncodingMode::Child { ticket, .. } => ticket,
            ProtoEncodingMode::SealedInner => None,
        }
    }

    pub fn kmode(self, fmt: &FormatConfig) -> KepochMode {
        match self {
            ProtoEncodingMode::SealedInner => KepochMode::Off,
            ProtoEncodingMode::Child { sealed: true, .. } => KepochMode::Off,
            _ => fmt.kmode,
        }
    }

    pub fn child(self, child_ticket: Option<u32>) -> ProtoEncodingMode {
        match self {
            ProtoEncodingMode::PagedRoot { .. } => ProtoEncodingMode::Child {
                patch_instrs: true,
                ticket: child_ticket,
                sealed: false,
            },
            ProtoEncodingMode::SealedInner => ProtoEncodingMode::Child {
                patch_instrs: false,
                ticket: child_ticket,
                sealed: true,
            },
            ProtoEncodingMode::Child {
                patch_instrs,
                sealed,
                ..
            } => ProtoEncodingMode::Child {
                patch_instrs,
                ticket: child_ticket,
                sealed,
            },
        }
    }

    pub fn is_main_tree(self) -> bool {
        match self {
            ProtoEncodingMode::PagedRoot { .. } => true,
            ProtoEncodingMode::Child { sealed, .. } => !sealed,
            ProtoEncodingMode::SealedInner => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FormatConfig {
        FormatConfig {
            version: FORMAT_VERSION,
            line_info: false,
            kmode: KepochMode::Off,
            frame_const_probe: false,
            framing: false,
            sem_family: false,
            instr_family: false,
            state_family: false,
            vm_traps: false,
            d1: false,
        }
    }

    #[test]
    fn all_off_is_zero_bits() {
        assert_eq!(base().feature_bits(), 0);
    }

    #[test]
    fn each_flag_sets_a_distinct_bit() {
        let fields: &[(fn(&mut FormatConfig), u32)] = &[
            (|c| c.line_info = true, 1 << 0),
            (|c| c.frame_const_probe = true, 1 << 1),
            (|c| c.framing = true, 1 << 2),
            (|c| c.sem_family = true, 1 << 3),
            (|c| c.instr_family = true, 1 << 4),
            (|c| c.state_family = true, 1 << 5),
            (|c| c.vm_traps = true, 1 << 6),
            (|c| c.d1 = true, 1 << 7),
        ];
        for (set, bit) in fields {
            let mut c = base();
            set(&mut c);
            assert_eq!(c.feature_bits(), *bit);
        }
    }

    #[test]
    fn kmode_distinguished_in_bits() {
        let off = base().feature_bits();
        let mut cons = base();
        cons.kmode = KepochMode::Conservative;
        let mut aggr = base();
        aggr.kmode = KepochMode::Aggressive;
        assert_ne!(off, cons.feature_bits());
        assert_ne!(off, aggr.feature_bits());
        assert_ne!(cons.feature_bits(), aggr.feature_bits());
    }

    #[test]
    fn identity_bytes_layout_is_le16_version_then_le32_features() {
        let mut c = base();
        c.version = 2;
        c.sem_family = true;
        let b = c.identity_bytes();
        assert_eq!(&b[0..2], &2u16.to_le_bytes());
        assert_eq!(&b[2..6], &c.feature_bits().to_le_bytes());
    }

    #[test]
    fn identity_changes_with_version_and_each_feature_bit() {
        let mut a = base();
        a.version = 2;
        let mut b = base();
        b.version = 3;
        assert_ne!(a.identity_bytes(), b.identity_bytes());
        let mut f = a;
        f.instr_family = true;
        assert_ne!(a.identity_bytes(), f.identity_bytes());
    }

    #[test]
    fn sealed_value_ad_is_fixed_width_and_domain_separated() {
        let mut c = base();
        c.version = 2;
        let salt = [7u8; 12];
        let ad = sealed_value_ad(&c, 0x0A0B0C0D, &salt, 2);
        assert_eq!(ad.len(), 5 + 6 + 4 + 12 + 1);
        assert_eq!(&ad[0..5], SEALED_VALUE_AD_DOMAIN);
        assert_eq!(&ad[5..11], &c.identity_bytes());
        assert_eq!(&ad[11..15], &0x0A0B0C0Du32.to_le_bytes());
        assert_eq!(&ad[15..27], &salt);
        assert_eq!(ad[27], 2);
        let mut d = c;
        d.sem_family = true;
        assert_ne!(sealed_value_ad(&d, 0x0A0B0C0D, &salt, 2), ad);
    }

    use proptest::prelude::*;

    fn arb_fmt() -> impl Strategy<Value = FormatConfig> {
        (
            any::<u16>(),
            prop_oneof![
                Just(KepochMode::Off),
                Just(KepochMode::Conservative),
                Just(KepochMode::Aggressive)
            ],
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(version, kmode, line_info, fcp, framing, sem, instr, state, vmt, d1)| {
                    FormatConfig {
                        version,
                        line_info,
                        kmode,
                        frame_const_probe: fcp,
                        framing,
                        sem_family: sem,
                        instr_family: instr,
                        state_family: state,
                        vm_traps: vmt,
                        d1,
                    }
                },
            )
    }

    proptest! {
        #[test]
        fn prop_identity_bytes_layout(fmt in arb_fmt()) {
            let b = fmt.identity_bytes();
            prop_assert_eq!(&b[0..2], &fmt.version.to_le_bytes());
            prop_assert_eq!(&b[2..6], &fmt.feature_bits().to_le_bytes());
            prop_assert_eq!(fmt.identity().version, fmt.version);
            prop_assert_eq!(fmt.identity().feature_bits, fmt.feature_bits());
        }

        #[test]
        fn prop_sealed_ad_fixed_layout(fmt in arb_fmt(), id in any::<u32>(), class in any::<u8>()) {
            let salt = [5u8; 12];
            let ad = sealed_value_ad(&fmt, id, &salt, class);
            prop_assert_eq!(ad.len(), 5 + 6 + 4 + 12 + 1);
            prop_assert_eq!(&ad[0..5], SEALED_VALUE_AD_DOMAIN);
            prop_assert_eq!(&ad[5..11], &fmt.identity_bytes());
            prop_assert_eq!(&ad[11..15], &id.to_le_bytes());
            prop_assert_eq!(ad[27], class);
            prop_assert_eq!(sealed_value_ad(&fmt, id, &salt, class), ad);
        }

        #[test]
        fn prop_identity_change_changes_ad(fmt in arb_fmt(), id in any::<u32>()) {
            let salt = [1u8; 12];
            let base_ad = sealed_value_ad(&fmt, id, &salt, 0);
            let mut flipped = fmt;
            flipped.instr_family = !flipped.instr_family;
            prop_assert_ne!(flipped.feature_bits(), fmt.feature_bits());
            prop_assert_ne!(sealed_value_ad(&flipped, id, &salt, 0), base_ad);
        }
    }

    #[test]
    fn mismatched_identity_fails_aead_open() {
        use crate::aead;
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let salt = [3u8; 12];
        let body = b"a serialized proto payload";
        let mut a = base();
        a.version = 2;
        a.sem_family = true;

        let ad = sealed_value_ad(&a, 5, &salt, 0);
        let blob = aead::seal(&key, &nonce, &ad, body);
        assert_eq!(
            aead::open(&key, &ad, &blob).as_deref(),
            Some(&body[..]),
            "correct identity opens"
        );

        let mut flip = a;
        flip.instr_family = true;
        assert_eq!(
            aead::open(&key, &sealed_value_ad(&flip, 5, &salt, 0), &blob),
            None,
            "flipped feature bit -> open fails"
        );

        let mut ver = a;
        ver.version = 3;
        assert_eq!(
            aead::open(&key, &sealed_value_ad(&ver, 5, &salt, 0), &blob),
            None,
            "changed version -> open fails"
        );
    }

    #[test]
    fn truncated_or_wrong_domain_ad_fails_open() {
        use crate::aead;
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let salt = [3u8; 12];
        let mut a = base();
        a.version = 2;
        let body = b"payload";
        let ad = sealed_value_ad(&a, 5, &salt, 0);
        let blob = aead::seal(&key, &nonce, &ad, body);

        let mut trunc = ad.clone();
        trunc.pop();
        assert_eq!(
            aead::open(&key, &trunc, &blob),
            None,
            "truncated AD -> open fails"
        );
    }

    #[test]
    fn paged_root_mode() {
        let m = ProtoEncodingMode::PagedRoot {
            activation_ticket: 7,
        };
        assert_eq!(m.paging(), RootPaging::Paged);
        assert!(m.patch_instrs());
        assert_eq!(m.parent_ticket(), Some(7));
        assert_eq!(
            m.kmode(&{
                let mut c = base();
                c.kmode = KepochMode::Aggressive;
                c
            }),
            KepochMode::Aggressive
        );
    }

    #[test]
    fn sealed_inner_mode() {
        let m = ProtoEncodingMode::SealedInner;
        assert_eq!(m.paging(), RootPaging::Unpaged);
        assert!(!m.patch_instrs());
        assert_eq!(m.parent_ticket(), None);
        let mut c = base();
        c.kmode = KepochMode::Aggressive;
        assert_eq!(m.kmode(&c), KepochMode::Off);
    }

    #[test]
    fn child_inherits_patch_ticket_and_sealed() {
        let mut c = base();
        c.kmode = KepochMode::Aggressive;

        let root = ProtoEncodingMode::PagedRoot {
            activation_ticket: 3,
        };
        let child = root.child(Some(9));
        assert_eq!(child.paging(), RootPaging::Unpaged);
        assert!(child.patch_instrs());
        assert_eq!(child.parent_ticket(), Some(9));
        assert_eq!(child.kmode(&c), KepochMode::Aggressive);
        assert_eq!(child.child(Some(5)).kmode(&c), KepochMode::Aggressive);

        let sealed = ProtoEncodingMode::SealedInner;
        let schild = sealed.child(None);
        assert!(!schild.patch_instrs());
        assert_eq!(schild.parent_ticket(), None);
        assert_eq!(schild.kmode(&c), KepochMode::Off);
        assert_eq!(schild.child(None).kmode(&c), KepochMode::Off);
    }
}
