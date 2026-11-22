#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IKind {
    Global,
    Method,
}

pub const INTRINSICS: &[(&str, IKind)] = &[
    ("game", IKind::Global),
    ("Instance", IKind::Global),
    ("Vector3", IKind::Global),
    ("CFrame", IKind::Global),
    ("typeof", IKind::Global),
    ("GetService", IKind::Method),
    ("GetAttribute", IKind::Method),
    ("SetAttribute", IKind::Method),
    ("IsA", IKind::Method),
    ("GetFullName", IKind::Method),
    ("Dot", IKind::Method),
    ("Cross", IKind::Method),
    ("Inverse", IKind::Method),
    ("VectorToWorldSpace", IKind::Method),
];

pub fn global_id(name: &str) -> Option<u32> {
    id_of(name, IKind::Global)
}

pub fn method_id(name: &str) -> Option<u32> {
    id_of(name, IKind::Method)
}

fn id_of(name: &str, kind: IKind) -> Option<u32> {
    INTRINSICS
        .iter()
        .position(|(n, k)| *n == name && *k == kind)
        .map(|i| i as u32)
}

pub fn name_of(id: u32) -> Option<&'static str> {
    INTRINSICS.get(id as usize).map(|(n, _)| *n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_kinds_are_distinct() {
        assert_eq!(name_of(global_id("game").unwrap()), Some("game"));
        assert_eq!(
            name_of(method_id("GetService").unwrap()),
            Some("GetService")
        );
        assert_eq!(global_id("GetService"), None);
        assert_eq!(method_id("game"), None);
        assert_eq!(global_id("workspace"), None);
        assert_eq!(method_id("customMethod"), None);
    }

    #[test]
    fn every_id_maps_back_to_its_name() {
        for (i, (name, _)) in INTRINSICS.iter().enumerate() {
            assert_eq!(name_of(i as u32), Some(*name));
        }
        assert_eq!(name_of(INTRINSICS.len() as u32), None);
    }
}
