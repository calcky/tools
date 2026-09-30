use flate2::read::GzDecoder;
use prost::Message;
use std::{collections::HashMap, io::Read};

pub const MAX_BODY: usize = 32 * 1024 * 1024;
const MAX_SAMPLES: usize = 300_000;

#[derive(Clone, PartialEq, Message)]
pub struct ValueType {
    #[prost(int64, tag = "1")]
    pub ty: i64,
    #[prost(int64, tag = "2")]
    pub unit: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct Sample {
    #[prost(uint64, repeated, tag = "1")]
    pub location_id: Vec<u64>,
    #[prost(int64, repeated, tag = "2")]
    pub value: Vec<i64>,
}
#[derive(Clone, PartialEq, Message)]
pub struct Location {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(message, repeated, tag = "4")]
    pub line: Vec<Line>,
}
#[derive(Clone, PartialEq, Message)]
pub struct Line {
    #[prost(uint64, tag = "1")]
    pub function_id: u64,
    #[prost(int64, tag = "2")]
    pub line: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct Function {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(int64, tag = "2")]
    pub name: i64,
    #[prost(int64, tag = "4")]
    pub filename: i64,
}
#[derive(Clone, PartialEq, Message)]
pub struct Profile {
    #[prost(message, repeated, tag = "1")]
    pub sample_type: Vec<ValueType>,
    #[prost(message, repeated, tag = "2")]
    pub sample: Vec<Sample>,
    #[prost(message, repeated, tag = "4")]
    pub location: Vec<Location>,
    #[prost(message, repeated, tag = "5")]
    pub function: Vec<Function>,
    #[prost(string, repeated, tag = "6")]
    pub string_table: Vec<String>,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Values {
    pub inuse_bytes: i64,
    pub inuse_objects: i64,
    pub alloc_bytes: i64,
    pub alloc_objects: i64,
}
impl Values {
    fn add(&mut self, other: Self) {
        self.inuse_bytes = self.inuse_bytes.saturating_add(other.inuse_bytes);
        self.inuse_objects = self.inuse_objects.saturating_add(other.inuse_objects);
        self.alloc_bytes = self.alloc_bytes.saturating_add(other.alloc_bytes);
        self.alloc_objects = self.alloc_objects.saturating_add(other.alloc_objects);
    }
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub stacks: HashMap<String, Values>,
    pub total: Values,
}

fn string(table: &[String], index: i64) -> Result<&str, String> {
    let index: usize = index.try_into().map_err(|_| "negative string index")?;
    table
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("invalid string index {index}"))
}

pub fn decode(bytes: &[u8]) -> Result<Snapshot, String> {
    if bytes.len() > MAX_BODY {
        return Err("profile exceeds 32 MiB limit".into());
    }
    let body = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        GzDecoder::new(bytes)
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut decoded)
            .map_err(|e| format!("gzip: {e}"))?;
        if decoded.len() > MAX_BODY {
            return Err("decompressed profile exceeds 32 MiB limit".into());
        }
        decoded
    } else {
        bytes.to_vec()
    };
    let profile = Profile::decode(body.as_slice()).map_err(|e| format!("protobuf: {e}"))?;
    if profile.sample.len() > MAX_SAMPLES {
        return Err("profile exceeds 300000 samples".into());
    }
    let mut types = HashMap::new();
    for (index, ty) in profile.sample_type.iter().enumerate() {
        let name = string(&profile.string_table, ty.ty)?;
        let unit = string(&profile.string_table, ty.unit)?;
        types.insert(name, (index, unit));
    }
    let mut indexes = [0; 4];
    for (position, (name, unit)) in [
        ("inuse_space", "bytes"),
        ("inuse_objects", "count"),
        ("alloc_space", "bytes"),
        ("alloc_objects", "count"),
    ]
    .iter()
    .enumerate()
    {
        match types.get(name) {
            Some((index, found)) if found == unit => indexes[position] = *index,
            _ => return Err(format!("heap profile missing {name}/{unit}")),
        }
    }
    let functions: HashMap<_, _> = profile.function.iter().map(|f| (f.id, f)).collect();
    let locations: HashMap<_, _> = profile.location.iter().map(|l| (l.id, l)).collect();
    let mut snapshot = Snapshot::default();
    for sample in &profile.sample {
        let numbers: Vec<_> = indexes
            .iter()
            .map(|index| {
                sample
                    .value
                    .get(*index)
                    .copied()
                    .ok_or("short sample value")
            })
            .collect::<Result<_, _>>()?;
        let values = Values {
            inuse_bytes: numbers[0],
            inuse_objects: numbers[1],
            alloc_bytes: numbers[2],
            alloc_objects: numbers[3],
        };
        let mut frames = Vec::new();
        for id in &sample.location_id {
            let location = locations.get(id).ok_or("missing location")?;
            for line in &location.line {
                let function = functions.get(&line.function_id).ok_or("missing function")?;
                let name = string(&profile.string_table, function.name)?;
                let file = string(&profile.string_table, function.filename)?;
                frames.push(format!("{name} ({file})"));
            }
        }
        if frames.is_empty() {
            frames.push("[unknown stack]".into());
        }
        let key = frames.join("\n");
        snapshot.stacks.entry(key).or_default().add(values);
        snapshot.total.add(values);
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        Profile {
            string_table: vec![
                "",
                "inuse_space",
                "bytes",
                "inuse_objects",
                "count",
                "alloc_space",
                "alloc_objects",
                "main.allocate",
                "main.go",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            sample_type: vec![(1, 2), (3, 4), (5, 2), (6, 4)]
                .into_iter()
                .map(|(ty, unit)| ValueType { ty, unit })
                .collect(),
            function: vec![Function {
                id: 1,
                name: 7,
                filename: 8,
            }],
            location: vec![Location {
                id: 1,
                line: vec![Line {
                    function_id: 1,
                    line: 10,
                }],
            }],
            sample: vec![
                Sample {
                    location_id: vec![1],
                    value: vec![100, 2, 200, 4],
                },
                Sample {
                    location_id: vec![1],
                    value: vec![50, 1, 60, 2],
                },
            ],
        }
        .encode_to_vec()
    }
    #[test]
    fn aggregates_same_stack_and_rejects_bad_data() {
        let result = decode(&fixture()).unwrap();
        assert_eq!(result.stacks.len(), 1);
        assert_eq!(result.total.inuse_bytes, 150);
        assert_eq!(result.total.alloc_objects, 6);
        assert!(decode(&[0xff, 0xff]).is_err());
        let mut profile = Profile::decode(fixture().as_slice()).unwrap();
        profile.sample_type.pop();
        assert!(decode(&profile.encode_to_vec())
            .unwrap_err()
            .contains("alloc_objects"));
    }
}
