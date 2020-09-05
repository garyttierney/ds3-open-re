use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, Lines};

#[derive(Default, Debug)]
pub struct TestVector {
    pub id: String,
    pub key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub additional_data: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn parse_fields<I>(lines: &mut Lines<I>) -> Option<HashMap<String, String>>
where
    I: BufRead,
{
    let mut map = HashMap::new();
    loop {
        let line = match lines.next() {
            Some(l) => l.ok()?,
            None => return Some(map),
        };

        if line.trim().is_empty() {
            break;
        }

        let mut tokens = line.split_ascii_whitespace();
        let (kw, data) = (tokens.next().unwrap(), tokens.next().unwrap());

        map.insert(kw.to_ascii_lowercase(), data.to_string());
    }

    Some(map)
}

pub fn parse_test_vector<I>(lines: &mut Lines<I>) -> Option<TestVector>
where
    I: BufRead,
{
    let fields = parse_fields(lines)?;
    let id = fields.get("vec")?.clone();
    let key = hex::decode(fields.get("key")?).ok()?;
    let additional_data = fields
        .get("hdr")
        .map(|d| hex::decode(d).unwrap())
        .unwrap_or_default();

    let nonce = hex::decode(fields.get("iv").unwrap()).unwrap();
    let plaintext = hex::decode(fields.get("ptx").unwrap()).unwrap();
    let ciphertext = hex::decode(fields.get("ctx").unwrap()).unwrap();
    let tag = hex::decode(fields.get("tag").unwrap()).unwrap();

    Some(TestVector {
        id,
        key,
        nonce,
        plaintext,
        ciphertext,
        tag,
        additional_data,
    })
}

pub fn parse_test_vectors<I>(input: I) -> Result<Vec<TestVector>, Box<dyn Error>>
where
    I: BufRead,
{
    let mut vectors = vec![];
    let mut lines = input.lines();

    while let Some(vector) = parse_test_vector(&mut lines) {
        vectors.push(vector);
    }

    Ok(vectors)
}
