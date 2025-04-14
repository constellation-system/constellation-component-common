use std::io::Result;
use std::io::Write;
use std::fs::File;
use std::path::Path;

use asn1rs::converter::Converter;
use asn1rs::gen::rust::RustCodeGenerator;

fn load_files(
    dir: &Path,
    converter: &mut Converter
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            load_files(&path, converter)?;
        } else {
            match path.as_os_str().to_os_string().into_string() {
                Ok(path) if path.ends_with(".asn1") => {
                    println!("cargo:rerun-if-changed={}", &path);

                    if let Err(e) = converter.load_file(&path) {
                        panic!("Couldn't load {}: {:?}", &path, e);
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}

const VERSION_IMPORT: &str = "pub use constellation_common::version::Version;";

pub fn main() {
    let mut converter = Converter::default();

    load_files(Path::new("./src/asn1"), &mut converter)
        .expect("Error loading ASN.1 files");

    let generated = Path::new("src/generated");

    if !generated.is_dir() {
        std::fs::create_dir(generated).expect("Could not create directory");
    }

    if let Err(e) =
        converter.to_rust(generated, |gen: &mut RustCodeGenerator| {
            gen.add_global_derive("serde::Deserialize");
            gen.add_global_derive("serde::Serialize");
        })
    {
        panic!("Error generating rust: {:?}", e);
    }

    // XXX workaround to asn1rs' inability to have explicit tags.
    match File::create(Path::new("src/generated/version.rs")) {
        Ok(mut file) => if let Err(e) = write!(file, "{}\n", VERSION_IMPORT) {
            panic!("Error generating rust import: {:?}", e)
        },
        Err(e) => panic!("Error generating rust import: {:?}", e)
    }
}
