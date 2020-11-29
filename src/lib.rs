#[macro_use]
extern crate log;

// we are extending the goblin api, so we export goblins types so
// others will use it directly instead of depending on goblin + metagoblin
pub use goblin::*;

type MRange = memrange::Range;

#[derive(Debug, Clone)]
/// Symbolically tags an address range in a binary
pub enum Tag {
    Meta,
    // TODO: rename this to Load and/or specialize loaded segments
    Code,
    Data,
    Relocation,
    StringTable,
    SymbolTable,
    Zero,
    ASCII,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct MetaData {
    pub tag: Tag,
    pub name: Option<String>,
    pub memory: Option<Segment>,
}

impl MetaData {
    pub fn name(&self) -> Option<&str> {
        if let &Some(ref name) = &self.name {
            Some(name)
        } else {
            None
        }
    }
}

impl<'a> From<&'a goblin::elf::ProgramHeader> for MetaData {
    fn from(phdr: &'a goblin::elf::ProgramHeader) -> Self {
        use goblin::elf::program_header;
        use goblin::elf::program_header::*;
        let mut memory = None;
        let name = Some(program_header::pt_to_str(phdr.p_type).to_string());
        let tag = match phdr.p_type {
            PT_PHDR => Tag::Meta,
            PT_INTERP => Tag::ASCII,
            PT_NOTE => Tag::ASCII,
            PT_DYNAMIC => Tag::Meta,
            PT_LOAD => {
                let permissions = Permissions::from(phdr);
                let segment = Segment::new(permissions);
                memory = Some(segment);
                Tag::Code
            }
            _ => Tag::Unknown,
        };
        MetaData { name, tag, memory }
    }
}

impl<'a> From<&'a goblin::elf::SectionHeader> for MetaData {
    fn from(shdr: &'a goblin::elf::SectionHeader) -> Self {
        use goblin::elf::section_header::*;
        let mut memory = None;
        let name = None;
        let tag = match shdr.sh_type {
            SHT_NOTE => Tag::ASCII,
            SHT_REL | SHT_RELA => Tag::Relocation,
            SHT_DYNAMIC => Tag::Meta,
            SHT_SYMTAB | SHT_DYNSYM => Tag::SymbolTable,
            SHT_STRTAB => Tag::StringTable,
            SHT_NOBITS => {
                let permissions = Permissions::from(shdr);
                let segment = Segment::new(permissions);
                memory = Some(segment);
                Tag::Zero
            }
            SHT_PROGBITS | SHT_FINI_ARRAY | SHT_INIT_ARRAY => {
                let permissions = Permissions::from(shdr);
                let segment = Segment::new(permissions);
                memory = Some(segment);
                Tag::Code
            }
            _ => Tag::Unknown,
        };
        MetaData { name, tag, memory }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Permissions {
    raw_perms: [bool; 3],
}

impl Permissions {
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Permissions {
            raw_perms: [read, write, execute],
        }
    }
    pub fn read(&self) -> bool {
        self.raw_perms[0]
    }
    pub fn write(&self) -> bool {
        self.raw_perms[1]
    }
    pub fn execute(&self) -> bool {
        self.raw_perms[2]
    }
}

impl ::std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        if self.read() {
            write!(f, "R")?;
        }
        if self.write() {
            write!(f, "W")?;
        }
        if self.execute() {
            write!(f, "+X")?;
        }
        Ok(())
    }
}

impl<'a> From<&'a goblin::elf::ProgramHeader> for Permissions {
    fn from(phdr: &'a goblin::elf::ProgramHeader) -> Self {
        Permissions::new(phdr.is_read(), phdr.is_write(), phdr.is_executable())
    }
}

impl<'a> From<&'a goblin::elf::SectionHeader> for Permissions {
    fn from(phdr: &'a goblin::elf::SectionHeader) -> Self {
        Permissions::new(phdr.is_alloc(), phdr.is_writable(), phdr.is_executable())
    }
}

#[derive(Debug, Default, Clone)]
pub struct Segment {
    pub permissions: Permissions,
    pub alignment: Option<usize>,
}

impl Segment {
    pub fn new(permissions: Permissions) -> Self {
        Segment {
            permissions,
            alignment: None,
        }
    }
}

#[derive(Debug)]
pub struct Analysis {
    pub franges: theban_interval_tree::IntervalTree<MetaData>,
    pub memranges: theban_interval_tree::IntervalTree<MetaData>,
}

impl Analysis {
    pub fn new<'a>(goblin: &Object<'a>) -> Self {
        let mut franges = theban_interval_tree::IntervalTree::new();
        let mut memranges = theban_interval_tree::IntervalTree::new();
        match goblin {
            &Object::Elf(ref elf) => {
                for phdr in &elf.program_headers {
                    let range = phdr.file_range();
                    let vmrange = phdr.vm_range();
                    let tag: MetaData = phdr.into();
                    debug!("{:?}", range);
                    franges.insert(
                        MRange::new(range.start as u64, range.end as u64),
                        tag.clone(),
                    );
                    memranges.insert(MRange::new(vmrange.start as u64, vmrange.end as u64), tag);
                }
                for shdr in &elf.section_headers {
                    if shdr.sh_size == 0 {
                        continue;
                    }
                    let range = shdr.file_range();
                    let vmrange = shdr.vm_range();
                    let mut tag = MetaData::from(shdr);
                    // fixme
                    tag.name = elf.shdr_strtab.get_unsafe(shdr.sh_name).map(String::from);
                    debug!("{:?}", range);
                    franges.insert(
                        MRange::new(range.start as u64, range.end as u64),
                        tag.clone(),
                    );
                    memranges.insert(MRange::new(vmrange.start as u64, vmrange.end as u64), tag);
                }
            }
            _ => (),
        }
        Analysis { franges, memranges }
    }
}
