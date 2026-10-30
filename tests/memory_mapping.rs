use solana_sbpf::{
    ebpf,
    memory_region::{
        default_access_violation_handler, AccessType, AlignedMemoryMapping, HostBuffer,
        MappingCache, MemoryMapping, MemoryMappingType, MemoryRegion,
    },
    program::SBPFVersion,
    vm::Config,
};
use std::{cell::RefCell, rc::Rc};
use test_utils::assert_error;

#[test]
fn test_mapping_cache() {
    let mut cache = MappingCache::new();
    assert_eq!(cache.find(0), None);

    let mut ranges = vec![10u64..20, 20..30, 30..40, 40..50];
    for (region, range) in ranges.iter().cloned().enumerate() {
        cache.insert(range, region);
    }
    for (region, range) in ranges.iter().enumerate() {
        if region > 0 {
            assert_eq!(cache.find(range.start - 1), Some(region - 1));
        } else {
            assert_eq!(cache.find(range.start - 1), None);
        }
        assert_eq!(cache.find(range.start), Some(region));
        assert_eq!(cache.find(range.start + 1), Some(region));
        assert_eq!(cache.find(range.end - 1), Some(region));
        if region < 3 {
            assert_eq!(cache.find(range.end), Some(region + 1));
        } else {
            assert_eq!(cache.find(range.end), None);
        }
    }

    cache.insert(50..60, 4);
    ranges.push(50..60);
    for (region, range) in ranges.iter().enumerate() {
        if region == 0 {
            assert_eq!(cache.find(range.start), None);
            continue;
        }
        if region > 1 {
            assert_eq!(cache.find(range.start - 1), Some(region - 1));
        } else {
            assert_eq!(cache.find(range.start - 1), None);
        }
        assert_eq!(cache.find(range.start), Some(region));
        assert_eq!(cache.find(range.start + 1), Some(region));
        assert_eq!(cache.find(range.end - 1), Some(region));
        if region < 4 {
            assert_eq!(cache.find(range.end), Some(region + 1));
        } else {
            assert_eq!(cache.find(range.end), None);
        }
    }
}

#[test]
fn test_mapping_cache_flush() {
    let mut cache = MappingCache::new();
    assert_eq!(cache.find(0), None);
    cache.insert(0..10, 0);
    assert_eq!(cache.find(0), Some(0));
    cache.flush();
    assert_eq!(cache.find(0), None);
}

#[test]
fn test_map_empty() {
    for aligned_memory_mapping in [false, true] {
        let config = Config {
            aligned_memory_mapping,
            ..Config::default()
        };
        let m = unsafe { MemoryMapping::new(vec![], &config, SBPFVersion::V3) }.unwrap();
        assert_error!(
            m.map(AccessType::Load, ebpf::MM_REGION_SIZE, 8),
            "AccessViolation"
        );
    }
}

#[test]
fn test_gapped_map() {
    for aligned_memory_mapping in [false, true] {
        let config = Config {
            aligned_memory_mapping,
            ..Config::default()
        };
        let mut mem1 = [0xff; 8];
        let mem2 = [0; 8];
        let mut m = unsafe {
            MemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const mem2[..], ebpf::MM_REGION_SIZE),
                    MemoryRegion::new_gapped(&raw mut mem1[..], ebpf::MM_REGION_SIZE * 2, 2),
                ],
                &config,
                SBPFVersion::V3,
            )
            .unwrap()
        };
        for frame in 0..4 {
            let address = ebpf::MM_STACK_START + frame * 4;
            assert!(m.find_region(address).is_some());
            assert!(m.map(AccessType::Load, address, 2).is_ok());
            assert_error!(m.map(AccessType::Load, address + 2, 2), "AccessViolation");
            assert_eq!(m.load_first_attempt::<u16>(address).unwrap(), 0xFFFF);
            assert_error!(m.load_first_attempt::<u16>(address + 2), "AccessViolation");
            assert!(m.store_first_attempt::<u16>(0xFFFF, address).is_ok());
            assert_error!(
                m.store_first_attempt::<u16>(0xFFFF, address + 2),
                "AccessViolation"
            );
        }
    }
}

#[test]
fn test_unaligned_map_overlap() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mem1 = [1, 2, 3, 4];
    let mem2 = [5, 6];
    assert_error!(
        unsafe {
            MemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                    MemoryRegion::new(
                        &raw const mem2,
                        ebpf::MM_REGION_SIZE + mem1.len() as u64 - 1,
                    ),
                ],
                &config,
                SBPFVersion::V3,
            )
        },
        "InvalidMemoryRegion(1)"
    );
    assert!(unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            ],
            &config,
            SBPFVersion::V3,
        )
    }
    .is_ok());
}

#[test]
fn test_unaligned_map() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mut mem1 = [11];
    let mem2 = [22, 22];
    let mem3 = [33];
    let mem4 = [44, 44];
    let m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
                MemoryRegion::new(
                    &raw const mem3,
                    ebpf::MM_REGION_SIZE + (mem1.len() + mem2.len()) as u64,
                ),
                MemoryRegion::new(
                    &raw const mem4,
                    ebpf::MM_REGION_SIZE + (mem1.len() + mem2.len() + mem3.len()) as u64,
                ),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };

    assert_eq!(
        m.map(AccessType::Load, ebpf::MM_REGION_SIZE, 1)
            .unwrap()
            .ptr()
            .addr(),
        mem1.as_ptr().addr()
    );

    assert_eq!(
        m.map(AccessType::Store, ebpf::MM_REGION_SIZE, 1)
            .unwrap()
            .ptr()
            .addr(),
        mem1.as_ptr().addr()
    );

    assert_error!(
        m.map(AccessType::Load, ebpf::MM_REGION_SIZE, 2),
        "AccessViolation"
    );

    assert_eq!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + mem1.len() as u64,
            1,
        )
        .unwrap()
        .ptr()
        .addr(),
        mem2.as_ptr().addr()
    );

    assert_eq!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + (mem1.len() + mem2.len()) as u64,
            1,
        )
        .unwrap()
        .ptr()
        .addr(),
        mem3.as_ptr().addr()
    );

    assert_eq!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + (mem1.len() + mem2.len() + mem3.len()) as u64,
            1,
        )
        .unwrap()
        .ptr()
        .addr(),
        mem4.as_ptr().addr()
    );

    assert_error!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + (mem1.len() + mem2.len() + mem3.len() + mem4.len()) as u64,
            1,
        ),
        "AccessViolation"
    );
}

#[test]
fn test_unaligned_region() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };

    let mut mem1 = [0xFF; 4];
    let mem2 = [0xDD; 4];
    let m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + 4),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    assert!(m.find_region(ebpf::MM_REGION_SIZE - 1).is_none());
    assert_eq!(
        HostBuffer::Mutable(&raw mut mem1[..]),
        m.find_region(ebpf::MM_REGION_SIZE).unwrap().1.host,
    );
    assert_eq!(
        HostBuffer::Mutable(&raw mut mem1[..]),
        m.find_region(ebpf::MM_REGION_SIZE + 3).unwrap().1.host,
    );
    assert_eq!(
        HostBuffer::Immutable(&raw const mem2[..]),
        m.find_region(ebpf::MM_REGION_SIZE + 4).unwrap().1.host,
    );
    assert_eq!(
        HostBuffer::Immutable(&raw const mem2[..]),
        m.find_region(ebpf::MM_REGION_SIZE + 7).unwrap().1.host,
    );
    assert!(m.find_region(ebpf::MM_REGION_SIZE + 8).is_some());
}

#[test]
fn test_aligned_region() {
    let config = Config {
        aligned_memory_mapping: true,
        ..Config::default()
    };

    let mut mem1 = [0xFF; 4];
    let mem2 = [0xDD; 4];
    let m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE * 2),
            ],
            &config,
            SBPFVersion::V4,
        )
        .unwrap()
    };
    assert_eq!(m.find_region(ebpf::MM_REGION_SIZE - 1).unwrap().1.len(), 0);
    assert_eq!(
        HostBuffer::Mutable(&raw mut mem1[..]),
        m.find_region(ebpf::MM_REGION_SIZE).unwrap().1.host,
    );
    assert_eq!(
        HostBuffer::Mutable(&raw mut mem1[..]),
        m.find_region(ebpf::MM_REGION_SIZE + 3).unwrap().1.host,
    );
    assert!(m.find_region(ebpf::MM_REGION_SIZE + 4).is_some());
    assert_eq!(
        HostBuffer::Immutable(&raw const mem2[..]),
        m.find_region(ebpf::MM_REGION_SIZE * 2).unwrap().1.host,
    );
    assert_eq!(
        HostBuffer::Immutable(&raw const mem2[..]),
        m.find_region(ebpf::MM_REGION_SIZE * 2 + 3).unwrap().1.host,
    );
    assert!(m.find_region(ebpf::MM_REGION_SIZE * 3 + 4).is_none());
}

#[test]
fn test_unaligned_map_load() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mem1 = [0x11, 0x22];
    let mem2 = [0x33];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };

    assert_eq!(
        m.load_first_attempt::<u16>(ebpf::MM_REGION_SIZE).unwrap(),
        0x2211
    );
    assert_error!(
        m.load_first_attempt::<u32>(ebpf::MM_REGION_SIZE),
        "AccessViolation"
    );
    assert_error!(
        m.load_first_attempt::<u32>(ebpf::MM_REGION_SIZE + 4),
        "AccessViolation"
    );
}

#[test]
fn test_unaligned_map_store() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mut mem1 = [0xff, 0xff];
    let mut mem2 = [0xff];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw mut mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };

    m.store_first_attempt(0x1122u16, ebpf::MM_REGION_SIZE)
        .unwrap();
    assert_eq!(
        m.load_first_attempt::<u16>(ebpf::MM_REGION_SIZE).unwrap(),
        0x1122
    );

    assert_error!(
        m.store_first_attempt(0x33445566u32, ebpf::MM_REGION_SIZE),
        "AccessViolation"
    );
}

#[test]
fn test_unaligned_map_store_out_of_bounds() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };

    let mut mem1 = [0xFF];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE)],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    m.store_first_attempt(0x11u8, ebpf::MM_REGION_SIZE).unwrap();
    assert_error!(
        m.store_first_attempt(0x11u8, ebpf::MM_REGION_SIZE - 1),
        "AccessViolation"
    );
    assert_error!(
        m.store_first_attempt(0x11u8, ebpf::MM_REGION_SIZE + 1),
        "AccessViolation"
    );
    // this gets us line coverage for the case where we're completely
    // outside the address space (the case above is just on the edge)
    assert_error!(
        m.store_first_attempt(0x11u8, ebpf::MM_REGION_SIZE + 2),
        "AccessViolation"
    );

    let mut mem1 = [0xFF; 4];
    let mut mem2 = [0xDD; 4];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw mut mem2, ebpf::MM_REGION_SIZE + 4),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    assert_error!(
        m.store_first_attempt(0x1122334455667788u64, ebpf::MM_REGION_SIZE),
        "AccessViolation"
    );
}

#[test]
fn test_unaligned_map_load_out_of_bounds() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };

    let mem1 = [0xff];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE)],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    assert_eq!(
        m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE).unwrap(),
        0xff
    );
    assert_error!(
        m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE - 1),
        "AccessViolation"
    );
    assert_error!(
        m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE + 1),
        "AccessViolation"
    );
    assert_error!(
        m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE + 2),
        "AccessViolation"
    );

    let mem1 = [0xFF; 4];
    let mem2 = [0xDD; 4];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + 4),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    assert_error!(
        m.load_first_attempt::<u64>(ebpf::MM_REGION_SIZE),
        "AccessViolation"
    );
}

#[test]
#[should_panic(expected = "AccessViolation")]
fn test_store_readonly() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mut mem1 = [0xff, 0xff];
    let mem2 = [0xff, 0xff];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw mut mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    m.store_first_attempt(0x11223344, ebpf::MM_REGION_SIZE)
        .unwrap();
}

#[test]
fn test_unaligned_map_replace_region() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };
    let mem1 = [11];
    let mem2 = [22, 22];
    let mem3 = [33];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };

    assert_eq!(
        m.map(AccessType::Load, ebpf::MM_REGION_SIZE, 1)
            .unwrap()
            .ptr()
            .addr(),
        mem1.as_ptr().addr()
    );

    assert_eq!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + mem1.len() as u64,
            1,
        )
        .unwrap()
        .ptr()
        .addr(),
        mem2.as_ptr().addr()
    );

    assert_error!(
        unsafe {
            m.replace_region(
                2,
                MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE + mem1.len() as u64),
            )
        },
        "InvalidMemoryRegion(2)"
    );

    let region_index = m
        .get_regions()
        .iter()
        .position(|mem| mem.vm_addr == ebpf::MM_REGION_SIZE + mem1.len() as u64)
        .unwrap();

    // old.vm_addr != new.vm_addr
    assert_error!(
        unsafe {
            m.replace_region(
                region_index,
                MemoryRegion::new(
                    &raw const mem3,
                    ebpf::MM_REGION_SIZE + mem1.len() as u64 + 1,
                ),
            )
        },
        "InvalidMemoryRegion({})",
        region_index
    );

    unsafe {
        m.replace_region(
            region_index,
            MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE + mem1.len() as u64),
        )
        .unwrap()
    };

    assert_eq!(
        m.map(
            AccessType::Load,
            ebpf::MM_REGION_SIZE + mem1.len() as u64,
            1,
        )
        .unwrap()
        .ptr()
        .addr(),
        mem3.as_ptr().addr()
    );
}

#[test]
fn test_aligned_map_replace_region() {
    let config = Config {
        aligned_memory_mapping: true,
        ..Config::default()
    };
    let mem1 = [11];
    let mem2 = [22, 22];
    let mem3 = [33, 33];
    let mut m = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(&raw const mem1, ebpf::MM_REGION_SIZE),
                MemoryRegion::new(&raw const mem2, ebpf::MM_REGION_SIZE * 2),
            ],
            &config,
            SBPFVersion::V4,
        )
        .unwrap()
    };

    assert_eq!(
        m.map(AccessType::Load, ebpf::MM_REGION_SIZE * 2, 1)
            .unwrap()
            .ptr()
            .addr(),
        mem2.as_ptr().addr()
    );

    // index > regions.len()
    assert_error!(
        unsafe {
            m.replace_region(
                3,
                MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE * 2),
            )
        },
        "InvalidMemoryRegion(3)"
    );

    // index != addr >> VIRTUAL_ADDRESS_BITS
    assert_error!(
        unsafe {
            m.replace_region(
                2,
                MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE * 3),
            )
        },
        "InvalidMemoryRegion(2)"
    );

    // index + len != addr >> VIRTUAL_ADDRESS_BITS
    assert_error!(
        unsafe {
            m.replace_region(
                2,
                MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE * 3 - 1),
            )
        },
        "InvalidMemoryRegion(2)"
    );

    unsafe {
        m.replace_region(
            2,
            MemoryRegion::new(&raw const mem3, ebpf::MM_REGION_SIZE * 2),
        )
        .unwrap()
    };

    assert_eq!(
        m.map(AccessType::Load, ebpf::MM_REGION_SIZE * 2, 1)
            .unwrap()
            .ptr()
            .addr(),
        mem3.as_ptr().addr()
    );
}

#[test]
fn test_aligned_initialize_variable_region_size() {
    // 128MB and 256MB regions
    for region_size in [1u64 << 27, 1u64 << 28] {
        let mut mem1 = [1u8; 4];
        let mem2 = [2u8; 4];
        let mut mapping = unsafe {
            AlignedMemoryMapping::new_uninitialized(
                vec![
                    MemoryRegion::new(&raw mut mem1[..], 0),
                    MemoryRegion::new(&raw const mem2[..], region_size * 2),
                ],
                region_size as usize,
            )
        };
        assert!(mapping.initialize().is_ok());
        // the gap at slot 1 is filled with an empty region
        assert_eq!(mapping.regions.len(), 3);
        assert_eq!(mapping.regions[1].vm_addr, region_size);
        assert_eq!(mapping.regions[1].len(), 0);
        assert_eq!(
            HostBuffer::Mutable(&raw mut mem1[..]),
            mapping.regions[0].host,
        );
        assert_eq!(
            HostBuffer::Immutable(&raw const mem2[..]),
            mapping.regions[2].host,
        );

        // two regions in the same slot are rejected
        let mut mapping = unsafe {
            AlignedMemoryMapping::new_uninitialized(
                vec![
                    MemoryRegion::new(&raw mut mem1[..], 0),
                    MemoryRegion::new(&raw const mem2[..], region_size / 2),
                ],
                region_size as usize,
            )
        };
        assert_error!(mapping.initialize(), "InvalidMemoryRegion(0)");
    }
}

#[test]
fn test_aligned_find_region_variable_region_size() {
    // 128MB and 256MB regions
    for region_size in [1u64 << 27, 1u64 << 28] {
        let mem1 = [1u8; 4];
        let mem2 = [2u8; 4];
        let mapping = unsafe {
            AlignedMemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const mem1[..], 0),
                    MemoryRegion::new(&raw const mem2[..], region_size * 2),
                ],
                region_size as usize,
            )
        }
        .unwrap();
        // slot 0
        assert_eq!(
            HostBuffer::Immutable(&raw const mem1[..]),
            mapping.find_region(0).unwrap().1.host,
        );
        assert_eq!(
            HostBuffer::Immutable(&raw const mem1[..]),
            mapping.find_region(region_size - 1).unwrap().1.host,
        );
        // slot 1 is the empty region inserted by initialize()
        assert_eq!(mapping.find_region(region_size).unwrap().0, 1);
        assert_eq!(mapping.find_region(region_size * 2 - 1).unwrap().1.len(), 0);
        // slot 2
        assert_eq!(
            HostBuffer::Immutable(&raw const mem2[..]),
            mapping.find_region(region_size * 2).unwrap().1.host,
        );
        assert_eq!(
            HostBuffer::Immutable(&raw const mem2[..]),
            mapping.find_region(region_size * 3 - 1).unwrap().1.host,
        );
        // beyond the last region
        assert!(mapping.find_region(region_size * 3).is_none());
    }
}

#[test]
fn test_aligned_replace_region_variable_region_size() {
    // 128MB and 256MB regions
    for region_size in [1u64 << 27, 1u64 << 28] {
        let mem1 = [1u8; 4];
        let mem2 = [2u8; 4];
        let mem3 = [3u8; 4];
        let mut mapping = unsafe {
            AlignedMemoryMapping::new(
                vec![
                    MemoryRegion::new(&raw const mem1[..], 0),
                    MemoryRegion::new(&raw const mem2[..], region_size * 2),
                ],
                region_size as usize,
            )
        }
        .unwrap();

        // index != addr >> virtual_address_bits
        assert_error!(
            unsafe { mapping.replace_region(1, MemoryRegion::new(&raw const mem3[..], 0)) },
            "InvalidMemoryRegion(1)"
        );

        // the region spans two slots
        assert_error!(
            unsafe {
                mapping.replace_region(
                    2,
                    MemoryRegion::new(&raw const mem3[..], region_size * 3 - 2),
                )
            },
            "InvalidMemoryRegion(2)"
        );

        // a valid replacement within slot 2
        unsafe {
            mapping
                .replace_region(2, MemoryRegion::new(&raw const mem3[..], region_size * 2))
                .unwrap()
        };
        assert_eq!(
            HostBuffer::Immutable(&raw const mem3[..]),
            mapping.find_region(region_size * 2).unwrap().1.host,
        );
    }
}

#[test]
fn test_access_violation_handler_map() {
    for aligned_memory_mapping in [true, false] {
        let config = Config {
            aligned_memory_mapping,
            ..Config::default()
        };
        let original = [11, 22];
        let copied = Rc::new(RefCell::new(Vec::new()));
        let mut regions = vec![MemoryRegion::new(&raw const original, ebpf::MM_REGION_SIZE)];
        regions[0].access_violation_handler_payload = Some(0);

        let c = Rc::clone(&copied);
        let mut m = unsafe {
            MemoryMapping::new_with_access_violation_handler(
                regions,
                &config,
                SBPFVersion::V3,
                Box::new(move |region, _, _, _, _| {
                    let mut vec = c.borrow_mut();
                    vec.extend_from_slice(&original);
                    region.redirect(&raw mut vec[..]);
                }),
            )
            .unwrap()
        };

        assert_eq!(
            m.map_with_access_violation_handler(AccessType::Load, ebpf::MM_REGION_SIZE, 1)
                .unwrap()
                .ptr()
                .addr(),
            original.as_ptr().addr()
        );
        assert_eq!(
            m.map_with_access_violation_handler(AccessType::Store, ebpf::MM_REGION_SIZE, 1)
                .unwrap()
                .ptr()
                .addr(),
            copied.borrow().as_ptr().addr()
        );
    }
}

#[test]
fn test_access_violation_handler_load_store() {
    for aligned_memory_mapping in [true, false] {
        let config = Config {
            aligned_memory_mapping,
            ..Config::default()
        };
        let original = [11, 22];
        let copied = Rc::new(RefCell::new(Vec::new()));
        let mut regions = vec![MemoryRegion::new(&raw const original, ebpf::MM_REGION_SIZE)];
        regions[0].access_violation_handler_payload = Some(0);

        let c = Rc::clone(&copied);
        let mut m = unsafe {
            MemoryMapping::new_with_access_violation_handler(
                regions,
                &config,
                SBPFVersion::V3,
                Box::new(move |region, _, _, _, _| {
                    let mut vec = c.borrow_mut();
                    vec.extend_from_slice(&original);
                    region.redirect(&raw mut vec[..]);
                }),
            )
            .unwrap()
        };

        assert_eq!(
            m.map(AccessType::Load, ebpf::MM_REGION_SIZE, 1)
                .unwrap()
                .ptr()
                .addr(),
            original.as_ptr().addr()
        );

        assert_eq!(
            m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE).unwrap(),
            11
        );
        assert_eq!(
            m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE + 1)
                .unwrap(),
            22
        );
        assert!(copied.borrow().is_empty());

        m.store_second_attempt(33u8, ebpf::MM_REGION_SIZE).unwrap();
        assert_eq!(original[0], 11);
        assert_eq!(
            m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE).unwrap(),
            33
        );
        assert_eq!(
            m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE + 1)
                .unwrap(),
            22
        );
    }
}

#[test]
fn test_access_violation_handler_region_id() {
    for aligned_memory_mapping in [true, false] {
        let config = Config {
            aligned_memory_mapping,
            ..Config::default()
        };
        let original1 = [11, 22];
        let original2 = [33, 44];
        let copied = Rc::new(RefCell::new(Vec::new()));

        let mut regions = vec![
            MemoryRegion::new(&raw const original1, ebpf::MM_REGION_SIZE),
            MemoryRegion::new(&raw const original2, ebpf::MM_REGION_SIZE * 2),
        ];
        regions[0].access_violation_handler_payload = Some(42);

        let c = Rc::clone(&copied);
        let mut m = unsafe {
            MemoryMapping::new_with_access_violation_handler(
                regions,
                &config,
                SBPFVersion::V3,
                Box::new(move |region, _, _, _, _| {
                    // check that the argument passed to MemoryRegion::new is then passed to the
                    // callback
                    assert_eq!(region.access_violation_handler_payload, Some(42));
                    let mut vec = c.borrow_mut();
                    vec.extend_from_slice(&original1);
                    region.redirect(&raw mut vec[..]);
                }),
            )
            .unwrap()
        };

        m.store_second_attempt(55u8, ebpf::MM_REGION_SIZE).unwrap();
        assert_eq!(original1[0], 11);
        assert_eq!(
            m.load_first_attempt::<u8>(ebpf::MM_REGION_SIZE).unwrap(),
            55
        );
    }
}

#[test]
#[should_panic(expected = "AccessViolation")]
fn test_map_access_violation_handler_error() {
    let config = Config::default();
    let original = [11, 22];

    let m = unsafe {
        MemoryMapping::new_with_access_violation_handler(
            vec![MemoryRegion::new(&raw const original, ebpf::MM_REGION_SIZE)],
            &config,
            SBPFVersion::V4,
            Box::new(default_access_violation_handler),
        )
        .unwrap()
    };

    m.map(AccessType::Store, ebpf::MM_REGION_SIZE, 1).unwrap();
}

#[test]
#[should_panic(expected = "AccessViolation")]
fn test_store_access_violation_handler_error() {
    let config = Config::default();
    let original = [11, 22];

    let mut m = unsafe {
        MemoryMapping::new_with_access_violation_handler(
            vec![MemoryRegion::new(&raw const original, ebpf::MM_REGION_SIZE)],
            &config,
            SBPFVersion::V4,
            Box::new(default_access_violation_handler),
        )
        .unwrap()
    };

    m.store_first_attempt(33u8, ebpf::MM_REGION_SIZE).unwrap();
}

#[test]
fn test_access_violation_region_identification() {
    let config = Config::default();
    let original = [11, 22];
    let region = 0x10_0000_0000;
    let mut m = unsafe {
        MemoryMapping::new(
            vec![MemoryRegion::new(&raw const original, region)],
            &config,
            SBPFVersion::V4,
        )
        .unwrap()
    };
    let store_err_inbound = m.store_first_attempt(33u8, region).unwrap_err();
    assert_eq!(
        store_err_inbound.to_string(),
        "Access violation writing 1 bytes at address 0x1000000000 (in allocated region)"
    );
    let store_err_oob = m.load_first_attempt::<u64>(region + 3).unwrap_err();
    assert_eq!(
        store_err_oob.to_string(),
        "Access violation reading 8 bytes at address 0x1000000003 (in unallocated region)"
    );
}

#[test]
fn v4_aligned_mapping() {
    let config = Config {
        aligned_memory_mapping: false,
        ..Config::default()
    };

    let mem = [11, 12];
    let mapping = unsafe {
        MemoryMapping::new_with_access_violation_handler(
            vec![MemoryRegion::new(&raw const mem, ebpf::MM_REGION_SIZE)],
            &config,
            SBPFVersion::V4,
            Box::new(default_access_violation_handler),
        )
        .unwrap()
    };

    assert!(matches!(mapping.ty, MemoryMappingType::Aligned(_)));
}

#[test]
fn test_different_region_sizes() {
    let mem1 = b"solana";
    let mem2 = b"is";
    let mem3 = b"cool";
    let mem4 = b"innit?";
    for region_size in [128 * 1024 * 1024, 256 * 1024 * 1024] {
        let mut mapping = unsafe {
            AlignedMemoryMapping::new_uninitialized(
                vec![
                    MemoryRegion::new(&raw const mem1[..], region_size),
                    MemoryRegion::new(&raw const mem2[..], 2 * region_size),
                    MemoryRegion::new(&raw const mem3[..], 3 * region_size),
                ],
                region_size as usize,
            )
        };

        mapping.initialize().unwrap();
        let (index, region) = mapping.find_region(2 * region_size).unwrap();
        assert_eq!(index, 2);
        assert_eq!(region.host_buffer().ptr().cast::<u8>(), mem2.as_ptr());
        let mut new_region = region.clone();
        unsafe {
            new_region.redirect(&raw const mem4[..]);
            mapping.replace_region(2, new_region).unwrap();
        }

        let (index, region) = mapping.find_region(2 * region_size).unwrap();
        assert_eq!(index, 2);
        assert_eq!(region.host_buffer().ptr().cast::<u8>(), mem4.as_ptr());
    }
}
