use luks_core::device::FileDevice;
use luks_core::fs::ext4::Ext4;
fn main() {
    let path = "../fixtures/ext4/many-groups-1k.img";
    let len = std::fs::metadata(path).unwrap().len();
    let fs = Ext4::mount(FileDevice::open(path).unwrap()).unwrap();
    let sb = fs.superblock();
    println!("blocks_count: {}", sb.blocks_count);
    println!("first_data_block: {}", sb.first_data_block);
    println!("blocks_per_group: {}", sb.blocks_per_group);
    println!("inodes_count: {}", sb.inodes_count);
    println!("groups: {}", fs.groups().len());
}
