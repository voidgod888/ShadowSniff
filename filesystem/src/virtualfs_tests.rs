/*
 * Unit tests for VirtualFileSystem
 */

#[cfg(test)]
mod tests {
    use crate::virtualfs::VirtualFileSystem;
    use crate::{FileSystem, FileSystemExt};
    use crate::path::Path;
    extern crate std;

    #[test]
    fn test_vfs_create_file() {
        let vfs = VirtualFileSystem::default();
        let path = Path::new("\\test\\file.txt");
        
        // Parent must exist first
        assert!(vfs.mkdirs(&Path::new("\\test")).is_ok());
        assert!(vfs.create_file(&path).is_ok());
        assert!(vfs.is_file(&path));
        assert!(!vfs.is_dir(&path));
    }

    #[test]
    fn test_vfs_write_read_file() {
        let vfs = VirtualFileSystem::default();
        let path = Path::new("\\test\\file.txt");
        
        let data = b"Hello, World!";
        assert!(vfs.write_file(&path, data).is_ok());
        
        let read_data = vfs.read_file(&path).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_vfs_mkdir() {
        let vfs = VirtualFileSystem::default();
        let dir = Path::new("\\test\\dir");
        
        // Parent must exist first
        assert!(vfs.mkdir(&Path::new("\\test")).is_ok());
        assert!(vfs.mkdir(&dir).is_ok());
        assert!(vfs.is_dir(&dir));
        assert!(!vfs.is_file(&dir));
    }

    #[test]
    fn test_vfs_mkdirs() {
        let vfs = VirtualFileSystem::default();
        let deep_dir = Path::new("\\test\\deep\\nested\\directory");
        
        assert!(vfs.mkdirs(&deep_dir).is_ok());
        assert!(vfs.is_dir(&deep_dir));
        
        // Parent should also exist
        assert!(vfs.is_dir(&Path::new("\\test\\deep")));
        assert!(vfs.is_dir(&Path::new("\\test\\deep\\nested")));
    }

    #[test]
    fn test_vfs_list_files() {
        let vfs = VirtualFileSystem::default();
        let dir = Path::new("\\test\\list");
        assert!(vfs.mkdirs(&dir).is_ok());
        
        assert!(vfs.write_file(&(&dir / "file1.txt"), b"data1").is_ok());
        assert!(vfs.write_file(&(&dir / "file2.txt"), b"data2").is_ok());
        assert!(vfs.mkdir(&(&dir / "subdir")).is_ok());
        
        let files = vfs.list_files(&dir);
        assert!(files.is_some());
        let files = files.unwrap();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_vfs_remove_file() {
        let vfs = VirtualFileSystem::default();
        let path = Path::new("\\test\\remove.txt");
        
        assert!(vfs.write_file(&path, b"data").is_ok());
        assert!(vfs.is_exists(&path));
        
        assert!(vfs.remove_file(&path).is_ok());
        assert!(!vfs.is_exists(&path));
    }

    #[test]
    fn test_vfs_error_handling() {
        let vfs = VirtualFileSystem::default();
        let path = Path::new("\\nonexistent\\file.txt");
        
        // Reading non-existent file should return error
        assert!(vfs.read_file(&path).is_err());
        
        // Creating file with non-existent parent should fail
        assert!(vfs.create_file(&path).is_err());
    }
}