use std::error::Error;
use std::ffi::{CString, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use hex_literal::hex;
use tea_soft::block_cipher::generic_array::GenericArray;
use tea_soft::block_cipher::{BlockCipher, NewBlockCipher};
use tea_soft::Tea32;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::processthreadsapi::{
    CreateProcessA, ResumeThread, PROCESS_INFORMATION, STARTUPINFOA,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_SUSPENDED, INFINITE};

use dks3_config::ConfigBuilder;

const PATH: &str = r#"F:\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe"#;
const CONNECT_INFO_VA: usize = 0x144F4A5B1;
const CONNECT_INFO_KEY: [u8; 16] = hex!("4B694CD6 96ADA235 EC91D9D4 23F562E5");

fn main() -> Result<(), Box<dyn Error>> {
    let config = ConfigBuilder::default()
        .add_file("server/config.toml")
        .and_then(|c| c.build())?;

    let dks3_exe_path: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| PATH.to_string())
        .into();

    let dks3_exe_dir = dks3_exe_path.parent().unwrap();

    let mut connect_info = config.security().public_key_pkcs1().into_bytes();
    connect_info.resize(516, 0);

    let connect_info_ip = &mut connect_info[432..];
    for (idx, chr) in OsString::from(config.server().hostname())
        .encode_wide()
        .enumerate()
    {
        connect_info_ip[idx * 2..idx * 2 + 2].copy_from_slice(&chr.to_le_bytes());
    }

    let cipher = Tea32::new(&GenericArray::from(CONNECT_INFO_KEY));
    for chunk in connect_info.chunks_mut(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);

        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        chunk.copy_from_slice(&block[..chunk.len()]);
    }

    unsafe {
        let mut proc_info: PROCESS_INFORMATION = std::mem::zeroed();
        let mut startup_info: STARTUPINFOA = std::mem::zeroed();

        let ret = CreateProcessA(
            ptr::null(),
            CString::new(dks3_exe_path.to_str().unwrap())?.as_ptr() as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            CREATE_SUSPENDED,
            ptr::null_mut(),
            CString::new(dks3_exe_dir.to_str().unwrap())?.as_ptr(),
            &mut startup_info as *mut _,
            &mut proc_info as *mut _,
        );

        if ret == 0 {
            panic!("Failed to launch Dark Souls 3, error: {:x}", GetLastError());
        }

        let mut written: usize = 0;
        WriteProcessMemory(
            proc_info.hProcess,
            CONNECT_INFO_VA as *mut _,
            connect_info.as_ptr() as *const _,
            connect_info.len(),
            &mut written as *mut _,
        );

        ResumeThread(proc_info.hThread);
        WaitForSingleObject(proc_info.hProcess, INFINITE);
    }

    Ok(())
}
