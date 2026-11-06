//! 智能流控在每个平台上都读得出这台机器的内存：Linux、FreeBSD 和 Windows 的 CI 各跑一遍
//! Smart flow control can read this machine's memory on every platform: the CI runs this on
//! Linux, FreeBSD and Windows

use kixdns::engine::memory_watermark::this_machine;

#[test]
fn this_machine_can_be_read() {
    let reading = this_machine();
    let system = reading
        .limits
        .first()
        .copied()
        .unwrap_or_else(|| panic!("the system's memory: {reading:?}"));
    assert!(system.total > 0, "{reading:?}");
    assert!(system.available <= system.total, "{reading:?}");
    assert!(reading.own > 0, "{reading:?}");
}

/// 本进程放进一个设了单进程内存上限的作业对象，读得到这处限制
/// With this process put in a job object that has a per-process memory limit, that limit is read
#[cfg(windows)]
#[test]
fn a_memory_limit_of_its_job_object_is_read() {
    use std::mem::{MaybeUninit, size_of};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const LIMIT: usize = 8 << 30;
    // SAFETY: the job's information is a zeroed C structure with the limit filled in, given with
    // its size; the job handle stays open for the rest of the process
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        assert!(!job.is_null(), "{}", std::io::Error::last_os_error());
        let mut limits = MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed();
        let info = limits.as_mut_ptr();
        (*info).BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        (*info).ProcessMemoryLimit = LIMIT;
        let set = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            info.cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        assert_ne!(set, 0, "{}", std::io::Error::last_os_error());
        let assigned = AssignProcessToJobObject(job, GetCurrentProcess());
        assert_ne!(assigned, 0, "{}", std::io::Error::last_os_error());
    }

    let reading = this_machine();
    let job = reading
        .limits
        .iter()
        .find(|limit| limit.total == LIMIT as u64)
        .unwrap_or_else(|| panic!("the job's limit: {reading:?}"));
    assert!(job.available < job.total, "{reading:?}");
}
